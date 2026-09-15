"""
Provider-agnostic LLM client shared by every tool in this repo.

Every audit tool talks to the model through this module instead of importing
the Anthropic SDK directly, so the same code runs against Anthropic, OpenAI,
or any OpenAI-compatible endpoint (Azure OpenAI, a local Ollama/vLLM server,
or another hosted OpenAI-API-compatible provider) by changing environment
variables only.

Environment variables:
  SAAF_LLM_PROVIDER    "anthropic" (default) or "openai"
  SAAF_LLM_MODEL        Model id to use. Defaults: "claude-opus-4-6" for
                         anthropic, "gpt-5" for openai.
  SAAF_LLM_API_KEY      Overrides the provider-native key env var below.
  ANTHROPIC_API_KEY      Used when provider=anthropic and SAAF_LLM_API_KEY unset.
  OPENAI_API_KEY         Used when provider=openai and SAAF_LLM_API_KEY unset.
  SAAF_LLM_BASE_URL     Optional custom endpoint — Azure OpenAI, a local
                         Ollama/vLLM server, or any other OpenAI-compatible
                         API — passed through to the provider's SDK.
  SAAF_LLM_REASONING    "1" (default) or "0" — request extended thinking /
                         reasoning where the provider and model support it.
                         Ignored by providers/models that don't.

Usage:
    from llm_provider import LLMClient

    client = LLMClient()  # reads config from environment
    result = client.complete(system=..., user=..., max_tokens=2048)
    print(result.text)

    for event in client.stream(system=..., user=..., max_tokens=8192):
        if event.type == "text":
            print(event.text, end="")
        elif event.type == "thinking":
            ...  # extended reasoning, only emitted where the provider supports it
"""
from __future__ import annotations

import os
import random
import time
from dataclasses import dataclass, field
from typing import Iterator, Optional

_DEFAULT_MODELS = {
    "anthropic": "claude-opus-4-6",
    "openai": "gpt-5",
}


class ProviderError(Exception):
    """Base class for provider-agnostic LLM errors."""


class ProviderRateLimitError(ProviderError):
    def __init__(self, message: str, retry_after: Optional[float] = None) -> None:
        super().__init__(message)
        self.retry_after = retry_after


class ProviderAPIError(ProviderError):
    def __init__(self, message: str, status_code: Optional[int] = None) -> None:
        super().__init__(message)
        self.status_code = status_code


class ProviderConnectionError(ProviderError):
    pass


@dataclass
class LLMResult:
    text: str
    thinking: str = ""


@dataclass
class StreamEvent:
    type: str  # "text" | "thinking"
    text: str


@dataclass
class LLMConfig:
    provider: str = field(default_factory=lambda: os.environ.get("SAAF_LLM_PROVIDER", "anthropic").strip().lower())
    model: Optional[str] = field(default_factory=lambda: os.environ.get("SAAF_LLM_MODEL") or None)
    api_key: Optional[str] = field(default_factory=lambda: os.environ.get("SAAF_LLM_API_KEY") or None)
    base_url: Optional[str] = field(default_factory=lambda: os.environ.get("SAAF_LLM_BASE_URL") or None)
    reasoning: bool = field(default_factory=lambda: os.environ.get("SAAF_LLM_REASONING", "1") != "0")

    def __post_init__(self) -> None:
        if not self.model:
            self.model = _DEFAULT_MODELS.get(self.provider, self.provider)
        if not self.api_key:
            native_env = "ANTHROPIC_API_KEY" if self.provider == "anthropic" else "OPENAI_API_KEY"
            self.api_key = os.environ.get(native_env)


def _retry_after(exc: Exception) -> Optional[float]:
    try:
        response = getattr(exc, "response", None)
        value = response.headers.get("retry-after") if response else None
        return float(value) if value else None
    except (AttributeError, TypeError, ValueError):
        return None


class _AnthropicBackend:
    def __init__(self, config: LLMConfig) -> None:
        try:
            import anthropic  # local import: only required when this provider is selected
        except ImportError as exc:
            raise ProviderError(
                "SAAF_LLM_PROVIDER=anthropic requires the 'anthropic' package: pip install anthropic"
            ) from exc

        self._sdk = anthropic
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self.client = anthropic.Anthropic(**kwargs)
        self.config = config

    def _request_kwargs(self, system: str, user: str, max_tokens: int) -> dict:
        kwargs = dict(
            model=self.config.model,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": user}],
        )
        if self.config.reasoning:
            kwargs["thinking"] = {"type": "adaptive"}
        return kwargs

    def _reraise(self, exc: Exception) -> None:
        if isinstance(exc, self._sdk.RateLimitError):
            raise ProviderRateLimitError(str(exc), retry_after=_retry_after(exc)) from exc
        if isinstance(exc, self._sdk.APIStatusError):
            raise ProviderAPIError(str(exc), status_code=exc.status_code) from exc
        if isinstance(exc, self._sdk.APIConnectionError):
            raise ProviderConnectionError(str(exc)) from exc
        raise

    def complete(self, *, system: str, user: str, max_tokens: int) -> LLMResult:
        try:
            response = self.client.messages.create(**self._request_kwargs(system, user, max_tokens))
        except Exception as exc:  # noqa: BLE001 - re-raised as a provider-agnostic type below
            self._reraise(exc)
        text = "".join(b.text for b in response.content if getattr(b, "type", None) == "text").strip()
        return LLMResult(text=text)

    def stream(self, *, system: str, user: str, max_tokens: int) -> Iterator[StreamEvent]:
        try:
            with self.client.messages.stream(**self._request_kwargs(system, user, max_tokens)) as stream:
                for event in stream:
                    if event.type != "content_block_delta":
                        continue
                    delta = event.delta
                    delta_type = getattr(delta, "type", None)
                    if delta_type == "text_delta":
                        yield StreamEvent("text", delta.text)
                    elif delta_type == "thinking_delta":
                        yield StreamEvent("thinking", delta.thinking)
        except Exception as exc:  # noqa: BLE001
            self._reraise(exc)


class _OpenAIBackend:
    """Covers OpenAI itself, and any OpenAI-compatible endpoint via base_url
    (Azure OpenAI, a local Ollama/vLLM server, or another hosted provider)."""

    def __init__(self, config: LLMConfig) -> None:
        try:
            import openai  # local import: only required when this provider is selected
        except ImportError as exc:
            raise ProviderError(
                "SAAF_LLM_PROVIDER=openai requires the 'openai' package: pip install openai"
            ) from exc

        self._sdk = openai
        kwargs = {"api_key": config.api_key}
        if config.base_url:
            kwargs["base_url"] = config.base_url
        self.client = openai.OpenAI(**kwargs)
        self.config = config

    @staticmethod
    def _supports_reasoning_effort(model: str) -> bool:
        # Only reasoning-capable OpenAI models accept reasoning_effort; sending it
        # to e.g. gpt-4o raises an "unsupported parameter" error.
        prefixes = ("o1", "o3", "o4", "gpt-5")
        return model.lower().startswith(prefixes)

    def _request_kwargs(self, system: str, user: str, max_tokens: int) -> dict:
        kwargs = dict(
            model=self.config.model,
            max_completion_tokens=max_tokens,
            messages=[
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
        )
        if self.config.reasoning and self._supports_reasoning_effort(self.config.model):
            kwargs["reasoning_effort"] = "high"
        return kwargs

    def _reraise(self, exc: Exception) -> None:
        if isinstance(exc, self._sdk.RateLimitError):
            raise ProviderRateLimitError(str(exc), retry_after=_retry_after(exc)) from exc
        if isinstance(exc, self._sdk.APIStatusError):
            raise ProviderAPIError(str(exc), status_code=exc.status_code) from exc
        if isinstance(exc, self._sdk.APIConnectionError):
            raise ProviderConnectionError(str(exc)) from exc
        raise

    def complete(self, *, system: str, user: str, max_tokens: int) -> LLMResult:
        try:
            response = self.client.chat.completions.create(**self._request_kwargs(system, user, max_tokens))
        except Exception as exc:  # noqa: BLE001
            self._reraise(exc)
        text = (response.choices[0].message.content or "").strip()
        return LLMResult(text=text)

    def stream(self, *, system: str, user: str, max_tokens: int) -> Iterator[StreamEvent]:
        # The Chat Completions API does not expose reasoning/thinking text, so
        # only "text" events are ever emitted here.
        try:
            stream = self.client.chat.completions.create(
                **self._request_kwargs(system, user, max_tokens), stream=True
            )
            for chunk in stream:
                delta_text = chunk.choices[0].delta.content
                if delta_text:
                    yield StreamEvent("text", delta_text)
        except Exception as exc:  # noqa: BLE001
            self._reraise(exc)


_BACKENDS = {
    "anthropic": _AnthropicBackend,
    "openai": _OpenAIBackend,
}


class LLMClient:
    """Provider-agnostic client. Selects a backend from LLMConfig (env-driven by default)."""

    def __init__(self, config: Optional[LLMConfig] = None) -> None:
        self.config = config or LLMConfig()
        backend_cls = _BACKENDS.get(self.config.provider)
        if backend_cls is None:
            raise ProviderError(
                f"Unknown SAAF_LLM_PROVIDER '{self.config.provider}'. "
                f"Supported: {', '.join(sorted(_BACKENDS))} "
                f"('openai' also covers Azure OpenAI, Ollama, vLLM, and other "
                f"OpenAI-compatible endpoints via SAAF_LLM_BASE_URL)."
            )
        if not self.config.api_key:
            native_env = "ANTHROPIC_API_KEY" if self.config.provider == "anthropic" else "OPENAI_API_KEY"
            raise ProviderError(
                f"No API key configured for provider '{self.config.provider}'. "
                f"Set {native_env} (or SAAF_LLM_API_KEY)."
            )
        self._backend = backend_cls(self.config)

    def complete(self, *, system: str, user: str, max_tokens: int) -> LLMResult:
        """Non-streaming call. Returns the full response text."""
        return self._backend.complete(system=system, user=user, max_tokens=max_tokens)

    def stream(self, *, system: str, user: str, max_tokens: int) -> Iterator[StreamEvent]:
        """Streaming call. Yields StreamEvent("text"|"thinking", chunk) as they arrive."""
        return self._backend.stream(system=system, user=user, max_tokens=max_tokens)

    def complete_with_retry(
        self,
        *,
        system: str,
        user: str,
        max_tokens: int,
        attempts: int = 3,
        on_retry=None,
    ) -> LLMResult:
        """Non-streaming call with rate-limit backoff, for batch/parallel callers."""
        last_error: Optional[Exception] = None
        for attempt in range(attempts):
            try:
                return self.complete(system=system, user=user, max_tokens=max_tokens)
            except ProviderRateLimitError as exc:
                last_error = exc
                if attempt == attempts - 1:
                    raise
                wait = exc.retry_after or ((2**attempt) * 60 + random.uniform(0, 10))
                if on_retry:
                    on_retry(attempt, wait)
                time.sleep(wait)
        raise last_error or ProviderError("No response after retries")
