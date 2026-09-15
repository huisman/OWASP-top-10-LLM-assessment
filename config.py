"""
Runtime configuration for the SAAF Compliance Agent (core/agent.py).

All values are read from environment variables so the same code runs
unmodified against different LLM providers, models, and keys — see
llm_provider.py for the full list of SAAF_LLM_* variables.
"""
from __future__ import annotations

import os
from dataclasses import dataclass, field


@dataclass
class Config:
    provider: str = field(default_factory=lambda: os.environ.get("SAAF_LLM_PROVIDER", "anthropic"))
    model: str | None = field(default_factory=lambda: os.environ.get("SAAF_LLM_MODEL"))
    api_key: str | None = field(default_factory=lambda: os.environ.get("SAAF_LLM_API_KEY"))
    base_url: str | None = field(default_factory=lambda: os.environ.get("SAAF_LLM_BASE_URL"))
    max_tokens: int = field(default_factory=lambda: int(os.environ.get("SAAF_LLM_MAX_TOKENS", "8192")))
    max_retries: int = field(default_factory=lambda: int(os.environ.get("SAAF_LLM_MAX_RETRIES", "1")))
