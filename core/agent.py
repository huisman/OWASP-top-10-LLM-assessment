"""
Compliance agent — orchestrates the mapper → prompt builder → LLM API → validator pipeline.
"""

from __future__ import annotations

import json
import logging
import re
import time

from pydantic import ValidationError

from config import Config
from llm_provider import LLMClient, LLMConfig, ProviderAPIError, ProviderConnectionError
from saaf.core.mapper import FrameworkMapper, MappingResult
from saaf.core.models import AuditInput, ComplianceReport
from saaf.prompts.system_prompt import build_system_prompt, build_user_message

log = logging.getLogger("saaf.agent")


class ComplianceReportError(Exception):
    """Raised when the agent cannot produce a valid compliance report."""

    def __init__(self, message: str, raw_response: str = "") -> None:
        super().__init__(message)
        self.raw_response = raw_response


class ComplianceAgent:
    def __init__(self, config: Config | None = None) -> None:
        self.config = config or Config()
        self.client = LLMClient(LLMConfig(
            provider=self.config.provider,
            model=self.config.model,
            api_key=self.config.api_key,
            base_url=self.config.base_url,
        ))

    # ------------------------------------------------------------------
    # Public entry point
    # ------------------------------------------------------------------

    def run(self, audit_input: AuditInput) -> tuple[ComplianceReport, MappingResult]:
        """
        Run the full compliance analysis pipeline.

        Returns (ComplianceReport, MappingResult) so callers can access
        both the report and the intermediate mapping data.
        """
        log.info("Starting audit: %s | %s | %s | %s | %s",
                 audit_input.company_name, audit_input.industry,
                 audit_input.country, audit_input.listed_status, audit_input.audit_topic)

        # Step 1: Deterministic framework mapping (no API call)
        mapping = FrameworkMapper(audit_input).map()
        log.info("Mapper: jurisdiction=%s  frameworks=%d  [%s]",
                 mapping.resolved_jurisdiction,
                 len(mapping.framework_matches),
                 ", ".join(m.key for m in mapping.framework_matches))

        # Step 2: Build prompts
        system_prompt = build_system_prompt(audit_input, mapping)
        user_message = build_user_message(audit_input, mapping)
        log.debug("Prompt sizes: system=%d chars  user=%d chars",
                  len(system_prompt), len(user_message))

        # Step 3: Call the configured LLM with streaming + extended thinking
        raw_json = self._call_llm(system_prompt, user_message)

        # Step 4: Parse and validate
        report = self._parse_and_validate(raw_json, audit_input)
        log.info("Report ready: id=%s  risk=%s  frameworks=%d  regulations=%d",
                 report.report_id,
                 report.gap_risk_summary.overall_risk_rating,
                 len(report.framework_assessments),
                 len(report.mandatory_regulations))

        return report, mapping

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _call_llm(self, system_prompt: str, user_message: str) -> str:
        """Call the configured model with streaming and extended thinking. Retry once on failure."""
        last_error: Exception | None = None

        for attempt in range(self.config.max_retries + 1):
            if attempt:
                log.warning("Retrying API call (attempt %d/%d)", attempt + 1, self.config.max_retries + 1)
            try:
                full_text = ""
                t_start = time.monotonic()
                thinking_tokens = 0

                log.info("Calling %s (%s)  max_tokens=%d  reasoning=%s",
                         self.client.config.model, self.client.config.provider,
                         self.config.max_tokens, self.client.config.reasoning)

                for event in self.client.stream(
                    system=system_prompt,
                    user=user_message,
                    max_tokens=self.config.max_tokens,
                ):
                    if event.type == "text":
                        full_text += event.text
                    elif event.type == "thinking":
                        thinking_tokens += len(event.text)

                elapsed = time.monotonic() - t_start
                log.info("API done in %.1fs  output=%d chars", elapsed, len(full_text))
                if thinking_tokens:
                    log.debug("Thinking block: ~%d chars", thinking_tokens)

                return full_text

            except ProviderAPIError as e:
                last_error = e
                log.error("API error %s: %s", e.status_code, e)
                if e.status_code is not None and e.status_code < 500:
                    raise ComplianceReportError(
                        f"LLM API error ({e.status_code}): {e}"
                    ) from e
            except ProviderConnectionError as e:
                last_error = e
                log.error("Connection error: %s", e)

        raise ComplianceReportError(
            f"LLM API failed after {self.config.max_retries + 1} attempts: {last_error}"
        )

    def _parse_and_validate(
        self, raw_json: str, audit_input: AuditInput
    ) -> ComplianceReport:
        """Extract JSON from the model's response, parse, and validate."""
        log.debug("Raw response: %d chars", len(raw_json))
        cleaned = self._extract_json_object(raw_json)
        if len(cleaned) != len(raw_json):
            log.debug("Extracted JSON object: %d chars (trimmed %d)",
                      len(cleaned), len(raw_json) - len(cleaned))

        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError as e:
            log.error("JSON parse failed at char %d: %s", e.pos, e.msg)
            raise ComplianceReportError(
                f"Model returned invalid JSON: {e}",
                raw_response=raw_json,
            ) from e

        log.debug("JSON parsed OK  keys=%s", list(data.keys()))

        if "audit_input" not in data or not data["audit_input"]:
            log.debug("audit_input missing from response — injecting from input")
            data["audit_input"] = audit_input.model_dump()

        try:
            report = ComplianceReport(**data)
        except ValidationError as e:
            log.error("Schema validation failed: %s", e)
            raise ComplianceReportError(
                f"Report failed schema validation: {e}",
                raw_response=raw_json,
            ) from e

        return report

    @staticmethod
    def _extract_json_object(text: str) -> str:
        """
        Robustly extract the outermost JSON object from the model's response.

        Handles:
          - Clean JSON with no surrounding text
          - Markdown code fences (```json ... ```)
          - Preamble prose before the opening brace
          - Trailing prose after the closing brace
        """
        text = text.strip()

        # 1. Strip markdown fences first
        text = re.sub(r"^```(?:json)?\s*\n?", "", text, flags=re.IGNORECASE)
        text = re.sub(r"\n?```\s*$", "", text).strip()

        # 2. Slice from the first '{' to the last '}', discarding any surrounding prose
        start = text.find("{")
        end = text.rfind("}")
        if start != -1 and end != -1 and end > start:
            return text[start : end + 1]

        # 3. Couldn't locate JSON object — return as-is and let json.loads report the error
        return text
