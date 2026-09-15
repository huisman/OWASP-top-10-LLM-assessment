"""Assess audit material against OWASP LLM controls via a provider-agnostic LLM client."""
from __future__ import annotations
import json
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass
from pathlib import Path

# Fix 1: import using package-relative path so the module works from any cwd
from .controls import Control

# llm_provider.py is shared from the repo root
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
from llm_provider import LLMClient, LLMConfig, ProviderRateLimitError

MODEL = LLMConfig().model

SYSTEM_PROMPT = """\
You are an AI security auditor specialised in the OWASP Top 10 for LLM Applications (2025 edition).
Given audit material (agent plan, codebase, configuration, or architecture description) and a single
OWASP LLM control definition, assess whether the target passes, fails, warns, or is not applicable
for this control.

## Verdict definitions

- PASS: All required mitigations are present in the code, configuration, or architecture. No
  indicators of the risk were detected. Minor improvements may still be possible.
- WARN: Some mitigations are present but gaps remain. The risk is reduced but not eliminated.
  Specific remediation actions can close the gap.
- FAIL: One or more indicators of the risk are present in the code with no corresponding
  mitigation. The agent is exposed to the described attack or failure mode.
- N-A: The agent's architecture makes the risk category irrelevant (e.g., no RAG for LLM08,
  no fine-tuning for LLM04). Requires positive evidence that the capability is absent —
  if uncertain, default to WARN.

## Verdict escalation

- A single FAIL finding on any criterion within a control makes the overall control verdict FAIL.
- A control with mixed PASS and WARN findings is WARN.

## Evidence standard

Every finding MUST cite:
1. Location — file path and line number(s) where the evidence was found (or where the expected
   mitigation is absent). Use the format "file.py:42".
2. Observation — what was found or not found, stated as fact.
3. Reasoning — why this observation maps to the given verdict.

Findings without file-level evidence must be flagged as "[no direct evidence — manual review required]".

## Response format

Return ONLY a valid JSON object with these fields:
- verdict: one of PASS, FAIL, WARN, N-A
- findings: list of strings, each citing location and observation (empty list for PASS/N-A)
- remediation: list of actionable recommendation strings (empty list for PASS/N-A)

Base your assessment ONLY on evidence present in the provided material. Do not invent findings.
Assessment methodology version: 1.0
"""


@dataclass
class Assessment:
    control_id: str
    control_name: str
    verdict: str          # PASS | FAIL | WARN | N-A
    findings: list[str]
    remediation: list[str]


# Fix 2: client created once and passed in; assess() is pure
def _call(client: LLMClient, material: str, control: Control) -> Assessment:
    user_message = f"""\
Control: {control.id} - {control.name}

Control definition:
{control.description}

---

Audit material:
{material}

---

Assess this agent against the control above. Return JSON only.
"""

    def _on_retry(attempt: int, wait: float) -> None:
        print(f"\n      [{control.id}] Rate limit — waiting {wait:.0f}s...", end=" ", flush=True)

    try:
        result = client.complete_with_retry(
            system=SYSTEM_PROMPT,
            user=user_message,
            max_tokens=2048,
            attempts=3,
            on_retry=_on_retry,
        )
    except ProviderRateLimitError as exc:
        raise RuntimeError(f"No response from API after 3 attempts for {control.id}") from exc

    raw = result.text
    if raw.startswith("```"):
        raw = raw.split("```")[1]
        if raw.startswith("json"):
            raw = raw[4:]
        raw = raw.strip()

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        data = {"verdict": "WARN", "findings": ["[response truncated — manual review required]"], "remediation": []}

    return Assessment(
        control_id=control.id,
        control_name=control.name,
        verdict=data.get("verdict", "N-A"),
        findings=data.get("findings", []),
        remediation=data.get("remediation", []),
    )


def assess(material: str, control: Control, client: LLMClient) -> Assessment:
    """Assess a single control. Client must be provided by the caller."""
    return _call(client, material, control)


# Fix 4: parallel assessment — run all 10 controls concurrently
def assess_all(
    material: str,
    controls: list[Control],
    client: LLMClient,
    on_result=None,
    max_workers: int = 5,
) -> list[Assessment]:
    """Assess all controls in parallel. on_result(assessment) called as each completes."""
    results: dict[str, Assessment] = {}

    with ThreadPoolExecutor(max_workers=max_workers) as pool:
        futures = {pool.submit(_call, client, material, ctrl): ctrl for ctrl in controls}
        for future in as_completed(futures):
            a = future.result()
            results[a.control_id] = a
            if on_result:
                on_result(a)

    # Return in original control order
    return [results[ctrl.id] for ctrl in controls]
