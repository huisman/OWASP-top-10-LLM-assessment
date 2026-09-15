"""Tests for owasp_llm_audit.auditor (no real API calls)."""
import sys
from pathlib import Path
from unittest.mock import MagicMock
import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))
sys.path.insert(0, str(Path(__file__).parent.parent.parent))
from owasp_llm_audit.auditor import Assessment, _call, assess_all
from owasp_llm_audit.controls import Control
from llm_provider import LLMResult, ProviderRateLimitError

CTRL = Control(id="LLM01", name="Prompt Injection", description="Test control")
MATERIAL = "def foo(): pass"


def _mock_client(verdict="PASS", findings=None, remediation=None):
    import json
    payload = json.dumps({
        "verdict": verdict,
        "findings": findings or [],
        "remediation": remediation or [],
    })
    client = MagicMock()
    client.complete_with_retry.return_value = LLMResult(text=payload)
    return client


def test_call_returns_assessment():
    client = _mock_client("PASS")
    result = _call(client, MATERIAL, CTRL)
    assert isinstance(result, Assessment)
    assert result.verdict == "PASS"
    assert result.control_id == "LLM01"


def test_call_fail_verdict():
    client = _mock_client("FAIL", findings=["issue found"], remediation=["fix it"])
    result = _call(client, MATERIAL, CTRL)
    assert result.verdict == "FAIL"
    assert result.findings == ["issue found"]
    assert result.remediation == ["fix it"]


def test_call_handles_markdown_fenced_json():
    payload = '```json\n{"verdict": "WARN", "findings": [], "remediation": []}\n```'
    client = MagicMock()
    client.complete_with_retry.return_value = LLMResult(text=payload)
    result = _call(client, MATERIAL, CTRL)
    assert result.verdict == "WARN"


def test_call_handles_truncated_json():
    client = MagicMock()
    client.complete_with_retry.return_value = LLMResult(text='{"verdict": "FAIL", "findings": ["truncated')
    result = _call(client, MATERIAL, CTRL)
    assert result.verdict == "WARN"
    assert "truncated" in result.findings[0].lower()


def test_call_raises_after_rate_limit_exhausted():
    client = MagicMock()
    client.complete_with_retry.side_effect = ProviderRateLimitError("rate limited")
    with pytest.raises(RuntimeError):
        _call(client, MATERIAL, CTRL)


def test_assess_all_returns_in_control_order():
    controls = [
        Control(id="LLM01", name="Prompt Injection", description="c1"),
        Control(id="LLM02", name="Sensitive Info", description="c2"),
    ]
    client = _mock_client("PASS")
    results = assess_all(MATERIAL, controls, client, max_workers=2)
    assert [r.control_id for r in results] == ["LLM01", "LLM02"]


def test_assess_all_calls_on_result():
    controls = [Control(id="LLM01", name="Prompt Injection", description="c")]
    client = _mock_client("PASS")
    received = []
    assess_all(MATERIAL, controls, client, on_result=received.append, max_workers=1)
    assert len(received) == 1
    assert received[0].control_id == "LLM01"
