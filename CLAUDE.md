# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this project does

This repo is the **OWASP Top 10 LLM Assessment** project — part of the [SAAF Project](https://github.com/SAAF-Project). It contains multiple tools for assessing AI agents against the OWASP Top 10 for LLM Applications (2025 edition), plus a compliance report generator and shared audit utilities.

### Tools in this repo

1. **Agent Reviewer CLI + Web Portal** (`agent-reviewer/`) — the primary tool. Reviews agent source code and configs against OWASP LLM Top 10. Available as CLI (`review_agent.py`) and Flask web portal (`app.py`). Includes `owasp_llm_top10.json` definitions with auto-update support.

2. **LLM OWASP Audit Pipeline** (`llm-owasp/`) — full pipeline package with parallel LLM API calls, per-control scoring (PASS/WARN/FAIL), Markdown reports, and a machine-readable SAAF finding schema. Entry point: `cli.py`.

3. **Root-level Reviewer** (`review_agent.py` + `app.py`) — earlier standalone version of the OWASP reviewer, still functional.

4. **Audit Document Reviewer** (`review_document.py`) — reviews internal audit documents (control descriptions, process docs, policies) for findings, gaps, risks, and recommendations.

5. **SAAF Compliance Agent** (`core/`, `prompts/`, `knowledge/`, `output/`) — structured compliance report generator. Maps applicable frameworks/regulations from a company profile, then calls the configured LLM to produce a validated Pydantic `ComplianceReport` as JSON.

6. **Prototype** (`prototype/`) — earlier Flask/Jinja2 prototype of the agent reviewer (March 2026). Contains `test_agent.py`, an intentionally insecure sample agent for testing.

## Model and provider configuration

All tools call the LLM through the shared `llm_provider.py` module (`config.py` for the SAAF Compliance Agent) instead of talking to a vendor SDK directly, so no tool is locked to a single AI provider or model. Configure via environment variables:

```
SAAF_LLM_PROVIDER    "anthropic" (default) or "openai"
SAAF_LLM_MODEL        Model id. Defaults: "claude-opus-4-6" (anthropic), "gpt-5" (openai)
SAAF_LLM_API_KEY      Optional; overrides the provider-native key env var below
ANTHROPIC_API_KEY      Used when provider=anthropic and SAAF_LLM_API_KEY unset
OPENAI_API_KEY         Used when provider=openai and SAAF_LLM_API_KEY unset
SAAF_LLM_BASE_URL     Optional custom endpoint — Azure OpenAI, a local Ollama/vLLM
                       server, or any other OpenAI-compatible API
SAAF_LLM_REASONING    "1" (default) or "0" — request extended thinking/reasoning
                       where the provider and model support it
```

`SAAF_LLM_PROVIDER=openai` also covers any OpenAI-compatible endpoint (Azure OpenAI, Ollama, vLLM, other hosted providers) via `SAAF_LLM_BASE_URL`.

## How to run

Set the API key for your chosen provider first (defaults to Anthropic if unset):
```
set ANTHROPIC_API_KEY=sk-ant-...your-key...
```

**Agent Reviewer (CLI) — primary:**
```
cd agent-reviewer
python review_agent.py my_agent.py                 # single file
python review_agent.py --folder agents_folder      # all agent files in a folder
python review_agent.py                             # paste code
python review_agent.py --update-owasp              # refresh OWASP definitions
```

**Agent Reviewer (Web Portal) — primary:**
```
cd agent-reviewer
pip install flask
python app.py                                      # opens http://localhost:5000
```

**LLM OWASP Audit Pipeline:**
```
cd llm-owasp
pip install -r requirements.txt
python cli.py path/to/agent.py                     # single file
python cli.py src/ --filter "*.py"                 # directory with glob filter
python cli.py agent.py --control LLM01             # single control only
python cli.py agent.py --strict                    # fail on WARN too (CI/CD)
python cli.py agent.py --dry-run                   # no API calls, preview format
```

**Audit Document Reviewer:**
```
python review_document.py my_document.txt          # single file (.txt, .docx, .pdf)
python review_document.py --folder my_folder       # all supported docs in a folder
python review_document.py                          # paste text (Ctrl+Z then Enter on Windows)
```

## Dependencies

```
pip install anthropic openai python-docx pypdf flask pydantic rich
```

Only the SDK for your configured `SAAF_LLM_PROVIDER` is actually imported at runtime (see `llm_provider.py`), but both are listed here since the provider is a runtime choice, not an install-time one.

`llm-owasp/` has its own `requirements.txt`.

## Repository structure

```
.
├── assessment-methodology.md    # PASS/WARN/FAIL criteria for all 10 controls
│
├── agent-reviewer/              # Primary standalone CLI + Flask web portal
│   ├── review_agent.py          # CLI reviewer (single file, multi-file, folder, --update-owasp)
│   ├── app.py                   # Flask portal with drag-and-drop upload, streaming
│   └── owasp_llm_top10.json     # OWASP LLM category definitions (auto-updatable)
│
├── llm-owasp/                   # Full audit pipeline package
│   ├── cli.py                   # CLI entry point
│   ├── owasp_llm_audit/         # Core library: collector, auditor, controls, report
│   ├── docs/                    # Extended control docs (LLM01–LLM10)
│   ├── tests/                   # Unit tests (pytest)
│   └── plan.md                  # Architecture and roadmap
│
├── review_agent.py              # Root-level standalone reviewer (earlier version)
├── app.py                       # Root-level Flask portal (earlier version)
├── review_document.py           # Audit document reviewer (.txt, .docx, .pdf)
├── owasp_llm_top10.json         # OWASP definitions for root-level reviewer
├── llm_provider.py              # Shared provider-agnostic LLM client (Anthropic/OpenAI)
├── config.py                    # Runtime config (provider/model/key) for the Compliance Agent
│
├── core/                        # SAAF Compliance Agent — agent logic + models
├── prompts/                     # SAAF Compliance Agent — prompt builders
├── knowledge/                   # SAAF Compliance Agent — framework/regulation registry
├── output/                      # SAAF Compliance Agent — Rich report formatter
│
├── prototype/                   # Earlier Flask/Jinja2 prototype (March 2026)
│   ├── app.py                   # Flask app with Jinja2 templates
│   ├── review_agent.py          # Prototype reviewer
│   ├── test_agent.py            # Intentionally insecure agent for testing
│   └── templates/               # HTML templates
│
├── outputs/                     # Audit report outputs from prior runs
├── plans/                       # Hackathon planning documents
│   ├── hackathon-2/
│   └── hackathon-3/
└── SAAF-Project/                # SAAF shared workspace content (submodule/copy)
```

## Architecture

**`llm_provider.py`** — shared provider-agnostic LLM client used by every tool below. `LLMClient` wraps either the Anthropic or OpenAI SDK (selected via `SAAF_LLM_PROVIDER`), exposing `complete()`, `stream()` (yields `StreamEvent("text"|"thinking", ...)`), and `complete_with_retry()` for parallel/batch callers. Raises `ProviderError` subclasses (`ProviderRateLimitError`, `ProviderAPIError`, `ProviderConnectionError`) instead of vendor-specific exceptions.

**`agent-reviewer/review_agent.py`** — self-contained CLI. Supports `.py`, `.js`, `.ts`, `.json`, `.yaml`, `.yml`, `.txt`, `.md`. Two-call pattern: streaming `review_agent()` produces OWASP per-category findings via `LLMClient.stream()` (extended thinking requested when the provider supports it), then `assess_risk()` extracts Critical/High/Medium/Low. In folder mode, writes `<filename>_owasp_review.txt` and `owasp_priority_report.txt` into `<folder>/reports/`. Exports `SYSTEM_PROMPT` and `SUPPORTED_EXTENSIONS` for `app.py`. Reads definitions from `owasp_llm_top10.json`; `--update-owasp` fetches a fresh copy from the configured URL. Imports `llm_provider.py` from the repo root via a `sys.path` bootstrap.

**`agent-reviewer/app.py`** — Flask web portal. Imports `SYSTEM_PROMPT` and `SUPPORTED_EXTENSIONS` from `review_agent`. Streams the model's response directly to the browser via `stream_with_context`. All HTML/CSS/JS inlined. Port defaults to `5000`, overridable via `PORT` env var.

**`llm-owasp/`** — pipeline package:
- `owasp_llm_audit/collector.py` — collects and normalises audit material from files/dirs
- `owasp_llm_audit/controls.py` — loads LLM01–LLM10 definitions from `docs/`
- `owasp_llm_audit/auditor.py` — calls the configured LLM in parallel via `LLMClient.complete_with_retry()`
- `owasp_llm_audit/report.py` — renders Markdown scorecard + SAAF finding schema JSON
- `cli.py` — entry point; supports `--filter`, `--output`, `--control`, `--strict`, `--dry-run`

**`review_document.py`** — self-contained. Supports `.txt`, `.docx`, `.pdf`. Two-call pattern: streaming `review_document()` produces structured audit review, then `assess_risk()` assigns High/Medium/Low. In folder mode, `save_priority_report()` writes `priority_report.txt` sorted by risk into `<folder>/reports/`.

**SAAF Compliance Agent** (`core/`, `prompts/`, `knowledge/`, `output/`):
1. `FrameworkMapper` (`core/mapper.py`) — pure-Python, no API call. Resolves jurisdiction, walks `FRAMEWORK_REGISTRY` and `REGULATORY_MATRIX` to determine applicable frameworks (capped at 8) and mandatory regulations.
2. `build_system_prompt` / `build_user_message` (`prompts/system_prompt.py`) — assembles prompts dynamically; injects only relevant framework knowledge.
3. `ComplianceAgent.run()` (`core/agent.py`) — calls the configured LLM via `llm_provider.LLMClient.stream()` with extended thinking requested where supported, retries once on 5xx, validates against `ComplianceReport` Pydantic schema (`core/models.py`).
4. `output/formatter.py` — Rich-based CLI renderer for the final report.

`ComplianceAgent` reads settings from the `Config` class in `config.py` (root) — provider, model, API key, base URL, max tokens, and max retries, all environment-driven.

## Coding conventions

- Python: PEP 8, type hints, `pathlib` over `os.path`
- All content in English (plans, docs, prompts, commit messages)
- Credentials from environment variables only, never hardcoded
- Agent outputs should conform to `outputs/schemas/finding-schema.json`: required fields `id` (`F-\d{2,4}`), `title`, `risk_rating` (High/Medium/Low/Informational), `observation`, `recommendation`

## Model used

Configurable per deployment via `SAAF_LLM_PROVIDER` / `SAAF_LLM_MODEL` (see "Model and provider configuration" above). Defaults to `claude-opus-4-6` on Anthropic when unset, for backward compatibility with existing deployments.
