# OWASP LLM Top 10 Audit Pipeline

Assesses any AI agent codebase, plan, or configuration against all 10 OWASP LLM controls (LLM01–LLM10, 2025 edition), via any supported LLM provider.

## Quick start

```bash
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY with SAAF_LLM_PROVIDER=openai

# Scan a single file
python cli.py path/to/agent.py

# Scan a directory, filtered by filename glob
python cli.py ../plans/hackathon-2 --filter "*.md"

# Multiple targets, custom output, strict mode (WARN also fails)
python cli.py src/ config/ --output reports/audit.md --strict

# Scan one specific control only
python cli.py agent.py --control LLM01

# Dry run — no API calls, synthetic report to preview output format
python cli.py agent.py --dry-run
```

## Options

| Flag | Description |
|---|---|
| `--filter GLOB` | Filename glob applied when walking directories |
| `--output FILE` | Output path (default: `<target>_owasp_audit.md`) |
| `--control ID` | Assess a single control only (e.g. `LLM01`) |
| `--strict` | Exit non-zero on WARN as well as FAIL (CI/CD) |
| `--dry-run` | Skip API calls; generate synthetic report |

## Output

Produces a Markdown report with:
- Scorecard table (PASS / WARN / FAIL / N-A per control)
- Per-control findings and remediation advice
- SAAF finding schema JSON (machine-readable, maps to `outputs/schemas/finding-schema.json`)

## Running tests

```bash
python -m pytest tests/ -v
```

## Architecture

```
owasp_llm_audit/
  collector.py   — collects & normalises audit material from files/dirs
  controls.py    — loads LLM01–LLM10 control definitions from docs/
  auditor.py     — calls the configured LLM via llm_provider.py (parallel, with retry/backoff)
  report.py      — renders Markdown scorecard + SAAF finding schema JSON
  docs/          — OWASP LLM control definition files (LLM01.md … LLM10.md)
cli.py           — CLI entry point
requirements.txt — Python dependencies
tests/           — unit tests
```
