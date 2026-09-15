# OWASP Top 10 LLM Assessment

Agent that assesses other agents for compliance with the OWASP Top 10 for LLM Applications (2025 edition). Part of the [SAAF Project](https://github.com/SAAF-Project).

## Repository structure

```
.
├── assessment-methodology.md  # PASS/WARN/FAIL criteria for all 10 controls
│
├── agent-reviewer/      # Standalone CLI + Flask web portal
│   ├── review_agent.py  # CLI: single file, multi-file, or folder review
│   ├── app.py           # Flask portal with drag-and-drop upload
│   └── owasp_llm_top10.json  # OWASP LLM category definitions
│
├── llm-owasp/           # Full audit pipeline package
│   ├── cli.py           # CLI entry point
│   ├── owasp_llm_audit/ # Core library (collector, auditor, controls, report)
│   ├── docs/            # Extended control docs (LLM01–LLM10)
│   ├── tests/           # Unit tests
│   ├── plan.md          # SAAF plan with architecture and roadmap
│   └── README.md        # Package-level docs
│
├── prototype/           # Earlier Flask/Jinja2 prototype (March 2026)
│   ├── app.py           # Flask app with Jinja2 template
│   ├── review_agent.py  # Prototype reviewer
│   ├── test_agent.py    # Intentionally insecure sample agent for testing
│   └── templates/       # HTML templates
│
├── outputs/             # Audit report outputs from prior runs
│   ├── owasp-agent-owasp-audit.md
│   ├── owasp-agent-owasp-audit-v2.md
│   ├── review-agent-owasp-audit.md
│   ├── hallucination-check-owasp-audit.md
│   └── track1-owasp-audit.md
│
└── plans/               # Hackathon planning documents
    ├── hackathon-2/
    └── hackathon-3/
```

## Quick start

### Agent Reviewer (CLI)

```bash
cd agent-reviewer
pip install anthropic openai flask
export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY with SAAF_LLM_PROVIDER=openai

python review_agent.py my_agent.py              # single file
python review_agent.py --folder agents_folder   # all files in a folder
python review_agent.py --thinking my_agent.py   # show extended thinking
```

### Agent Reviewer (Web Portal)

```bash
cd agent-reviewer
python app.py    # opens http://localhost:5000
```

### LLM-OWASP Audit Pipeline

```bash
cd llm-owasp
pip install -r requirements.txt
export ANTHROPIC_API_KEY=sk-ant-...   # or OPENAI_API_KEY with SAAF_LLM_PROVIDER=openai

python cli.py path/to/agent.py                  # scan a single file
python cli.py src/ --output reports/audit.md     # scan a directory
python cli.py agent.py --dry-run                 # preview without API calls
```

See [llm-owasp/README.md](llm-owasp/README.md) for full options and [llm-owasp/plan.md](llm-owasp/plan.md) for architecture details.

## Assessment methodology

See [assessment-methodology.md](assessment-methodology.md) for the full criteria used to determine PASS / WARN / FAIL / N/A verdicts per control, including:

- Verdict definitions and escalation rules
- Evidence standards (file path + line number required)
- Per-control criteria tables with 4–5 numbered checkpoints each
- Overall agent risk aggregation (Critical / High / Medium / Low)

## What it checks

All 10 OWASP LLM controls (2025 edition):

| ID | Control |
|---|---|
| LLM01 | Prompt Injection |
| LLM02 | Sensitive Information Disclosure |
| LLM03 | Supply Chain |
| LLM04 | Data and Model Poisoning |
| LLM05 | Improper Output Handling |
| LLM06 | Excessive Agency |
| LLM07 | System Prompt Leakage |
| LLM08 | Vector and Embedding Weaknesses |
| LLM09 | Misinformation |
| LLM10 | Unbounded Consumption |

## Model and provider

All tools call the LLM through a shared, provider-agnostic client (`llm_provider.py`). Set `SAAF_LLM_PROVIDER=anthropic` (default) or `openai` — the latter also covers Azure OpenAI, Ollama, vLLM, and other OpenAI-compatible endpoints via `SAAF_LLM_BASE_URL` — and `SAAF_LLM_MODEL` to pick the model. Defaults to `claude-opus-4-6` on Anthropic when unset.

## Related repos

- [SAAF-Project/threewaysecurity](https://github.com/SAAF-Project/threewaysecurity) — parent repo with audit document reviewer and compliance agent
- [SAAF-Project/SAAF-Project](https://github.com/SAAF-Project/SAAF-Project) — main SAAF monorepo
