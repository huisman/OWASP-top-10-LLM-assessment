# `AUDIT-CRITERIA.md`

## Metadata

| Field | Value |
|---|---|
| **Agent** | OWASP Top 10 LLM Assessment |
| **Repository** | https://github.com/SAAF-Project/OWASP-top-10-LLM-assessment |
| **Maintainer(s)** | SAAF Project |
| **Last reviewed** | 2026-09-15 |
| **Status** | Draft |

## 1. What the agent does

Reviews AI agent source code and configuration files against the OWASP Top 10 for LLM Applications (2025 edition). Takes a file or folder of agent artefacts as input and produces a structured per-control verdict (PASS / WARN / FAIL / N/A) plus an overall risk rating (Critical / High / Medium / Low). Available as a CLI, a Flask web portal, and a full audit pipeline package.

## 2. Control objectives & framework mapping

| Control objective | Framework + clause/area | Why relevant |
|---|---|---|
| CO-1 — LLM-based agents are assessed for prompt injection vulnerabilities before deployment | OWASP LLM01 (2025) | Prompt injection is the leading attack vector against LLM applications |
| CO-2 — Agents do not expose sensitive information or credentials through outputs, logs, or prompts | OWASP LLM02 (2025) · GDPR Art. 25 (data minimisation) | Prevents PII leakage and credential theft |
| CO-3 — Agent supply chains (dependencies, models, plugins) are verified, pinned, and monitored | OWASP LLM03 (2025) · ISO 27001 (Third-Party & Vendor Risk) | Unverified dependencies are a primary compromise vector |
| CO-4 — Agents operate under least privilege and require human authorisation for irreversible actions | OWASP LLM06 (2025) · EU AI Act · NIST AI RMF | Limits blast radius of agent misbehaviour |
| CO-5 — LLM-generated outputs are validated before being rendered, executed, or passed to downstream systems | OWASP LLM05 (2025) | Prevents XSS, SQL injection, and code execution from model output |
| CO-6 — Agents have resource controls to prevent unbounded API consumption and cost overruns | OWASP LLM10 (2025) | Protects against denial-of-wallet and runaway agentic loops |

*Full framework catalogue: `docs/reference/domains-and-frameworks.md` in the SAAF-Project repo.*

## 3. Acceptance criteria (testable, pass/fail)

**CO-1 — Prompt Injection**
- Given an agent file, the tool identifies whether system prompt and user input are structurally separated at the API level.
- Given raw user input concatenated into the system prompt, the tool returns FAIL for LLM01.
- Given an agent with no user input and hardcoded prompts only, the tool returns N/A for LLM01.

**CO-2 — Sensitive Information Disclosure**
- Given an agent file containing a hardcoded API key or secret, the tool returns FAIL for LLM02.
- Given an agent that sends full user records to the model without redaction, the tool returns FAIL for LLM02.
- Given an agent that loads secrets from environment variables only, the tool returns PASS for criterion 2.1.

**CO-3 — Supply Chain**
- Given a project with no version-pinned dependencies and no lockfile, the tool returns FAIL for LLM03.
- Given a project with all dependencies pinned and a lockfile present, the tool returns PASS for criterion 3.1.
- The tool never returns N/A for LLM03 regardless of agent architecture.

**CO-4 — Excessive Agency**
- Given an agent that performs irreversible actions (delete, send, publish) without a human confirmation step, the tool returns FAIL for LLM06.
- Given a read-only agent with no tools and no API calls, the tool returns N/A for LLM06.
- Given an agent with no iteration cap on agentic loops, the tool returns FAIL for criterion 6.3.

**CO-5 — Improper Output Handling**
- Given model output passed to `eval()`, `exec()`, or `subprocess` with no sandboxing, the tool returns FAIL for LLM05.
- Given model output interpolated into raw SQL without parameterisation, the tool returns FAIL for criterion 5.3.
- Given an agent that renders model output as raw HTML with no escaping, the tool returns FAIL for criterion 5.1.

**CO-6 — Unbounded Consumption**
- Given an API call with no `max_tokens` set, the tool returns FAIL for LLM10.
- Given an agent with no iteration limits on loops, the tool returns FAIL for criterion 10.2.
- The tool never returns N/A for LLM10 regardless of agent architecture.

## 4. Good output / never do

| A correct output MUST contain | The agent must NEVER |
|---|---|
| ✓ A verdict (PASS / WARN / FAIL / N/A) for each of the 10 OWASP LLM controls | ✕ Invent findings not grounded in the submitted source code or config |
| ✓ File path and line number evidence for every non-N/A verdict | ✕ Present output as audit-ready without a human-review gate |
| ✓ An overall risk rating (Critical / High / Medium / Low) derived from the aggregation rules in `assessment-methodology.md` | ✕ Hard-code credentials or API keys in source, prompts, or config |
| ✓ `llm-owasp` appends a machine-readable JSON block conforming to `outputs/schemas/finding-schema.json` for every FAIL/WARN verdict | ✕ Return N/A for LLM03 or LLM10 (these controls are never N/A) |
| ✓ Confidence language that distinguishes evidence-backed findings from inferences | ✕ Return N/A for LLM09 in any audit context |

## 5. Coverage gaps

- **No dynamic / runtime analysis** — the tool performs static analysis only. Prompt injection via runtime tool outputs is not detectable from source code alone.
- **LLM04 (Data and Model Poisoning)** — criteria require access to training pipelines and RAG ingestion processes that are rarely in scope of a single agent file review.
- **LLM08 (Vector and Embedding Weaknesses)** — tenant isolation and write-access controls on vector stores cannot be verified from agent source code without access to infrastructure configuration.
- **No end-to-end acceptance tests** — `llm-owasp` has unit tests (`tests/`) but they mock the Claude API and test pipeline mechanics only, not whether the tool correctly detects real vulnerabilities. Neither tool has tests that run against `prototype/test_agent.py` or any real insecure agent. `agent-reviewer/` has no test suite at all.
- **Multi-file dependency tracing** — the tool does not resolve cross-file imports, so secrets or unsafe patterns in imported modules may not be detected.

## 6. Status / validation

| Acceptance criterion | Verified? | Evidence |
|---|---|---|
| CO-1 #1 — Structural separation detected | ☐ | Pending A1 stress-test |
| CO-1 #2 — FAIL on concatenated prompt | ☐ | Pending |
| CO-2 #1 — FAIL on hardcoded API key | ☐ | Pending |
| CO-3 #3 — Never N/A for LLM03 | ☐ | Pending |
| CO-4 #1 — FAIL on no human checkpoint | ☐ | Pending |
| CO-5 #1 — FAIL on eval/exec with model output | ☐ | Pending |
| CO-6 #1 — FAIL on missing max_tokens | ☐ | Pending |
| CO-6 #3 — Never N/A for LLM10 | ☐ | Pending |
