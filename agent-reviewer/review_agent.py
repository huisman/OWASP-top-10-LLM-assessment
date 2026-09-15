"""
OWASP LLM Top 10 Agent Compliance Reviewer
Analyse agent source code or configs for OWASP Top 10 LLM security risks.

Usage:
  python review_agent.py                                          <- paste code
  python review_agent.py my_agent.py                             <- review one file
  python review_agent.py --thinking my_agent.py                  <- review + show extended thinking
  python review_agent.py agent1.py agent2.py agent3.py           <- review multi-agent system
  python review_agent.py --folder agents_folder                  <- review all agent files in a folder
  python review_agent.py --update-owasp                          <- update definitions from default URL
  python review_agent.py --update-owasp <url>                    <- update from a specific URL
"""

import hashlib
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

# llm_provider.py is shared from the repo root
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from llm_provider import LLMClient, LLMConfig

SUPPORTED_EXTENSIONS = (".py", ".js", ".ts", ".json", ".yaml", ".yml", ".txt", ".md")
MODEL = LLMConfig().model

OWASP_DEFS_PATH = os.path.join(os.path.dirname(os.path.abspath(__file__)), "owasp_llm_top10.json")
# Override this URL to point at your own hosted copy of owasp_llm_top10.json
OWASP_UPDATE_URL = "https://raw.githubusercontent.com/SAAF-Project/SAAF/master/owasp_llm_top10.json"
STALENESS_DAYS = 30


# ---------------------------------------------------------------------------
# OWASP definitions loading
# ---------------------------------------------------------------------------

def _load_owasp_defs() -> dict:
    """Load OWASP Top 10 definitions from the local JSON file."""
    try:
        with open(OWASP_DEFS_PATH, "r", encoding="utf-8") as f:
            return json.load(f)
    except FileNotFoundError:
        raise FileNotFoundError(
            f"OWASP definitions file not found: {OWASP_DEFS_PATH}\n"
            "Run: python review_agent.py --update-owasp"
        )
    except json.JSONDecodeError as e:
        raise ValueError(f"Invalid OWASP definitions file: {e}")


def _build_system_prompt(defs: dict) -> str:
    """Build the security review system prompt from loaded OWASP definitions."""
    edition = defs.get("edition", "OWASP Top 10 for Large Language Model Applications 2025")
    categories = defs.get("categories", [])

    cat_lines = []
    for c in categories:
        cat_lines.append(f"  {c['id']} – {c['name']}  {c['description']}")
        for indicator in c.get("indicators", []):
            cat_lines.append(f"    • {indicator}")

    return "\n".join([
        "You are a senior application security engineer specialising in LLM security.",
        "You review agent code, prompts, and configurations for compliance against the",
        f"{edition}.",
        "",
        "## Verdict definitions (assessment methodology v1.0)",
        "",
        "- PASS: All required mitigations are present in the code, configuration, or architecture.",
        "  No indicators of the risk were detected.",
        "- PARTIAL: Some mitigations are present but gaps remain. The risk is reduced but not",
        "  eliminated. Specific remediation actions can close the gap.",
        "- FAIL: One or more indicators of the risk are present with no corresponding mitigation.",
        "  The agent is exposed to the described attack or failure mode.",
        "- N/A: The agent's architecture makes the risk category irrelevant (e.g., no RAG for",
        "  LLM08, no fine-tuning for LLM04). Requires positive evidence the capability is absent.",
        "  If uncertain, default to PARTIAL.",
        "",
        "Verdict escalation: a single FAIL finding on any criterion within a control makes the",
        "overall control verdict FAIL. Mixed PASS and PARTIAL findings yield PARTIAL.",
        "",
        "## Evidence standard",
        "",
        "Every finding MUST cite:",
        "1. Location — file path and line number (e.g., agent.py:42)",
        "2. Observation — what was found or not found, stated as fact",
        "3. Reasoning — why this maps to the given verdict",
        "",
        "## Categories",
        "",
        "The ten categories you must assess are:",
        *cat_lines,
        "",
        "For each category that is relevant to the submitted code, output:",
        "",
        "**LLMxx – <Category Name>**",
        "- Status: PASS | FAIL | PARTIAL | N/A",
        '- Evidence: quote the exact line(s) of code or config value(s) that determined this status in a fenced code block with file:line references; write "none visible" if status is N/A',
        "- Findings: explain what the evidence shows and why it is a risk (or why it is safe)",
        "- Recommendation: concrete remediation step (skip if status is PASS or N/A)",
        "",
        "Then close with:",
        "",
        "**Overall Compliance Summary**",
        "- Overall risk rating, using these aggregation rules:",
        "  - Critical: 3+ FAIL verdicts, or FAIL on both LLM01 and LLM06",
        "  - High: 2+ FAIL verdicts, or FAIL on LLM01, LLM02, or LLM05",
        "  - Medium: 1 FAIL verdict, or 4+ PARTIAL verdicts",
        "  - Low: No FAIL verdicts and fewer than 4 PARTIAL verdicts",
        "- Top three priority fixes (numbered)",
        "- Positive security controls already in place",
        "",
        "When reviewing a multi-agent system, also assess inter-agent risks: cross-agent prompt injection",
        "paths, sensitive data flowing between agents, and cumulative agency across the system.",
        "",
        "Be specific. Quote actual variable names, string literals, and config keys from the submitted code.",
        "Do not guess about functionality that is not visible in the submitted code.",
    ])


# Load definitions at module level. Graceful fallback so --update-owasp can still run.
try:
    _OWASP_DEFS = _load_owasp_defs()
    _load_error = None
except (FileNotFoundError, ValueError) as _e:
    _OWASP_DEFS = {"version": "unknown", "edition": "OWASP Top 10 for LLM Applications", "categories": []}
    _load_error = str(_e)

OWASP_VERSION      = _OWASP_DEFS.get("version", "unknown")
OWASP_LAST_UPDATED = _OWASP_DEFS.get("last_updated", "")
OWASP_EDITION      = _OWASP_DEFS.get("edition", "OWASP Top 10 for LLM Applications")
OWASP_SOURCE_URL   = _OWASP_DEFS.get("source_url", "")

SYSTEM_PROMPT = _build_system_prompt(_OWASP_DEFS)

# Computed once at import time; included in every report so methodology is traceable.
PROMPT_HASH = hashlib.sha256(SYSTEM_PROMPT.encode("utf-8")).hexdigest()

_W = 62  # separator width


# ---------------------------------------------------------------------------
# Staleness check and update
# ---------------------------------------------------------------------------

def check_owasp_staleness() -> tuple:
    """Return (is_stale, days_old). days_old is -1 if undeterminable."""
    if not OWASP_LAST_UPDATED:
        return True, -1
    try:
        last = datetime.fromisoformat(OWASP_LAST_UPDATED.replace("Z", "+00:00"))
        days = (datetime.now(timezone.utc) - last).days
        return days > STALENESS_DAYS, days
    except ValueError:
        return False, -1


def update_owasp_definitions(url: str = OWASP_UPDATE_URL) -> dict:
    """Fetch updated OWASP definitions from url, validate, save, and return the new data."""
    if not url:
        raise ValueError(
            "No update URL configured. Pass a URL explicitly or set OWASP_UPDATE_URL in review_agent.py."
        )
    print(f"Fetching OWASP definitions from: {url}")
    try:
        with urllib.request.urlopen(url, timeout=15) as resp:
            raw = resp.read().decode("utf-8")
    except urllib.error.URLError as e:
        raise RuntimeError(f"Failed to fetch definitions: {e}") from e

    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise ValueError(f"Response is not valid JSON: {e}") from e

    missing = {"version", "categories"} - data.keys()
    if missing:
        raise ValueError(f"Invalid definitions — missing required keys: {missing}")
    if not isinstance(data["categories"], list) or not data["categories"]:
        raise ValueError("categories must be a non-empty list")
    for cat in data["categories"]:
        if not isinstance(cat, dict) or "id" not in cat or "name" not in cat:
            raise ValueError(f"Invalid category entry: {cat}")

    with open(OWASP_DEFS_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)
        f.write("\n")

    print(f"Saved: {data.get('edition', data.get('version'))}")
    print(f"  -> {OWASP_DEFS_PATH}")
    print("Restart the application to apply the updated definitions.")
    return data


# ---------------------------------------------------------------------------
# Audit helpers
# ---------------------------------------------------------------------------

def _sha256(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_report_header(agents: list) -> str:
    """Return a plain-text audit header block. agents: list of {"filename": str, "code": str}."""
    ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    combined = "|".join(f"{a['filename']}:{a['code']}" for a in agents)
    file_hash = _sha256(combined)
    file_label = ", ".join(a["filename"] for a in agents)
    hash_label = "SHA-256 (input)  " if len(agents) == 1 else "SHA-256 (combined)"
    return "\n".join([
        "=" * _W,
        "OWASP LLM TOP 10 REVIEW — AUDIT RECORD",
        "=" * _W,
        f"Reviewed:          {ts}",
        f"File(s):           {file_label}",
        f"Model:             {MODEL}",
        f"OWASP definitions: {OWASP_EDITION} (v{OWASP_VERSION}, updated {OWASP_LAST_UPDATED})",
        f"{hash_label}: {file_hash}",
        f"SHA-256 (prompt):  {PROMPT_HASH}",
        "=" * _W,
        "",
    ])


def read_file(file_path: str) -> str:
    """Read a source file as plain text."""
    _, ext = os.path.splitext(file_path)
    if ext.lower() not in SUPPORTED_EXTENSIONS:
        raise ValueError(f"Unsupported file type: {ext}")
    with open(file_path, "r", encoding="utf-8", errors="replace") as f:
        return f.read()


# ---------------------------------------------------------------------------
# Review engine
# ---------------------------------------------------------------------------

def _stream_review(user_message: str, show_thinking: bool = False) -> dict:
    """Stream a review request. Returns {"review": str, "thinking": str}."""
    client = LLMClient()
    result = []
    thinking_parts = []
    in_thinking = False

    for event in client.stream(system=SYSTEM_PROMPT, user=user_message, max_tokens=8192):
        if event.type == "thinking":
            if not in_thinking and show_thinking:
                in_thinking = True
                print("\033[2m\n[THINKING ────────────────────────────────]\033[0m", flush=True)
            thinking_parts.append(event.text)
            if show_thinking:
                print(f"\033[2m{event.text}\033[0m", end="", flush=True)
        elif event.type == "text":
            if in_thinking and show_thinking:
                print("\033[2m\n[──────────────────────── END THINKING]\033[0m\n", flush=True)
            in_thinking = False
            print(event.text, end="", flush=True)
            result.append(event.text)

    return {"review": "".join(result), "thinking": "".join(thinking_parts)}


def review_agent(code_text: str, filename: str = "<stdin>", show_thinking: bool = False) -> dict:
    """Review a single agent. Returns {"review": str, "thinking": str}."""
    print(f"\n--- Analysing {filename} against OWASP LLM Top 10... ---\n")
    user_message = (
        f"Please review the following agent code/config for OWASP LLM Top 10 compliance.\n"
        f"Filename: {filename}\n\n"
        f"```\n{code_text}\n```"
    )
    result = _stream_review(user_message, show_thinking)
    print("\n\n--- Review complete ---\n")
    return result


def review_multi_agent(agents: list, show_thinking: bool = False) -> dict:
    """Review a multi-agent system as a whole. agents: list of {"filename": str, "code": str}.
    Returns {"review": str, "thinking": str}.
    """
    filenames = ", ".join(a["filename"] for a in agents)
    print(f"\n--- Analysing multi-agent system ({len(agents)} components: {filenames}) ---\n")

    parts = [
        f"Please review the following multi-agent system ({len(agents)} components) "
        f"for OWASP LLM Top 10 compliance.\n\n"
        f"Assess each component individually and then consider inter-agent risks: "
        f"cross-agent prompt injection paths, sensitive data flowing between agents, "
        f"and cumulative agency across the system.\n"
    ]
    for i, agent in enumerate(agents, 1):
        parts.append(
            f"\n---\n\n### Component {i}: `{agent['filename']}`\n\n"
            f"```\n{agent['code']}\n```\n"
        )

    result = _stream_review("\n".join(parts), show_thinking)
    print("\n\n--- Review complete ---\n")
    return result


def assess_risk(filename: str, review_text: str) -> dict:
    """Ask the configured model to extract the overall risk rating from a completed review."""
    client = LLMClient()

    result = client.complete(
        system="""You are an LLM security risk classifier.
Given an OWASP LLM Top 10 review, extract the overall risk rating and one concise reason.
Respond in exactly this format:
RISK: Critical | High | Medium | Low
REASON: one sentence""",
        user=f"File: {filename}\n\nReview:\n{review_text}",
        max_tokens=256,
    )

    output = result.text
    risk_level = "Unknown"
    reason = ""

    for line in output.splitlines():
        if line.startswith("RISK:"):
            risk_level = line.replace("RISK:", "").strip()
        elif line.startswith("REASON:"):
            reason = line.replace("REASON:", "").strip()

    return {"file": filename, "risk": risk_level, "reason": reason}


def _write_report_file(path: str, agents: list, review: str, thinking: str) -> None:
    """Write a complete report file: audit header + optional thinking + review."""
    with open(path, "w", encoding="utf-8") as f:
        f.write(build_report_header(agents))
        if thinking:
            f.write("─" * _W + "\n")
            f.write("EXTENDED THINKING\n")
            f.write("[Model's reasoning chain, preserved for audit/reperformance purposes]\n")
            f.write("─" * _W + "\n\n")
            f.write(thinking)
            f.write("\n\n" + "─" * _W + "\n\n")
        f.write("REVIEW\n")
        f.write("─" * _W + "\n\n")
        f.write(review)


def save_priority_report(assessments: list, reports_folder: str) -> None:
    """Save agents sorted by risk level (Critical first)."""
    order = {"Critical": 0, "High": 1, "Medium": 2, "Low": 3, "Unknown": 4}
    sorted_assessments = sorted(assessments, key=lambda x: order.get(x["risk"], 4))

    report_path = os.path.join(reports_folder, "owasp_priority_report.txt")
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("OWASP LLM TOP 10 — AGENT PRIORITY REPORT\n")
        f.write("=" * 50 + "\n\n")
        for item in sorted_assessments:
            f.write(f"[{item['risk'].upper()}] {item['file']}\n")
            f.write(f"  → {item['reason']}\n\n")

    print("\n--- Priority Report ---\n")
    for item in sorted_assessments:
        print(f"  [{item['risk'].upper()}] {item['file']}")
        print(f"         {item['reason']}")
    print(f"\nSaved to: {report_path}")


def review_folder(folder_path: str) -> None:
    """Review all agent files in a folder individually, then generate a priority report."""
    if not os.path.isdir(folder_path):
        print(f"Error: Folder '{folder_path}' not found.")
        sys.exit(1)

    agent_files = [
        f for f in os.listdir(folder_path)
        if os.path.splitext(f)[1].lower() in SUPPORTED_EXTENSIONS
    ]

    if not agent_files:
        print(f"No supported agent files found in '{folder_path}'.")
        sys.exit(1)

    reports_folder = os.path.join(folder_path, "reports")
    os.makedirs(reports_folder, exist_ok=True)

    print(f"Found {len(agent_files)} file(s) to review.")
    print(f"Reports will be saved to: {reports_folder}\n")

    assessments = []

    for i, filename in enumerate(agent_files, 1):
        file_path = os.path.join(folder_path, filename)
        print(f"[{i}/{len(agent_files)}] {filename}")

        code_text = read_file(file_path)
        result = review_agent(code_text, filename)

        base_name = os.path.splitext(filename)[0]
        report_path = os.path.join(reports_folder, base_name + "_owasp_review.txt")
        _write_report_file(report_path, [{"filename": filename, "code": code_text}],
                           result["review"], result["thinking"])

        print(f"    Saved: {base_name}_owasp_review.txt")
        print(f"    Assessing risk level...")

        assessment = assess_risk(filename, result["review"])
        assessments.append(assessment)
        print(f"    Risk: {assessment['risk']}\n")

    print(f"\nAll {len(agent_files)} file(s) reviewed. Generating priority report...")
    save_priority_report(assessments, reports_folder)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    args = sys.argv[1:]
    show_thinking = "--thinking" in args
    args = [a for a in args if a != "--thinking"]

    # Option 0: update OWASP definitions
    if args and args[0] == "--update-owasp":
        url = args[1] if len(args) > 1 else OWASP_UPDATE_URL
        try:
            update_owasp_definitions(url)
        except (RuntimeError, ValueError) as e:
            print(f"Error: {e}")
            sys.exit(1)
        return

    # Fail fast if definitions failed to load (except for --update-owasp above)
    if _load_error:
        print(f"Error: {_load_error}")
        sys.exit(1)

    # Staleness warning
    is_stale, days = check_owasp_staleness()
    if is_stale:
        age = f"{days} days old" if days >= 0 else "unknown age"
        print(f"[Warning] OWASP definitions are {age} (>{STALENESS_DAYS} days). "
              f"Run: python review_agent.py --update-owasp\n")

    # Option 1: folder mode
    if len(args) >= 2 and args[0] == "--folder":
        review_folder(args[1])

    # Option 2: multiple files — multi-agent review
    elif len(args) >= 2:
        agents = []
        for file_path in args:
            try:
                code_text = read_file(file_path)
                agents.append({"filename": os.path.basename(file_path), "code": code_text})
            except FileNotFoundError:
                print(f"Error: File '{file_path}' not found.")
                sys.exit(1)
            except ValueError as e:
                print(f"Error: {e}")
                sys.exit(1)
        print(build_report_header(agents))
        review_multi_agent(agents, show_thinking=show_thinking)
        print(f"(To save, redirect stdout or use --folder mode for batch reports)")

    # Option 3: single file
    elif len(args) == 1:
        file_path = args[0]
        try:
            code_text = read_file(file_path)
        except FileNotFoundError:
            print(f"Error: File '{file_path}' not found.")
            sys.exit(1)
        except ValueError as e:
            print(f"Error: {e}")
            sys.exit(1)
        print(build_report_header([{"filename": os.path.basename(file_path), "code": code_text}]))
        review_agent(code_text, os.path.basename(file_path), show_thinking=show_thinking)

    # Option 4: paste mode
    else:
        print("Paste your agent code below.")
        print("When done, press Enter, then Ctrl+Z (Windows) and Enter to submit.\n")
        lines = []
        try:
            for line in sys.stdin:
                lines.append(line)
        except KeyboardInterrupt:
            pass
        code_text = "".join(lines).strip()
        if not code_text:
            print("No code provided. Exiting.")
            sys.exit(1)
        print(build_report_header([{"filename": "<stdin>", "code": code_text}]))
        review_agent(code_text, show_thinking=show_thinking)


if __name__ == "__main__":
    main()
