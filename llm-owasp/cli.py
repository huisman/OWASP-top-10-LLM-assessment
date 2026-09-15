"""OWASP LLM Top 10 audit pipeline.

Usage:
    python cli.py <target> [<target> ...] [--filter GLOB] [--output FILE]
                  [--control ID] [--strict] [--dry-run]

Examples:
    python cli.py review_agent.py
    python cli.py plans/hackathon-2 --filter "frank-van-dissel-uc*.md"
    python cli.py src/ tests/ --output reports/audit.md --strict
    python cli.py agent.py --control LLM01
    python cli.py agent.py --dry-run
"""
from __future__ import annotations
import argparse
import itertools
import os
import sys
import threading
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent))
sys.path.insert(0, str(Path(__file__).parent.parent))

from llm_provider import LLMClient, ProviderError
from owasp_llm_audit.collector import collect
from owasp_llm_audit.controls import load_controls, CONTROL_IDS
from owasp_llm_audit.auditor import Assessment, assess, assess_all
from owasp_llm_audit.report import format_report

_print_lock = threading.Lock()

# Fix 3: dry-run cycles through varied verdicts so the report format is meaningful
_DRY_RUN_VERDICTS = itertools.cycle(["PASS", "WARN", "FAIL", "N-A", "PASS", "WARN", "PASS", "PASS", "WARN", "PASS"])


def _on_result(a: Assessment) -> None:
    with _print_lock:
        print(f"      {a.control_id} [{a.verdict}]")


def _dry_run_assessment(control_id: str, control_name: str) -> Assessment:
    verdict = next(_DRY_RUN_VERDICTS)
    findings = ["[dry-run] synthetic finding for demonstration"] if verdict in ("FAIL", "WARN") else []
    remediation = ["[dry-run] synthetic remediation advice"] if verdict in ("FAIL", "WARN") else []
    return Assessment(
        control_id=control_id,
        control_name=control_name,
        verdict=verdict,
        findings=findings,
        remediation=remediation,
    )


def _default_output(targets: list[str], filter_glob: str | None) -> Path:
    """Fix 4: derive a meaningful default output path from the target."""
    base = Path(targets[0])
    stem = base.stem if base.is_file() else base.name
    if filter_glob:
        stem = filter_glob.replace("*", "").replace("?", "").strip("-_. ") or stem
    return Path(f"{stem}_owasp_audit.md")


def main() -> None:
    parser = argparse.ArgumentParser(
        description="OWASP LLM Top 10 audit pipeline for AI agents",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument("target", nargs="+", help="Path(s) to audit — files or directories")
    parser.add_argument("--filter", metavar="GLOB", default=None,
                        help="Filename glob filter when walking directories")
    parser.add_argument("--output", default=None,
                        help="Output report path (default: <target>_owasp_audit.md)")
    # Fix 7: --control for single-control re-runs
    parser.add_argument("--control", metavar="ID", default=None,
                        choices=CONTROL_IDS,
                        help="Assess a single control only (e.g. LLM01)")
    parser.add_argument("--strict", action="store_true",
                        help="Exit non-zero on WARN as well as FAIL (useful for CI)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Skip API calls and generate a synthetic report")
    args = parser.parse_args()

    if not args.dry_run:
        try:
            client = LLMClient()
        except ProviderError as e:
            print(f"ERROR: {e}", file=sys.stderr)
            sys.exit(1)

    label = ", ".join(args.target) + (f" [filter={args.filter}]" if args.filter else "")

    print(f"[1/4] Collecting audit material from: {label}")
    material = collect(args.target, filter_glob=args.filter)
    print(f"      {len(material):,} bytes collected")

    print("[2/4] Loading OWASP LLM control definitions")
    all_controls = load_controls()
    controls = [c for c in all_controls if c.id == args.control] if args.control else all_controls
    print(f"      {len(controls)} control(s) loaded" + (f" [{args.control}]" if args.control else ""))

    print("[3/4] Assessing controls" + (" [dry-run]" if args.dry_run else ""))
    if args.dry_run:
        assessments = [_dry_run_assessment(c.id, c.name) for c in controls]
    else:
        if args.control:
            # Single control — no need for thread pool
            a = assess(material, controls[0], client)
            _on_result(a)
            assessments = [a]
        else:
            # Fix 5: max_workers=2 to avoid hammering rate limits with large material
            assessments = assess_all(material, controls, client, on_result=_on_result, max_workers=2)

    print("[4/4] Generating report")
    # Fix 4: sensible default output path
    out_path = Path(args.output) if args.output else _default_output(args.target, args.filter)
    report_text = format_report(label, assessments)
    out_path.write_text(report_text, encoding="utf-8")
    print(f"      Saved: {out_path.resolve()}")

    counts = {v: sum(1 for a in assessments if a.verdict == v)
              for v in ("FAIL", "WARN", "PASS", "N-A")}
    print(f"\nResult: {counts['FAIL']} FAIL  {counts['WARN']} WARN  "
          f"{counts['PASS']} PASS  {counts['N-A']} N/A")

    if counts["FAIL"] > 0 or (args.strict and counts["WARN"] > 0):
        sys.exit(2)


if __name__ == "__main__":
    main()
