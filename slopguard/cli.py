"""Command-line interface.

Two subcommands:

  slopguard triage --repo PATH [--file report.json] [--text]
      Read a report (from --file, or stdin if omitted), run the static checks
      against the repo, and print the triage decision as JSON (default) or as
      readable text (--text).

  slopguard refresh [--nvd-max N] [--ghsa-max N]
      Pull GHSA + NVD into the local cache the dedup check reads. Needs a
      GITHUB_TOKEN for GHSA; NVD works without one.

Exit codes: 0 ran fine, 2 bad input or usage. The verdict itself lives in the
output, never in the exit code. The maintainer decides.
"""

from __future__ import annotations

import argparse
import sys
import urllib.error
from pathlib import Path

from pydantic import ValidationError

from slopguard import advisories
from slopguard.decision import decide
from slopguard.schema import CheckOutcome, Report, TriageDecision
from slopguard.verification import verify_report


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="slopguard",
        description="Triage incoming vulnerability reports for AI slop.",
    )
    sub = parser.add_subparsers(dest="command", required=True)

    triage = sub.add_parser("triage", help="Triage one report.")
    triage.add_argument("--repo", required=True, help="Path to a clone of the project.")
    triage.add_argument("--file", help="Report JSON file. Reads stdin if omitted.")
    triage.add_argument("--text", action="store_true", help="Readable output.")

    refresh = sub.add_parser("refresh", help="Refresh the GHSA/NVD advisory cache.")
    refresh.add_argument("--nvd-max", type=int, default=2000)
    refresh.add_argument("--ghsa-max", type=int, default=2000)

    args = parser.parse_args(argv)
    if args.command == "triage":
        return _cmd_triage(args)
    if args.command == "refresh":
        return _cmd_refresh(args)
    return 2  # unreachable: the subparser is required


def _cmd_triage(args: argparse.Namespace) -> int:
    repo = Path(args.repo)
    if not repo.is_dir():
        print(f"error: --repo path does not exist: {args.repo}", file=sys.stderr)
        return 2

    try:
        if args.file:
            raw = Path(args.file).read_text(encoding="utf-8")
        else:
            raw = sys.stdin.read()
    except OSError as e:
        print(f"error: cannot read report: {e}", file=sys.stderr)
        return 2

    try:
        report = Report.model_validate_json(raw)
    except ValidationError as e:
        print(f"error: report does not match the schema:\n{e}", file=sys.stderr)
        return 2

    checks = verify_report(report, str(repo))
    decision = decide(report, checks)

    if args.text:
        print(_format_text(decision))
    else:
        print(decision.model_dump_json(indent=2))
    return 0


def _cmd_refresh(args: argparse.Namespace) -> int:
    try:
        pulled = advisories.refresh_cache(
            nvd_max=args.nvd_max, ghsa_max=args.ghsa_max
        )
    except (urllib.error.URLError, OSError, ValueError) as e:
        print(f"error: refresh failed: {e}", file=sys.stderr)
        return 2
    print(f"cached {len(pulled)} advisories to {advisories.default_cache_path()}")
    return 0


def _format_text(decision: TriageDecision) -> str:
    groups: dict[CheckOutcome, list] = {
        CheckOutcome.FAIL: [],
        CheckOutcome.PASS: [],
        CheckOutcome.INDETERMINATE: [],
    }
    for check in decision.static_checks:
        groups[check.outcome].append(check)

    lines = [
        f"SlopGuard triage  {decision.report_id}",
        "",
        f"Confidence: {decision.confidence_score}/100  ({decision.suggested_action})",
    ]
    sections = [
        (CheckOutcome.FAIL, "Failed checks:"),
        (CheckOutcome.PASS, "Passed checks:"),
        (CheckOutcome.INDETERMINATE, "Indeterminate:"),
    ]
    for outcome, title in sections:
        if groups[outcome]:
            lines.append("")
            lines.append(title)
            lines += [f"  - {c.name}: {c.detail}" for c in groups[outcome]]
    if decision.draft_response:
        lines += ["", "Draft response (edit before sending):", decision.draft_response]
    return "\n".join(lines)


if __name__ == "__main__":
    sys.exit(main())
