"""Static verification layer.

Cheap, deterministic checks. Runs before any LLM call.
Conservative by default — burying a real report is worse than letting slop through.

`_check_code_references` is implemented and tested.
The other checks are still TODOs (Phase 1 continues).
"""

from __future__ import annotations

import subprocess
from pathlib import Path

from slopguard.schema import (
    CheckOutcome,
    CodeReference,
    Report,
    VerificationCheck,
)


def verify_report(report: Report, repo_path: str) -> list[VerificationCheck]:
    """Run all static checks against a report."""
    checks: list[VerificationCheck] = []
    checks.extend(_check_code_references(report, repo_path))
    # TODO Phase 1: dedup, CWE plausibility, reporter signal
    return checks


def _check_code_references(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Do the cited files/lines actually exist at the claimed commit?

    For each CodeReference in the report:
      - Resolve the target commit (claimed_commit, else HEAD)
      - Check the file exists at that commit
      - If a line number is given, check the line is in range
      - If a symbol is given, do a coarse substring search (tree-sitter later)

    Symbol-level checks are intentionally lax for now: we only flag
    `symbol_never_found` when the symbol literally doesn't appear anywhere in
    the file. Tree-sitter integration (planned for Phase 2) will tighten this.
    """
    if not report.code_references:
        return []

    repo = Path(repo_path)
    if not (repo / ".git").is_dir():
        return [
            VerificationCheck(
                name="code_references",
                outcome=CheckOutcome.INDETERMINATE,
                detail=f"{repo_path} is not a git repository.",
            )
        ]

    target_commit = report.claimed_commit or "HEAD"
    if not _commit_exists(repo, target_commit):
        return [
            VerificationCheck(
                name="code_references",
                outcome=CheckOutcome.INDETERMINATE,
                detail=(
                    f"Claimed commit {target_commit} not found locally. "
                    f"Cannot verify code references."
                ),
            )
        ]

    results: list[VerificationCheck] = []
    for ref in report.code_references:
        results.append(_check_one_reference(repo, target_commit, ref))
    return results


def _check_one_reference(
    repo: Path, commit: str, ref: CodeReference
) -> VerificationCheck:
    """Check a single CodeReference against a specific commit."""
    file_content = _git_show(repo, commit, ref.file_path)
    if file_content is None:
        return VerificationCheck(
            name="file_not_found",
            outcome=CheckOutcome.FAIL,
            detail=(
                f"{ref.file_path} does not exist at commit {commit[:8]}."
            ),
        )

    lines = file_content.splitlines()
    if ref.line_number is not None:
        if ref.line_number < 1 or ref.line_number > len(lines):
            return VerificationCheck(
                name="line_out_of_range",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"{ref.file_path}:{ref.line_number} is out of range "
                    f"(file has {len(lines)} lines at commit {commit[:8]})."
                ),
            )

    if ref.symbol is not None:
        if ref.symbol not in file_content:
            return VerificationCheck(
                name="symbol_never_found",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"Symbol {ref.symbol!r} not found anywhere in "
                    f"{ref.file_path} at commit {commit[:8]}."
                ),
            )

    return VerificationCheck(
        name="code_reference_ok",
        outcome=CheckOutcome.PASS,
        detail=(
            f"{ref.file_path}"
            + (f":{ref.line_number}" if ref.line_number else "")
            + (f" ({ref.symbol})" if ref.symbol else "")
            + f" exists at {commit[:8]}."
        ),
    )


def _commit_exists(repo: Path, commit: str) -> bool:
    """Returns True if `commit` resolves to a known object in `repo`."""
    try:
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", f"{commit}^{{commit}}"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _git_show(repo: Path, commit: str, path: str) -> str | None:
    """Returns the file contents at `commit:path`, or None if missing."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{path}"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return result.stdout.decode("utf-8", errors="replace")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


def _check_advisory_dedup(report: Report) -> list[VerificationCheck]:
    """Is this a near-dupe of something in GHSA or NVD?

    TODO Phase 1: TF-IDF + n-gram overlap against cached feeds.
    """
    raise NotImplementedError("Phase 1.")


def _check_cwe_plausibility(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Could the claimed CWE actually happen here? (SQLi on a no-DB project = no.)

    TODO Phase 1: project profile derivation.
    """
    raise NotImplementedError("Phase 1.")


def _check_reporter_signal(report: Report) -> list[VerificationCheck]:
    """Soft signals only. Account age, prior credits, velocity.

    TODO Phase 1.
    """
    raise NotImplementedError("Phase 1.")
