"""
Static verification layer.

Runs deterministic, cheap checks before any LLM call. The output of this
module feeds into both the context provided to the LLM assessment layer
and directly into the evidence panel shown to the maintainer.

Design goals:
- Conservative by default. False positives (rejecting genuine reports)
  are worse than false negatives (letting slop through to the LLM layer).
- Fast. Target under one second per report.
- Auditable. Every check produces a human-readable `detail` string.

Implementation status: design phase. The functions below are stubs
that document the expected interface.
"""

from __future__ import annotations

from slopguard.schema import (
    CheckOutcome,
    Report,
    VerificationCheck,
)


def verify_report(report: Report, repo_path: str) -> list[VerificationCheck]:
    """Run all static checks against a report.

    Args:
        report: The normalized report to verify.
        repo_path: Local filesystem path to the repository.

    Returns:
        A list of check results, one per check that was applicable.
    """
    checks: list[VerificationCheck] = []
    checks.extend(_check_code_references(report, repo_path))
    checks.extend(_check_advisory_dedup(report))
    checks.extend(_check_cwe_plausibility(report, repo_path))
    checks.extend(_check_reporter_signal(report))
    return checks


def _check_code_references(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Verify that file paths, lines, and symbols cited in the report
    actually exist in the repository at the claimed commit.

    TODO: implement git-based commit resolution + tree-sitter symbol lookup.
    """
    raise NotImplementedError("Phase 1 implementation.")


def _check_advisory_dedup(report: Report) -> list[VerificationCheck]:
    """Fuzzy-match the report against GHSA and NVD to flag near-duplicates.

    TODO: implement TF-IDF + n-gram overlap with cached GHSA + NVD feeds.
    """
    raise NotImplementedError("Phase 1 implementation.")


def _check_cwe_plausibility(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Check whether the claimed CWE is possible given the project's surface.

    A SQL injection claim against a project with no SQL surface gets a
    lower-confidence signal, not an automatic rejection.

    TODO: implement project-profile derivation + CWE-to-surface mapping.
    """
    raise NotImplementedError("Phase 1 implementation.")


def _check_reporter_signal(report: Report) -> list[VerificationCheck]:
    """Compute soft signals from reporter metadata.

    None of these signals are decisive. They route reports to faster or
    slower lanes, they do not auto-reject.

    TODO: implement based on the reporter info already in the schema.
    """
    raise NotImplementedError("Phase 1 implementation.")
