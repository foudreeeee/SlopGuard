"""Static verification layer.

Cheap, deterministic checks. Runs before any LLM call.
Conservative by default — burying a real report is worse than letting slop through.

Status: skeleton. Functions below are TODOs.
"""

from __future__ import annotations

from slopguard.schema import (
    CheckOutcome,
    Report,
    VerificationCheck,
)


def verify_report(report: Report, repo_path: str) -> list[VerificationCheck]:
    """Run all static checks against a report."""
    checks: list[VerificationCheck] = []
    checks.extend(_check_code_references(report, repo_path))
    checks.extend(_check_advisory_dedup(report))
    checks.extend(_check_cwe_plausibility(report, repo_path))
    checks.extend(_check_reporter_signal(report))
    return checks


def _check_code_references(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Do the cited files/lines/symbols actually exist at the claimed commit?

    TODO: git resolution + tree-sitter symbol lookup.
    """
    raise NotImplementedError("Phase 1.")


def _check_advisory_dedup(report: Report) -> list[VerificationCheck]:
    """Is this a near-dupe of something in GHSA or NVD?

    TODO: TF-IDF + n-gram overlap.
    """
    raise NotImplementedError("Phase 1.")


def _check_cwe_plausibility(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Could the claimed CWE actually happen here? (SQLi on a no-DB project = no.)

    TODO: project profile derivation.
    """
    raise NotImplementedError("Phase 1.")


def _check_reporter_signal(report: Report) -> list[VerificationCheck]:
    """Soft signals only. Account age, prior credits, velocity.

    TODO: implement.
    """
    raise NotImplementedError("Phase 1.")
