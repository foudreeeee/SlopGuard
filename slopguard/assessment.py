"""
LLM-assisted claim assessment layer.

Only reports passing the static verification layer reach this stage.
The LLM is used as a grounded reasoner over evidence the static layer
has already extracted, not as an autonomous oracle.

Design goals:
- Hallucination resistance via grounding. The model is forbidden from
  referencing files or symbols not in the provided context.
- Prompt-injection resistance. Report text is treated as untrusted
  input throughout. Outputs are typed and validated.
- Cost ceiling. Target under $0.05 per assessment, including retries.

Methodological foundation: HalluJudge (Tantithamthavorn et al., 2026).

Implementation status: design phase.
"""

from __future__ import annotations

from slopguard.schema import (
    LLMAssessment,
    Report,
    VerificationCheck,
)


def assess_claim(
    report: Report,
    static_checks: list[VerificationCheck],
    repo_path: str,
) -> LLMAssessment:
    """Run the grounded claim assessment for a report.

    Args:
        report: The normalized report.
        static_checks: Results from the static verification layer. Used to
            decide which code excerpts to extract for the LLM context.
        repo_path: Local filesystem path to the repository.

    Returns:
        A typed LLMAssessment. Outputs not matching the Pydantic schema
        are treated as soft-rejection signals and produce an
        UNDETERMINED verdict.
    """
    raise NotImplementedError("Phase 2 implementation.")


def _build_grounded_context(
    report: Report, static_checks: list[VerificationCheck], repo_path: str
) -> dict:
    """Extract the exact code excerpts and metadata to feed into the LLM.

    The LLM only sees this context. Any file or symbol not present here
    is considered hallucinated if the model cites it.
    """
    raise NotImplementedError("Phase 2 implementation.")


def _validate_citations(
    assessment: LLMAssessment, allowed_context: dict
) -> LLMAssessment:
    """Override the LLM verdict to UNDETERMINED if it cites code not in
    the provided context.

    This is the second line of defense against hallucinated assessments.
    """
    raise NotImplementedError("Phase 2 implementation.")
