"""LLM claim assessment layer.

Runs after static checks pass. The LLM gets the report + the actual code
the static layer pulled out. It's not allowed to reference anything outside
that context — if it does, we override the verdict to UNDETERMINED.

Methodologically borrowed from HalluJudge (Tantithamthavorn et al., 2026).

Status: skeleton.
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
    """Grounded claim assessment. PLAUSIBLE / IMPLAUSIBLE / UNDETERMINED.

    Outputs failing schema validation → soft-reject (treated as UNDETERMINED).
    """
    raise NotImplementedError("Phase 2.")


def _build_grounded_context(
    report: Report, static_checks: list[VerificationCheck], repo_path: str
) -> dict:
    """Pull the exact code excerpts and metadata the LLM is allowed to see.

    Anything outside this context is hallucinated if the model cites it.
    """
    raise NotImplementedError("Phase 2.")


def _validate_citations(
    assessment: LLMAssessment, allowed_context: dict
) -> LLMAssessment:
    """Second line of defense: override to UNDETERMINED if the model
    cites code that wasn't in the context.
    """
    raise NotImplementedError("Phase 2.")
