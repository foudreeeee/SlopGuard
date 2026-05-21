"""Decision layer.

Turns the static checks (and, later, the LLM assessment) into the single
TriageDecision a maintainer sees: a 0-100 confidence score, a suggested
action, and an editable draft reply.

Scoring is a transparent weighted sum, on purpose. No multiplicative magic,
no cross-signal interaction rules ("if dedup is high AND code ref failed,
multiply by..."). Every check moves the score by a fixed, documented amount,
so the same evidence always produces the same score and a maintainer can read
off exactly why. Higher score = more credible report.

Two rules baked into the weights:
  - A failed check weighs more than a passed one. A fabricated file path is
    strong evidence of slop; a real file path doesn't prove the bug is real.
  - Soft signals (reporter reputation) are deliberately small, so they can
    never push a report across an action boundary on their own.

The maintainer always sees the full evidence regardless of score. Nothing
here closes a report.
"""

from __future__ import annotations

from datetime import UTC, datetime

from slopguard.schema import (
    CheckOutcome,
    LLMAssessment,
    Report,
    TriageDecision,
    VerificationCheck,
)

# --- tunable knobs (a maintainer can adjust these without touching logic) ---

# Score ranges -> suggested action. Higher score = more credible report.
THRESHOLD_FAST_TRACK = 80  # >= 80   -> fast_track
THRESHOLD_STANDARD = 40  # 40..79  -> standard_review
THRESHOLD_CLARIFICATION = 20  # 20..39  -> request_clarification
# below THRESHOLD_CLARIFICATION    -> likely_slop

# An unverifiable report sits at "unknown" and gets nudged from there.
BASELINE_SCORE = 50

# Per-category point contributions. Negative on fail (suspicious), positive on
# pass (credible). Failures weigh more than passes (see module docstring), and
# the soft signal is small enough that it can never decide alone.
SCORE_WEIGHTS: dict[str, dict[str, int]] = {
    "code_reference": {"fail": -35, "pass": 12},
    "advisory_dedup": {"fail": -25, "pass": 8},
    "cwe_plausibility": {"fail": -20, "pass": 6},
    "reporter_signal": {"fail": -8, "pass": 5},  # soft: never decides alone
}

# The LLM verdict (Phase 2) folds into the same transparent sum. Listed here so
# the contract is complete; the layer that produces the verdict is not built
# yet (assessment.py is a skeleton).
LLM_WEIGHTS = {"PLAUSIBLE": 20, "IMPLAUSIBLE": -30, "UNDETERMINED": 0}

# Which category each verification check name belongs to. Keep in sync with the
# check names emitted in verification.py. Unknown names contribute 0, so a new
# unregistered check can't silently swing the score.
_CATEGORY_BY_CHECK = {
    "code_references": "code_reference",
    "code_reference_ok": "code_reference",
    "file_not_found": "code_reference",
    "line_out_of_range": "code_reference",
    "symbol_never_found": "code_reference",
    "advisory_dedup": "advisory_dedup",
    "no_known_duplicate": "advisory_dedup",
    "possible_duplicate": "advisory_dedup",
    # Registered ahead of implementation (Phase 1, step 3). The CWE and reporter
    # checks must emit these exact names.
    "cwe_plausibility": "cwe_plausibility",
    "cwe_plausible": "cwe_plausibility",
    "cwe_implausible": "cwe_plausibility",
    "reporter_signal": "reporter_signal",
}

# Within a category, the dominant outcome. FAIL dominates (one fabricated
# reference taints the category); otherwise a confirmed PASS beats an
# INDETERMINATE "couldn't check".
_OUTCOME_RANK = {
    CheckOutcome.FAIL: 2,
    CheckOutcome.PASS: 1,
    CheckOutcome.INDETERMINATE: 0,
}


def decide(
    report: Report,
    static_checks: list[VerificationCheck],
    llm_assessment: LLMAssessment | None = None,
) -> TriageDecision:
    """Assemble the TriageDecision from the checks (and optional LLM verdict)."""
    score = _score(static_checks, llm_assessment)
    action = _action_for_score(score)
    return TriageDecision(
        report_id=report.id,
        confidence_score=score,
        suggested_action=action,
        static_checks=static_checks,
        llm_assessment=llm_assessment,
        draft_response=_draft_response(action, static_checks),
        processed_at=datetime.now(UTC),
    )


def _score(
    checks: list[VerificationCheck], llm_assessment: LLMAssessment | None
) -> int:
    """Transparent weighted sum of the evidence, clamped to [0, 100]."""
    score = BASELINE_SCORE
    for category, outcome in _aggregate_by_category(checks).items():
        weights = SCORE_WEIGHTS.get(category)
        if weights is None:
            continue
        if outcome == CheckOutcome.FAIL:
            score += weights["fail"]
        elif outcome == CheckOutcome.PASS:
            score += weights["pass"]
        # INDETERMINATE contributes nothing.
    if llm_assessment is not None:
        score += LLM_WEIGHTS.get(llm_assessment.verdict, 0)
    return max(0, min(100, score))


def _aggregate_by_category(
    checks: list[VerificationCheck],
) -> dict[str, CheckOutcome]:
    """Reduce each category's checks to its dominant outcome (FAIL > PASS > INDET)."""
    dominant: dict[str, CheckOutcome] = {}
    for check in checks:
        category = _CATEGORY_BY_CHECK.get(check.name)
        if category is None:
            continue
        current = dominant.get(category)
        if current is None or _OUTCOME_RANK[check.outcome] > _OUTCOME_RANK[current]:
            dominant[category] = check.outcome
    return dominant


def _action_for_score(score: int) -> str:
    """Map a score to a suggested action via the configurable ranges above."""
    if score >= THRESHOLD_FAST_TRACK:
        return "fast_track"
    if score >= THRESHOLD_STANDARD:
        return "standard_review"
    if score >= THRESHOLD_CLARIFICATION:
        return "request_clarification"
    return "likely_slop"


def _draft_response(action: str, checks: list[VerificationCheck]) -> str:
    """A short, neutral, editable starting reply. Never accusatory: a real
    reporter may be on the other end, and the maintainer edits before sending.
    """
    if action in ("likely_slop", "request_clarification"):
        failed = [c for c in checks if c.outcome == CheckOutcome.FAIL]
        lines = [
            "Thanks for the report. Before I can act on it, a few automated "
            "checks flagged things worth confirming:"
        ]
        lines += (
            [f"- {c.detail}" for c in failed]
            if failed
            else ["- I couldn't reproduce the issue from the details provided."]
        )
        lines.append(
            "Could you confirm the file paths, line numbers, and the exact "
            "affected version or commit? That will help me verify and prioritize."
        )
        return "\n".join(lines)
    if action == "standard_review":
        return (
            "Thanks for the report. I've queued it for review and will follow "
            "up if anything needs clarifying."
        )
    return (
        "Thanks for the report, this looks well-grounded. I'm prioritizing a "
        "review and will follow up shortly."
    )
