"""Tests for the decision layer.

The scoring is a transparent weighted sum, so these tests pin down exact
scores, not just ordering. They also lock in the two rules that matter:
failures outweigh passes, and a soft signal can never decide on its own.
"""

from __future__ import annotations

from datetime import UTC, datetime

import pytest

from slopguard.decision import _action_for_score, decide
from slopguard.schema import (
    CheckOutcome,
    LLMAssessment,
    Report,
    VerificationCheck,
)


def _chk(name: str, outcome: CheckOutcome) -> VerificationCheck:
    return VerificationCheck(name=name, outcome=outcome, detail=f"{name} detail")


def _report() -> Report:
    return Report(
        id="r1",
        source="cli",
        title="t",
        description="d",
        received_at=datetime.now(UTC),
    )


def _decide(checks, llm=None):
    return decide(_report(), checks, llm)


def test_all_static_pass_is_standard_review():
    d = _decide(
        [
            _chk("code_reference_ok", CheckOutcome.PASS),
            _chk("no_known_duplicate", CheckOutcome.PASS),
        ]
    )
    assert d.confidence_score == 70  # 50 + 12 + 8
    assert d.suggested_action == "standard_review"


def test_fabricated_reference_is_likely_slop():
    d = _decide([_chk("file_not_found", CheckOutcome.FAIL)])
    assert d.confidence_score == 15  # 50 - 35
    assert d.suggested_action == "likely_slop"


def test_duplicate_alone_requests_clarification():
    d = _decide([_chk("possible_duplicate", CheckOutcome.FAIL)])
    assert d.confidence_score == 25  # 50 - 25
    assert d.suggested_action == "request_clarification"


def test_soft_signal_never_decides_alone():
    """A bad reporter signal on its own must not sink the report."""
    d = _decide([_chk("reporter_signal", CheckOutcome.FAIL)])
    assert d.confidence_score == 42  # 50 - 8
    assert d.suggested_action == "standard_review"
    assert d.suggested_action not in ("likely_slop", "request_clarification")


def test_everything_failing_floors_to_likely_slop():
    d = _decide(
        [
            _chk("file_not_found", CheckOutcome.FAIL),
            _chk("possible_duplicate", CheckOutcome.FAIL),
            _chk("cwe_implausible", CheckOutcome.FAIL),
            _chk("reporter_signal", CheckOutcome.FAIL),
        ]
    )
    assert d.confidence_score == 0  # clamped from 50 - 88
    assert d.suggested_action == "likely_slop"


def test_indeterminate_is_neutral():
    d = _decide(
        [
            _chk("code_references", CheckOutcome.INDETERMINATE),
            _chk("advisory_dedup", CheckOutcome.INDETERMINATE),
        ]
    )
    assert d.confidence_score == 50
    assert d.suggested_action == "standard_review"


def test_code_reference_fail_dominates_pass_in_same_category():
    """One fabricated reference taints the category even if others are real."""
    d = _decide(
        [
            _chk("code_reference_ok", CheckOutcome.PASS),
            _chk("file_not_found", CheckOutcome.FAIL),
        ]
    )
    assert d.confidence_score == 15  # category resolves to FAIL: 50 - 35


def test_llm_plausible_promotes_to_fast_track():
    llm = LLMAssessment(verdict="PLAUSIBLE", justification="grounded", cited_lines=[])
    d = _decide(
        [
            _chk("code_reference_ok", CheckOutcome.PASS),
            _chk("no_known_duplicate", CheckOutcome.PASS),
        ],
        llm,
    )
    assert d.confidence_score == 90  # 70 + 20
    assert d.suggested_action == "fast_track"


def test_llm_implausible_lowers_score():
    llm = LLMAssessment(verdict="IMPLAUSIBLE", justification="no", cited_lines=[])
    d = _decide(
        [
            _chk("code_reference_ok", CheckOutcome.PASS),
            _chk("no_known_duplicate", CheckOutcome.PASS),
        ],
        llm,
    )
    assert d.confidence_score == 40  # 70 - 30
    assert d.suggested_action == "standard_review"


def test_unknown_check_is_ignored():
    """An unregistered check name must not move the score."""
    d = _decide([_chk("some_future_check", CheckOutcome.FAIL)])
    assert d.confidence_score == 50


@pytest.mark.parametrize(
    "score,action",
    [
        (100, "fast_track"),
        (80, "fast_track"),
        (79, "standard_review"),
        (40, "standard_review"),
        (39, "request_clarification"),
        (20, "request_clarification"),
        (19, "likely_slop"),
        (0, "likely_slop"),
    ],
)
def test_action_threshold_boundaries(score: int, action: str):
    assert _action_for_score(score) == action


def test_decide_returns_well_formed_triage_decision():
    checks = [_chk("code_reference_ok", CheckOutcome.PASS)]
    d = _decide(checks)
    assert d.report_id == "r1"
    assert 0 <= d.confidence_score <= 100
    assert d.static_checks == checks
    assert d.llm_assessment is None
    assert d.draft_response
    assert d.processed_at is not None


def test_draft_mentions_failed_check_for_slop():
    d = _decide([_chk("file_not_found", CheckOutcome.FAIL)])
    assert "file_not_found detail" in d.draft_response
