"""Tests for the internal schema. Verifies that the data model is well-formed."""

from datetime import UTC, datetime

import pytest
from pydantic import ValidationError

from slopguard.schema import (
    CodeReference,
    LLMAssessment,
    Report,
    ReporterInfo,
    Severity,
    TriageDecision,
)


def test_minimal_report_validates():
    """A report with only the required fields should validate."""
    report = Report(
        id="test-001",
        source="cli",
        title="Buffer overflow in parser",
        description="A buffer overflow occurs when the input exceeds 512 bytes.",
        received_at=datetime.now(UTC),
    )
    assert report.id == "test-001"
    assert report.code_references == []
    assert report.poc_present is False


def test_report_with_code_reference():
    """A report citing a specific code location should populate code_references."""
    report = Report(
        id="test-002",
        source="github",
        title="OOB read in JSON parser",
        description="Reading past the buffer in parse_json.",
        code_references=[
            CodeReference(
                file_path="src/parser.c",
                line_number=142,
                symbol="parse_json",
            )
        ],
        received_at=datetime.now(UTC),
    )
    assert len(report.code_references) == 1
    assert report.code_references[0].file_path == "src/parser.c"


def test_severity_accepts_standard_values():
    """Severity should map to standardized CVSS-like values."""
    assert Severity.HIGH.value == "high"
    assert Severity.CRITICAL.value == "critical"


def test_confidence_score_bounded():
    """TriageDecision confidence must be in [0, 100]."""
    with pytest.raises(ValidationError):
        TriageDecision(
            report_id="test",
            confidence_score=150,
            suggested_action="fast_track",
            static_checks=[],
            processed_at=datetime.now(UTC),
        )


def test_llm_assessment_verdict_constrained():
    """LLM verdict must be one of the three allowed values."""
    assessment = LLMAssessment(
        verdict="PLAUSIBLE",
        justification="The cited code does contain the described pattern.",
        cited_lines=[],
    )
    assert assessment.verdict == "PLAUSIBLE"

    with pytest.raises(ValidationError):
        LLMAssessment(
            verdict="MAYBE_PROBABLY",  # not in the allowed set
            justification="...",
            cited_lines=[],
        )


def test_reporter_info_defaults():
    """ReporterInfo should have sensible defaults for unknown reporters."""
    info = ReporterInfo()
    assert info.prior_credited_advisories == 0
    assert info.submission_velocity_30d == 0
    assert info.handle is None
