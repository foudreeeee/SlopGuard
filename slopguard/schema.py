"""
Internal data schema for SlopGuard.

All adapters (GitHub, GitLab, email, CLI) normalize incoming reports into
the `Report` type defined here. The verification and assessment layers
operate exclusively on this normalized form.
"""

from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Literal, Optional

from pydantic import BaseModel, Field


class Severity(str, Enum):
    """Standardized severity levels. Matches CVSS qualitative ratings."""

    NONE = "none"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class CodeReference(BaseModel):
    """A specific code location cited in the report.

    Used by the static verification layer to check whether the cited code
    actually exists in the repository at the claimed commit.
    """

    file_path: str = Field(..., description="Path relative to repo root.")
    line_number: Optional[int] = Field(
        None, description="1-indexed line number, if specified."
    )
    symbol: Optional[str] = Field(
        None,
        description="Function, class, or other named symbol, if specified.",
    )


class ReporterInfo(BaseModel):
    """Metadata about the reporter, used as a signal but never decisive."""

    handle: Optional[str] = None
    account_age_days: Optional[int] = None
    prior_credited_advisories: int = 0
    submission_velocity_30d: int = Field(
        0,
        description="Number of vulnerability reports this account has filed "
        "across all projects in the last 30 days.",
    )


class Report(BaseModel):
    """A normalized vulnerability report ready for triage."""

    id: str = Field(..., description="Stable identifier for this report.")
    source: Literal["github", "gitlab", "email", "cli"]
    title: str
    description: str
    claimed_affected_versions: Optional[list[str]] = None
    claimed_severity: Optional[Severity] = None
    claimed_cwe: Optional[list[str]] = Field(
        None,
        description="CWE identifiers as cited by the reporter, e.g., 'CWE-79'.",
    )
    code_references: list[CodeReference] = Field(default_factory=list)
    poc_present: bool = False
    poc_text: Optional[str] = None
    reporter: ReporterInfo = Field(default_factory=ReporterInfo)
    received_at: datetime
    claimed_commit: Optional[str] = Field(
        None,
        description="Git commit hash the report claims to refer to, if any.",
    )


class CheckOutcome(str, Enum):
    """Outcome of an individual static verification check."""

    PASS = "pass"
    FAIL = "fail"
    INDETERMINATE = "indeterminate"


class VerificationCheck(BaseModel):
    """Result of a single check in the static verification layer."""

    name: str
    outcome: CheckOutcome
    detail: str = Field(
        ...,
        description="Human-readable explanation, displayed in the evidence panel.",
    )


class LLMAssessment(BaseModel):
    """Output of the LLM claim assessment layer.

    Enforced via Pydantic schema. Any LLM output that fails to parse into
    this shape is treated as a soft-rejection signal.
    """

    verdict: Literal["PLAUSIBLE", "IMPLAUSIBLE", "UNDETERMINED"]
    justification: str = Field(..., max_length=2000)
    cited_lines: list[CitedLine] = Field(default_factory=list)


class CitedLine(BaseModel):
    """A line of code the LLM cited in its justification.

    The verification layer checks that cited lines exist in the context
    that was provided to the LLM. Hallucinated citations (lines not in
    context) trigger an automatic verdict override to UNDETERMINED.
    """

    file: str
    line: int
    relevance: str


class TriageDecision(BaseModel):
    """The complete output of SlopGuard for one report.

    This is what the maintainer sees in the internal triage view.
    """

    report_id: str
    confidence_score: int = Field(..., ge=0, le=100)
    suggested_action: Literal[
        "fast_track",
        "standard_review",
        "request_clarification",
        "likely_slop",
    ]
    static_checks: list[VerificationCheck]
    llm_assessment: Optional[LLMAssessment] = None
    draft_response: Optional[str] = Field(
        None,
        description="Maintainer-editable draft response to the reporter.",
    )
    processed_at: datetime


# Required for forward references
CitedLine.model_rebuild()
LLMAssessment.model_rebuild()
