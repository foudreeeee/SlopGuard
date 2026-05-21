"""Run the benchmark through the pipeline and tally how it scores.

Honest about limits. Code-reference grounding and CWE plausibility need the
repo each report cites, which this script does not clone, so the run below
exercises the portable signals only: advisory dedup (against a small slice of
real, well-known advisories) and the reporter signal. Point it at the cited
repos to exercise the rest.

    python -m benchmark.evaluate
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from tempfile import TemporaryDirectory

from slopguard.advisories import Advisory
from slopguard.decision import decide
from slopguard.schema import CheckOutcome, Report
from slopguard.verification import verify_report

BENCHMARK = Path(__file__).resolve().parent

# A small slice of what `slopguard refresh` would cache: real, well-known
# advisories. Enough for dedup to catch a report that recycles a famous CVE.
EVAL_CORPUS = [
    Advisory(
        id="GHSA-jfh8-c2jp-5v3q",
        source="ghsa",
        title="Remote code execution in Log4j 2 (Log4Shell)",
        summary=(
            "Apache Log4j2 JNDI features used in configuration, log messages, "
            "and parameters do not protect against attacker-controlled LDAP "
            "and other JNDI endpoints, allowing remote code execution. "
            "CVE-2021-44228."
        ),
        aliases=["CVE-2021-44228"],
        cwe_ids=["CWE-502", "CWE-917"],
    ),
    Advisory(
        id="CVE-2014-0160",
        source="nvd",
        title="CVE-2014-0160 (Heartbleed)",
        summary=(
            "The TLS heartbeat extension in OpenSSL lets remote attackers read "
            "process memory via crafted packets (Heartbleed)."
        ),
        aliases=["CVE-2014-0160"],
        cwe_ids=["CWE-125"],
    ),
    Advisory(
        id="CVE-2021-3156",
        source="nvd",
        title="CVE-2021-3156 (Baron Samedit)",
        summary=(
            "Heap-based buffer overflow in sudo via sudoedit -s allows local "
            "privilege escalation to root."
        ),
        aliases=["CVE-2021-3156"],
        cwe_ids=["CWE-787"],
    ),
    Advisory(
        id="CVE-2014-6271",
        source="nvd",
        title="CVE-2014-6271 (Shellshock)",
        summary=(
            "GNU Bash processes trailing strings after function definitions in "
            "environment variables, allowing remote code execution via crafted "
            "values (Shellshock)."
        ),
        aliases=["CVE-2014-6271"],
        cwe_ids=["CWE-78"],
    ),
    Advisory(
        id="CVE-2016-5195",
        source="nvd",
        title="CVE-2016-5195 (Dirty COW)",
        summary=(
            "A race condition in the Linux kernel copy-on-write handling lets a "
            "local user gain write access to read-only memory and escalate "
            "privileges (Dirty COW)."
        ),
        aliases=["CVE-2016-5195"],
        cwe_ids=["CWE-362"],
    ),
    Advisory(
        id="CVE-2022-22965",
        source="nvd",
        title="CVE-2022-22965 (Spring4Shell)",
        summary=(
            "Spring Framework data binding on JDK 9+ allows remote code "
            "execution by manipulating class loader properties (Spring4Shell)."
        ),
        aliases=["CVE-2022-22965"],
        cwe_ids=["CWE-94"],
    ),
    Advisory(
        id="CVE-2017-0144",
        source="nvd",
        title="CVE-2017-0144 (EternalBlue)",
        summary=(
            "The Microsoft SMBv1 server mishandles crafted packets, allowing "
            "remote code execution (EternalBlue, used by WannaCry)."
        ),
        aliases=["CVE-2017-0144"],
        cwe_ids=["CWE-20"],
    ),
]

# Actions that mean the tool steered the maintainer away from normal handling.
FLAGGING_ACTIONS = ("likely_slop", "request_clarification")


@dataclass
class Row:
    id: str
    label: str
    score: int
    action: str
    fired: list[str] = field(default_factory=list)


def _flagged(action: str) -> bool:
    return action in FLAGGING_ACTIONS


def run() -> list[Row]:
    """Score every benchmark report with the portable signals (no repo)."""
    rows: list[Row] = []
    with TemporaryDirectory() as no_repo:
        for label in ("slop", "genuine"):
            for path in sorted((BENCHMARK / label).glob("*.json")):
                report = Report.model_validate_json(
                    path.read_text(encoding="utf-8")
                )
                checks = verify_report(report, no_repo, advisories=EVAL_CORPUS)
                decision = decide(report, checks)
                fired = [
                    c.name
                    for c in checks
                    if c.outcome != CheckOutcome.INDETERMINATE
                ]
                rows.append(
                    Row(
                        id=report.id,
                        label=label,
                        score=decision.confidence_score,
                        action=decision.suggested_action,
                        fired=fired,
                    )
                )
    return rows


def main() -> int:
    rows = run()
    print("SlopGuard benchmark evaluation")
    print(
        "(portable signals only: code-reference grounding and CWE plausibility\n"
        " need the cited repo and are not exercised here)\n"
    )
    print(f"{'id':<14}{'label':<9}{'score':<7}{'action':<22}fired")
    for r in rows:
        print(
            f"{r.id:<14}{r.label:<9}{r.score:<7}{r.action:<22}{', '.join(r.fired)}"
        )

    slop = [r for r in rows if r.label == "slop"]
    genuine = [r for r in rows if r.label == "genuine"]
    slop_flagged = [r for r in slop if _flagged(r.action)]
    genuine_flagged = [r for r in genuine if _flagged(r.action)]
    print("\nSummary")
    print(f"  slop flagged:          {len(slop_flagged)}/{len(slop)}")
    print(f"  genuine false-flagged: {len(genuine_flagged)}/{len(genuine)}")
    print(
        "  note: slop relying on a fabricated file path or an impossible CWE is\n"
        "        caught by code-reference grounding / CWE plausibility, which need\n"
        "        the cited repo. Run against the upstream to exercise those."
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
