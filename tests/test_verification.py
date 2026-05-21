"""Tests for the static verification layer.

These build a tiny throwaway git repository in a temp directory, stage
some real files, then check that SlopGuard's code reference grounding
correctly identifies which references are grounded and which are slop.
"""

from __future__ import annotations

import subprocess
from datetime import datetime, timezone
from pathlib import Path

import pytest

from slopguard.schema import CheckOutcome, CodeReference, Report
from slopguard.verification import _check_code_references


@pytest.fixture
def tiny_repo(tmp_path: Path) -> Path:
    """A minimal git repository with two known files."""
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "test@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "Test"],
        check=True,
    )

    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "parser.c").write_text(
        "int main(void) {\n"
        "    parse_json();\n"
        "    return 0;\n"
        "}\n"
    )
    (tmp_path / "README.md").write_text("# A real repo\n")

    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"],
        check=True,
    )
    return tmp_path


def _make_report(refs: list[CodeReference]) -> Report:
    return Report(
        id="test",
        source="cli",
        title="test",
        description="test",
        code_references=refs,
        received_at=datetime.now(timezone.utc),
    )


def test_existing_file_passes(tiny_repo: Path):
    """A reference to a real file at HEAD should pass."""
    report = _make_report([CodeReference(file_path="src/parser.c")])
    checks = _check_code_references(report, str(tiny_repo))
    assert len(checks) == 1
    assert checks[0].outcome == CheckOutcome.PASS


def test_missing_file_fails(tiny_repo: Path):
    """A reference to a fabricated file should fail loudly."""
    report = _make_report([CodeReference(file_path="lib/curl_sasl.c")])
    checks = _check_code_references(report, str(tiny_repo))
    assert len(checks) == 1
    assert checks[0].outcome == CheckOutcome.FAIL
    assert checks[0].name == "file_not_found"
    assert "lib/curl_sasl.c" in checks[0].detail


def test_line_in_range_passes(tiny_repo: Path):
    """Citing a line that exists should pass."""
    report = _make_report(
        [CodeReference(file_path="src/parser.c", line_number=2)]
    )
    checks = _check_code_references(report, str(tiny_repo))
    assert checks[0].outcome == CheckOutcome.PASS


def test_line_out_of_range_fails(tiny_repo: Path):
    """Citing line 471 of a 5-line file should fail."""
    report = _make_report(
        [CodeReference(file_path="src/parser.c", line_number=471)]
    )
    checks = _check_code_references(report, str(tiny_repo))
    assert checks[0].outcome == CheckOutcome.FAIL
    assert checks[0].name == "line_out_of_range"


def test_symbol_found_passes(tiny_repo: Path):
    """Citing a symbol that's in the file should pass."""
    report = _make_report(
        [CodeReference(file_path="src/parser.c", symbol="parse_json")]
    )
    checks = _check_code_references(report, str(tiny_repo))
    assert checks[0].outcome == CheckOutcome.PASS


def test_symbol_hallucinated_fails(tiny_repo: Path):
    """Citing a fabricated symbol should fail."""
    report = _make_report(
        [CodeReference(
            file_path="src/parser.c", symbol="totally_made_up_function"
        )]
    )
    checks = _check_code_references(report, str(tiny_repo))
    assert checks[0].outcome == CheckOutcome.FAIL
    assert checks[0].name == "symbol_never_found"


def test_multiple_references(tiny_repo: Path):
    """Multiple references in one report should each produce a check."""
    report = _make_report([
        CodeReference(file_path="src/parser.c"),
        CodeReference(file_path="src/nope.c"),  # doesn't exist
        CodeReference(file_path="README.md"),
    ])
    checks = _check_code_references(report, str(tiny_repo))
    assert len(checks) == 3
    assert checks[0].outcome == CheckOutcome.PASS
    assert checks[1].outcome == CheckOutcome.FAIL
    assert checks[2].outcome == CheckOutcome.PASS


def test_no_references_no_checks(tiny_repo: Path):
    """A report with no code references shouldn't produce any checks."""
    report = _make_report([])
    checks = _check_code_references(report, str(tiny_repo))
    assert checks == []


def test_not_a_git_repo(tmp_path: Path):
    """If the path isn't a git repo, we return INDETERMINATE not FAIL."""
    report = _make_report([CodeReference(file_path="anything")])
    checks = _check_code_references(report, str(tmp_path))
    assert len(checks) == 1
    assert checks[0].outcome == CheckOutcome.INDETERMINATE


def test_claimed_commit_that_doesnt_exist(tiny_repo: Path):
    """A report citing a commit hash we don't have → INDETERMINATE."""
    report = Report(
        id="test",
        source="cli",
        title="test",
        description="test",
        code_references=[CodeReference(file_path="src/parser.c")],
        claimed_commit="deadbeef" * 5,  # 40 hex chars, doesn't exist
        received_at=datetime.now(timezone.utc),
    )
    checks = _check_code_references(report, str(tiny_repo))
    assert len(checks) == 1
    assert checks[0].outcome == CheckOutcome.INDETERMINATE
