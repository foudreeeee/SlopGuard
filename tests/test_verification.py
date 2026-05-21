"""Tests for the static verification layer.

These build a tiny throwaway git repository in a temp directory, stage
some real files, then check that SlopGuard's code reference grounding
correctly identifies which references are grounded and which are slop.
"""

from __future__ import annotations

import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest

from slopguard.advisories import Advisory
from slopguard.schema import CheckOutcome, CodeReference, Report
from slopguard.verification import (
    _advisory_ids,
    _char_ngrams,
    _check_advisory_dedup,
    _check_code_references,
    _code_terms,
    _dice,
    _TfidfIndex,
    _tokenize,
)


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
        received_at=datetime.now(UTC),
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
        received_at=datetime.now(UTC),
    )
    checks = _check_code_references(report, str(tiny_repo))
    assert len(checks) == 1
    assert checks[0].outcome == CheckOutcome.INDETERMINATE


# --- advisory dedup --------------------------------------------------------


@pytest.fixture
def fake_corpus() -> list[Advisory]:
    """A tiny stand-in for the GHSA/NVD cache: three unrelated advisories."""
    return [
        Advisory(
            id="GHSA-aaaa-bbbb-cccc",
            source="ghsa",
            title="Heap buffer overflow in curl SASL authentication",
            summary=(
                "A heap buffer overflow in lib/curl_sasl.c lets a malicious "
                "server overflow a buffer during the SASL authentication "
                "handshake parsing."
            ),
            aliases=["GHSA-aaaa-bbbb-cccc", "CVE-2024-11111"],
            cwe_ids=["CWE-122"],
        ),
        Advisory(
            id="CVE-2023-22222",
            source="nvd",
            title="CVE-2023-22222",
            summary=(
                "SQL injection in the Django ORM via crafted query parameters "
                "in the admin interface allows data extraction."
            ),
            aliases=["CVE-2023-22222"],
            cwe_ids=["CWE-89"],
        ),
        Advisory(
            id="GHSA-dddd-eeee-ffff",
            source="ghsa",
            title="Stored XSS in markdown rendering",
            summary=(
                "Stored cross-site scripting in the markdown renderer through "
                "unsanitized image alt text."
            ),
            aliases=["GHSA-dddd-eeee-ffff", "CVE-2022-33333"],
            cwe_ids=["CWE-79"],
        ),
    ]


def _dedup_report(title: str, description: str, **kwargs) -> Report:
    return Report(
        id="test",
        source="cli",
        title=title,
        description=description,
        received_at=datetime.now(UTC),
        **kwargs,
    )


def test_dedup_empty_corpus_is_indeterminate():
    """No cached advisories means we can't dedup, so don't fail the report."""
    report = _dedup_report("anything", "anything at all")
    checks = _check_advisory_dedup(report, [])
    assert len(checks) == 1
    assert checks[0].outcome == CheckOutcome.INDETERMINATE
    assert checks[0].name == "advisory_dedup"


def test_dedup_exact_cve_match_flags(fake_corpus: list[Advisory]):
    """Citing a CVE id already in the corpus is a near-certain duplicate."""
    report = _dedup_report(
        "Possible issue in query handling",
        "I believe this is the same as CVE-2023-22222 in the database layer.",
    )
    checks = _check_advisory_dedup(report, fake_corpus)
    assert checks[0].outcome == CheckOutcome.FAIL
    assert checks[0].name == "possible_duplicate"
    assert "CVE-2023-22222" in checks[0].detail


def test_dedup_near_duplicate_text_flags(fake_corpus: list[Advisory]):
    """Reworded copy of a known advisory (no shared id) flags on text similarity."""
    report = _dedup_report(
        "Heap buffer overflow in curl SASL authentication",
        "A heap buffer overflow in lib/curl_sasl.c allows a malicious server "
        "to overflow a buffer during the SASL authentication handshake parsing.",
    )
    checks = _check_advisory_dedup(report, fake_corpus)
    assert checks[0].outcome == CheckOutcome.FAIL
    assert checks[0].name == "possible_duplicate"
    assert "GHSA-aaaa-bbbb-cccc" in checks[0].detail


def test_dedup_novel_report_passes(fake_corpus: list[Advisory]):
    """A report unrelated to anything in the corpus should pass cleanly."""
    report = _dedup_report(
        "Timing side channel in password comparison",
        "The login endpoint compares password hashes with a non-constant-time "
        "string comparison, leaking timing information to an attacker.",
    )
    checks = _check_advisory_dedup(report, fake_corpus)
    assert checks[0].outcome == CheckOutcome.PASS
    assert checks[0].name == "no_known_duplicate"


def test_dedup_threshold_is_respected(fake_corpus: list[Advisory]):
    """A high threshold suppresses a text-only near-dup but not an exact-id dup."""
    near_dup = _dedup_report(
        "Heap buffer overflow in curl SASL authentication",
        "A heap buffer overflow in lib/curl_sasl.c allows a malicious server "
        "to overflow a buffer during the SASL authentication handshake parsing.",
    )
    relaxed = _check_advisory_dedup(near_dup, fake_corpus)
    assert relaxed[0].outcome == CheckOutcome.FAIL

    strict = _check_advisory_dedup(near_dup, fake_corpus, threshold=0.99)
    assert strict[0].outcome == CheckOutcome.PASS

    # An exact CVE match scores 1.0, so it survives even the strict threshold.
    exact = _dedup_report("x", "duplicate of CVE-2023-22222")
    assert _check_advisory_dedup(exact, fake_corpus, threshold=0.99)[0].outcome == (
        CheckOutcome.FAIL
    )


# --- text matching primitives ----------------------------------------------


def test_tokenize_drops_stopwords_and_singletons():
    tokens = _tokenize("The parser has a Buffer OVERFLOW in X")
    assert "the" not in tokens
    assert "a" not in tokens
    assert "x" not in tokens  # single char dropped
    assert "buffer" in tokens
    assert "overflow" in tokens


def test_advisory_ids_extracts_identifiers():
    ids = _advisory_ids("see cve-2024-1234 and CWE-79 and GHSA-aaaa-bbbb-cccc")
    assert ids == {"CVE-2024-1234", "CWE-79", "GHSA-AAAA-BBBB-CCCC"}


def test_code_terms_extracts_function_shapes():
    terms = _code_terms(
        "the call parse_json() in os.path with camelCase helper"
    )
    assert "parse_json" in terms
    assert "os.path" in terms
    assert "camelcase" in terms


def test_dice_overlap():
    assert _dice(set(), {"a"}) == 0.0
    assert _dice({"ab", "bc"}, {"ab", "bc"}) == 1.0
    assert 0.0 < _dice({"ab", "bc"}, {"ab", "xy"}) < 1.0


def test_char_ngrams_short_string():
    assert _char_ngrams("ab", n=4) == {"ab"}
    assert _char_ngrams("", n=4) == set()


def test_tfidf_identical_text_is_most_similar():
    index = _TfidfIndex(
        [
            "heap buffer overflow in the sasl handshake parser",
            "sql injection in the database query builder",
        ]
    )
    sims = index.similarities("heap buffer overflow in the sasl handshake parser")
    assert sims[0] > sims[1]
    assert sims[0] == pytest.approx(1.0, abs=1e-9)


def test_tfidf_unrelated_text_scores_zero():
    index = _TfidfIndex(["buffer overflow in parser"])
    assert index.similarities("completely different unrelated wording")[0] == 0.0
