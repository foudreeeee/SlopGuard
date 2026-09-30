import pytest

from slopguard import symbols


def test_language_for_maps_known_extensions():
    assert symbols.language_for("a/b/c.py") == "python"
    assert symbols.language_for("x.tsx") == "tsx"
    assert symbols.language_for("notes.md") is None


def test_unknown_language_is_undecidable():
    # no supported language -> None, so the caller keeps its substring check
    assert symbols.symbol_is_code_identifier("foo bar", "notes.md", "foo") is None


def test_real_identifier_is_detected():
    pytest.importorskip("tree_sitter_language_pack")
    src = "def check_permission(role):\n    return role\n"
    result = symbols.symbol_is_code_identifier(src, "access.py", "check_permission")
    assert result is True


def test_comment_or_string_mention_is_not_an_identifier():
    pytest.importorskip("tree_sitter_language_pack")
    src = "# check_permission is only named in this comment\nx = 'check_permission'\n"
    result = symbols.symbol_is_code_identifier(src, "access.py", "check_permission")
    assert result is False
