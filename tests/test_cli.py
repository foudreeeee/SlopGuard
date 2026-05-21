"""Tests for the CLI.

A real tiny git repo is built so the code-reference grounding has something to
resolve against. The advisory cache is pointed at an empty temp dir so dedup is
deterministically INDETERMINATE and never touches the developer's real cache.
"""

from __future__ import annotations

import io
import json
import subprocess
from pathlib import Path

import pytest

from slopguard import advisories
from slopguard.cli import main

VALID_ACTIONS = {
    "fast_track",
    "standard_review",
    "request_clarification",
    "likely_slop",
}


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    subprocess.run(["git", "init", "-q", str(tmp_path)], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.email", "t@example.com"],
        check=True,
    )
    subprocess.run(
        ["git", "-C", str(tmp_path), "config", "user.name", "T"], check=True
    )
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "app.py").write_text("def handler():\n    return 1\n")
    subprocess.run(["git", "-C", str(tmp_path), "add", "-A"], check=True)
    subprocess.run(
        ["git", "-C", str(tmp_path), "commit", "-q", "-m", "init"], check=True
    )
    return tmp_path


@pytest.fixture(autouse=True)
def empty_cache(tmp_path_factory, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.setenv(
        "SLOPGUARD_CACHE_DIR", str(tmp_path_factory.mktemp("cache"))
    )


def _report_json(**overrides) -> str:
    base = {
        "id": "cli-1",
        "source": "cli",
        "title": "t",
        "description": "d",
        "received_at": "2026-05-01T00:00:00Z",
        "code_references": [{"file_path": "src/app.py", "symbol": "handler"}],
    }
    base.update(overrides)
    return json.dumps(base)


def test_triage_file_json_output(repo: Path, tmp_path: Path, capsys):
    rf = tmp_path / "r.json"
    rf.write_text(_report_json())
    code = main(["triage", "--repo", str(repo), "--file", str(rf)])
    assert code == 0
    out = json.loads(capsys.readouterr().out)
    assert out["report_id"] == "cli-1"
    assert 0 <= out["confidence_score"] <= 100
    assert out["suggested_action"] in VALID_ACTIONS
    assert isinstance(out["static_checks"], list)


def test_triage_reads_stdin(repo: Path, monkeypatch: pytest.MonkeyPatch, capsys):
    monkeypatch.setattr("sys.stdin", io.StringIO(_report_json()))
    code = main(["triage", "--repo", str(repo)])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["report_id"] == "cli-1"


def test_triage_text_output(repo: Path, tmp_path: Path, capsys):
    rf = tmp_path / "r.json"
    rf.write_text(_report_json())
    code = main(["triage", "--repo", str(repo), "--file", str(rf), "--text"])
    assert code == 0
    out = capsys.readouterr().out
    assert "SlopGuard triage" in out
    assert "Confidence:" in out
    assert "Draft response" in out


def test_triage_fabricated_file_is_likely_slop(repo: Path, tmp_path: Path, capsys):
    rf = tmp_path / "r.json"
    rf.write_text(_report_json(code_references=[{"file_path": "lib/ghost.c"}]))
    code = main(["triage", "--repo", str(repo), "--file", str(rf)])
    assert code == 0
    assert json.loads(capsys.readouterr().out)["suggested_action"] == "likely_slop"


def test_triage_bad_json_errors(repo: Path, tmp_path: Path, capsys):
    rf = tmp_path / "r.json"
    rf.write_text("{not valid json")
    code = main(["triage", "--repo", str(repo), "--file", str(rf)])
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_triage_missing_repo_errors(tmp_path: Path, capsys):
    rf = tmp_path / "r.json"
    rf.write_text(_report_json())
    code = main(["triage", "--repo", str(tmp_path / "nope"), "--file", str(rf)])
    assert code == 2
    assert "error" in capsys.readouterr().err.lower()


def test_refresh_invokes_refresh_cache(monkeypatch: pytest.MonkeyPatch, capsys):
    captured = {}

    def fake_refresh(**kwargs):
        captured.update(kwargs)
        return [object(), object()]

    monkeypatch.setattr(advisories, "refresh_cache", fake_refresh)
    code = main(["refresh", "--nvd-max", "10", "--ghsa-max", "5"])
    assert code == 0
    assert captured == {"nvd_max": 10, "ghsa_max": 5}
    assert "2 advisories" in capsys.readouterr().out


def test_no_subcommand_errors():
    with pytest.raises(SystemExit):
        main([])
