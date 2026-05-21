"""Tests for advisory ingestion and the local cache.

No network here. Response parsing is tested against static sample payloads
shaped like the real NVD JSON 2.0 and GHSA GraphQL responses; the fetch loops
are tested with the HTTP layer monkeypatched out.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

import pytest

from slopguard import advisories
from slopguard.advisories import (
    Advisory,
    cache_fetched_at,
    default_cache_path,
    fetch_ghsa,
    fetch_nvd,
    is_stale,
    load_advisories,
    parse_ghsa_response,
    parse_nvd_response,
    save_advisories,
)

# --- parsing ---------------------------------------------------------------


def test_parse_nvd_response():
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "descriptions": [
                        {"lang": "es", "value": "ignorado"},
                        {"lang": "en", "value": "A flaw in the JSON parser."},
                    ],
                    "weaknesses": [
                        {"description": [{"lang": "en", "value": "CWE-787"}]}
                    ],
                }
            },
            {"cve": {}},  # no id, must be skipped
        ]
    }
    out = parse_nvd_response(payload)
    assert len(out) == 1
    adv = out[0]
    assert adv.id == "CVE-2024-0001"
    assert adv.source == "nvd"
    assert adv.title == "CVE-2024-0001"
    assert adv.summary == "A flaw in the JSON parser."
    assert adv.aliases == ["CVE-2024-0001"]
    assert adv.cwe_ids == ["CWE-787"]


def test_parse_ghsa_response():
    payload = {
        "data": {
            "securityAdvisories": {
                "nodes": [
                    {
                        "ghsaId": "GHSA-xxxx-yyyy-zzzz",
                        "summary": "Stored XSS in markdown renderer",
                        "description": "Longer description of the issue.",
                        "identifiers": [
                            {"type": "GHSA", "value": "GHSA-xxxx-yyyy-zzzz"},
                            {"type": "CVE", "value": "CVE-2024-9999"},
                        ],
                        "cwes": {"nodes": [{"cweId": "CWE-79"}]},
                    },
                    {"summary": "no id, skipped"},
                ]
            }
        }
    }
    out = parse_ghsa_response(payload)
    assert len(out) == 1
    adv = out[0]
    assert adv.id == "GHSA-xxxx-yyyy-zzzz"
    assert adv.source == "ghsa"
    assert adv.title == "Stored XSS in markdown renderer"
    assert adv.summary == "Longer description of the issue."
    assert "CVE-2024-9999" in adv.aliases
    assert adv.cwe_ids == ["CWE-79"]


def test_parse_ghsa_falls_back_to_id_when_no_summary():
    payload = {
        "data": {
            "securityAdvisories": {
                "nodes": [{"ghsaId": "GHSA-aaaa-bbbb-cccc"}]
            }
        }
    }
    out = parse_ghsa_response(payload)
    assert out[0].title == "GHSA-aaaa-bbbb-cccc"
    assert out[0].summary == "GHSA-aaaa-bbbb-cccc"


# --- cache -----------------------------------------------------------------


def test_cache_roundtrip(tmp_path: Path):
    path = tmp_path / "advisories.json"
    original = [
        Advisory(id="CVE-2024-0001", source="nvd", title="CVE-2024-0001", summary="x"),
        Advisory(
            id="GHSA-a-b-c", source="ghsa", title="t", summary="y", aliases=["CVE-1"]
        ),
    ]
    save_advisories(original, path)
    loaded = load_advisories(path)
    assert loaded == original


def test_load_missing_cache_returns_empty(tmp_path: Path):
    assert load_advisories(tmp_path / "nope.json") == []


def test_load_corrupt_cache_returns_empty(tmp_path: Path):
    path = tmp_path / "advisories.json"
    path.write_text("{not valid json", encoding="utf-8")
    assert load_advisories(path) == []


def test_load_skips_malformed_records(tmp_path: Path):
    path = tmp_path / "advisories.json"
    path.write_text(
        '{"advisories": [{"id": "CVE-1", "source": "nvd", "title": "ok"}, '
        '{"id": "CVE-2"}]}',  # second record missing required fields
        encoding="utf-8",
    )
    loaded = load_advisories(path)
    assert len(loaded) == 1
    assert loaded[0].id == "CVE-1"


def test_cache_fetched_at_none_when_missing(tmp_path: Path):
    assert cache_fetched_at(tmp_path / "nope.json") is None


def test_staleness(tmp_path: Path):
    path = tmp_path / "advisories.json"
    assert is_stale(path) is True  # missing cache is stale

    save_advisories([], path, fetched_at=datetime.now(UTC))
    assert is_stale(path, max_age_days=7) is False

    old = datetime.now(UTC) - timedelta(days=10)
    save_advisories([], path, fetched_at=old)
    assert is_stale(path, max_age_days=7) is True


def test_default_cache_path_respects_env(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
):
    monkeypatch.setenv("SLOPGUARD_CACHE_DIR", str(tmp_path))
    assert default_cache_path() == tmp_path / "advisories.json"


def test_default_cache_path_uses_xdg(tmp_path: Path, monkeypatch: pytest.MonkeyPatch):
    monkeypatch.delenv("SLOPGUARD_CACHE_DIR", raising=False)
    monkeypatch.setenv("XDG_CACHE_HOME", str(tmp_path))
    assert default_cache_path() == tmp_path / "slopguard" / "advisories.json"


# --- fetch loops (HTTP monkeypatched out) ----------------------------------


def test_fetch_ghsa_requires_token():
    with pytest.raises(ValueError):
        fetch_ghsa("")


def test_fetch_nvd_paginates(monkeypatch: pytest.MonkeyPatch):
    pages = {
        0: {
            "vulnerabilities": [
                {"cve": {"id": "CVE-1", "descriptions": []}},
                {"cve": {"id": "CVE-2", "descriptions": []}},
            ],
            "totalResults": 3,
        },
        2: {
            "vulnerabilities": [{"cve": {"id": "CVE-3", "descriptions": []}}],
            "totalResults": 3,
        },
    }

    def fake_get(url: str, headers: dict, timeout: float = 30.0) -> dict:
        start = int(url.split("startIndex=")[1])
        return pages[start]

    monkeypatch.setattr(advisories, "_get_json", fake_get)
    monkeypatch.setattr(advisories, "_NVD_PAGE_SIZE", 2)
    monkeypatch.setattr(advisories.time, "sleep", lambda *_: None)

    out = fetch_nvd(max_results=10)
    assert [a.id for a in out] == ["CVE-1", "CVE-2", "CVE-3"]


def test_fetch_nvd_respects_max_results(monkeypatch: pytest.MonkeyPatch):
    page = {
        "vulnerabilities": [
            {"cve": {"id": "CVE-1", "descriptions": []}},
            {"cve": {"id": "CVE-2", "descriptions": []}},
        ],
        "totalResults": 100,
    }
    monkeypatch.setattr(advisories, "_get_json", lambda *a, **k: page)
    monkeypatch.setattr(advisories, "_NVD_PAGE_SIZE", 2)
    monkeypatch.setattr(advisories.time, "sleep", lambda *_: None)

    out = fetch_nvd(max_results=2)
    assert len(out) == 2


def test_fetch_ghsa_paginates(monkeypatch: pytest.MonkeyPatch):
    pages = [
        {
            "data": {
                "securityAdvisories": {
                    "nodes": [{"ghsaId": "GHSA-1"}],
                    "pageInfo": {"hasNextPage": True, "endCursor": "c1"},
                }
            }
        },
        {
            "data": {
                "securityAdvisories": {
                    "nodes": [{"ghsaId": "GHSA-2"}],
                    "pageInfo": {"hasNextPage": False, "endCursor": None},
                }
            }
        },
    ]
    cursors: list = []

    def fake_post(url: str, body: dict, headers: dict, timeout: float = 30.0) -> dict:
        cursors.append(body["variables"]["cursor"])
        return pages[len(cursors) - 1]

    monkeypatch.setattr(advisories, "_post_json", fake_post)

    out = fetch_ghsa("token", max_results=10)
    assert [a.id for a in out] == ["GHSA-1", "GHSA-2"]
    assert cursors == [None, "c1"]
