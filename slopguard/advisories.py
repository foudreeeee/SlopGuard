"""GHSA + NVD advisory ingestion and local cache.

The dedup check (`verification._check_advisory_dedup`) matches incoming
reports against a corpus of known advisories. That corpus comes from two
public sources:

  - GHSA, the GitHub Advisory Database, via the GraphQL API (needs a token).
  - NVD, the NIST CVE feed, via the public JSON 2.0 API (no token, but
    rate-limited).

Both get normalized into `Advisory` and cached on disk. Refresh weekly.

Network code uses only the standard library (urllib) on purpose: one fewer
dependency for maintainers to vet. The HTTP wrappers are thin and the
response parsing is split out (`parse_nvd_response`, `parse_ghsa_response`)
so it can be tested without a network.
"""

from __future__ import annotations

import json
import os
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field, ValidationError

NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GHSA_GRAPHQL_URL = "https://api.github.com/graphql"

# NVD allows up to 2000 results per page. Without an API key you get roughly
# 5 requests per 30s, so we pause between pages to stay under the limit.
_NVD_PAGE_SIZE = 2000
_NVD_PAUSE_SECONDS = 6.0

_GHSA_PAGE_SIZE = 100
_GHSA_QUERY = """
query($cursor: String) {
  securityAdvisories(first: 100, after: $cursor, classifications: [GENERAL, MALWARE]) {
    pageInfo { hasNextPage endCursor }
    nodes {
      ghsaId
      summary
      description
      identifiers { type value }
      cwes(first: 10) { nodes { cweId } }
    }
  }
}
"""


class Advisory(BaseModel):
    """A known advisory pulled from GHSA or NVD, normalized for matching."""

    id: str = Field(..., description="GHSA or CVE id (e.g. CVE-2024-1234).")
    source: Literal["ghsa", "nvd"]
    title: str = Field(..., description="Short summary line.")
    summary: str = Field("", description="Longer description text.")
    aliases: list[str] = Field(
        default_factory=list,
        description="Cross-referenced ids (CVE/GHSA) for this same advisory.",
    )
    cwe_ids: list[str] = Field(
        default_factory=list, description="Associated CWE identifiers, e.g. 'CWE-79'."
    )


# --- local cache -----------------------------------------------------------


def default_cache_path() -> Path:
    """Where the advisory cache lives.

    Honors SLOPGUARD_CACHE_DIR, then XDG_CACHE_HOME, then ~/.cache.
    """
    override = os.environ.get("SLOPGUARD_CACHE_DIR")
    if override:
        base = Path(override)
    else:
        xdg = os.environ.get("XDG_CACHE_HOME")
        base = (Path(xdg) if xdg else Path.home() / ".cache") / "slopguard"
    return base / "advisories.json"


def load_advisories(path: str | Path | None = None) -> list[Advisory]:
    """Read cached advisories. Returns [] if the cache is missing or unreadable.

    Forgiving on purpose: a broken cache should degrade dedup to
    INDETERMINATE, not crash the whole triage run.
    """
    p = Path(path) if path is not None else default_cache_path()
    if not p.is_file():
        return []
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return []
    raw = data.get("advisories", []) if isinstance(data, dict) else []
    out: list[Advisory] = []
    for item in raw:
        try:
            out.append(Advisory.model_validate(item))
        except ValidationError:
            continue
    return out


def save_advisories(
    advisories: list[Advisory],
    path: str | Path | None = None,
    fetched_at: datetime | None = None,
) -> Path:
    """Write advisories to the cache atomically. Returns the path written."""
    p = Path(path) if path is not None else default_cache_path()
    p.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "fetched_at": (fetched_at or datetime.now(UTC)).isoformat(),
        "advisories": [a.model_dump() for a in advisories],
    }
    tmp = p.with_name(p.name + ".tmp")
    tmp.write_text(json.dumps(payload), encoding="utf-8")
    tmp.replace(p)
    return p


def cache_fetched_at(path: str | Path | None = None) -> datetime | None:
    """When the cache was last written, or None if there's no readable cache."""
    p = Path(path) if path is not None else default_cache_path()
    if not p.is_file():
        return None
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return datetime.fromisoformat(data["fetched_at"])
    except (OSError, json.JSONDecodeError, KeyError, ValueError):
        return None


def is_stale(path: str | Path | None = None, max_age_days: int = 7) -> bool:
    """True if the cache is missing or older than max_age_days (default weekly)."""
    fetched = cache_fetched_at(path)
    if fetched is None:
        return True
    if fetched.tzinfo is None:
        fetched = fetched.replace(tzinfo=UTC)
    return datetime.now(UTC) - fetched > timedelta(days=max_age_days)


# --- response parsing (no network; unit-tested directly) -------------------


def parse_nvd_response(payload: dict[str, Any]) -> list[Advisory]:
    """Turn one page of the NVD JSON 2.0 response into Advisory records."""
    out: list[Advisory] = []
    for item in payload.get("vulnerabilities", []):
        cve = item.get("cve", {})
        cve_id = cve.get("id")
        if not cve_id:
            continue
        description = ""
        for d in cve.get("descriptions", []):
            if d.get("lang") == "en":
                description = d.get("value", "")
                break
        cwes: list[str] = []
        for weakness in cve.get("weaknesses", []):
            for d in weakness.get("description", []):
                value = d.get("value", "")
                if value.startswith("CWE-"):
                    cwes.append(value)
        out.append(
            Advisory(
                id=cve_id,
                source="nvd",
                title=cve_id,  # NVD entries have no title; the id is the handle.
                summary=description,
                aliases=[cve_id],
                cwe_ids=sorted(set(cwes)),
            )
        )
    return out


def parse_ghsa_response(payload: dict[str, Any]) -> list[Advisory]:
    """Turn one page of the GHSA GraphQL response into Advisory records."""
    nodes = (
        payload.get("data", {})
        .get("securityAdvisories", {})
        .get("nodes", [])
    )
    out: list[Advisory] = []
    for node in nodes:
        ghsa_id = node.get("ghsaId")
        if not ghsa_id:
            continue
        title = node.get("summary") or ghsa_id
        aliases = [
            ident["value"]
            for ident in node.get("identifiers", [])
            if ident.get("value")
        ]
        cwes = [
            c["cweId"]
            for c in node.get("cwes", {}).get("nodes", [])
            if c.get("cweId")
        ]
        out.append(
            Advisory(
                id=ghsa_id,
                source="ghsa",
                title=title,
                summary=node.get("description") or title,
                aliases=aliases,
                cwe_ids=cwes,
            )
        )
    return out


# --- network fetch ---------------------------------------------------------


def _get_json(
    url: str, headers: dict[str, str], timeout: float = 30.0
) -> dict[str, Any]:
    req = urllib.request.Request(url, headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read().decode("utf-8"))


def _post_json(
    url: str, body: dict[str, Any], headers: dict[str, str], timeout: float = 30.0
) -> dict[str, Any]:
    data = json.dumps(body).encode("utf-8")
    req = urllib.request.Request(url, data=data, headers=headers, method="POST")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310 (https only)
        return json.loads(resp.read().decode("utf-8"))


def fetch_nvd(api_key: str | None = None, max_results: int = 2000) -> list[Advisory]:
    """Fetch recent CVEs from NVD's public JSON 2.0 API, newest first.

    `max_results` caps how much we pull. A full NVD mirror is ~250k CVEs;
    pulling all of it through this paginated API is slow and rate-limited, so
    a real deployment should seed from the NVD bulk feeds instead.
    TODO Phase 1: bulk-feed seeding + incremental lastModStartDate refresh.
    """
    headers = {"User-Agent": "slopguard"}
    if api_key:
        headers["apiKey"] = api_key
    out: list[Advisory] = []
    start = 0
    while len(out) < max_results:
        url = f"{NVD_API_URL}?resultsPerPage={_NVD_PAGE_SIZE}&startIndex={start}"
        payload = _get_json(url, headers)
        batch = parse_nvd_response(payload)
        if not batch:
            break
        out.extend(batch)
        start += _NVD_PAGE_SIZE
        if start >= payload.get("totalResults", 0):
            break
        time.sleep(_NVD_PAUSE_SECONDS)
    return out[:max_results]


def fetch_ghsa(token: str, max_results: int = 2000) -> list[Advisory]:
    """Fetch advisories from the GitHub Advisory Database via GraphQL.

    Needs a GitHub token (any classic/fine-grained token with default scope
    works; the advisory database is public). Raises ValueError without one.
    """
    if not token:
        raise ValueError("GHSA fetch needs a GitHub token (set GITHUB_TOKEN).")
    headers = {
        "Authorization": f"bearer {token}",
        "Content-Type": "application/json",
        "User-Agent": "slopguard",
    }
    out: list[Advisory] = []
    cursor: str | None = None
    while len(out) < max_results:
        body = {"query": _GHSA_QUERY, "variables": {"cursor": cursor}}
        payload = _post_json(GHSA_GRAPHQL_URL, body, headers)
        out.extend(parse_ghsa_response(payload))
        page = (
            payload.get("data", {})
            .get("securityAdvisories", {})
            .get("pageInfo", {})
        )
        if not page.get("hasNextPage"):
            break
        cursor = page.get("endCursor")
    return out[:max_results]


def refresh_cache(
    path: str | Path | None = None,
    github_token: str | None = None,
    nvd_api_key: str | None = None,
    nvd_max: int = 2000,
    ghsa_max: int = 2000,
) -> list[Advisory]:
    """Pull GHSA (if a token is available) + NVD and write the cache.

    GHSA is skipped, not fatal, when no token is configured. Returns the
    combined advisory list that was written.
    """
    advisories: list[Advisory] = []
    token = github_token or os.environ.get("GITHUB_TOKEN")
    if token:
        advisories.extend(fetch_ghsa(token, max_results=ghsa_max))
    key = nvd_api_key or os.environ.get("NVD_API_KEY")
    advisories.extend(fetch_nvd(api_key=key, max_results=nvd_max))
    save_advisories(advisories, path)
    return advisories
