"""Static verification layer.

Cheap, deterministic checks. Runs before any LLM call.
Conservative by default — burying a real report is worse than letting slop through.

All four static checks are implemented and tested: code reference grounding,
advisory dedup, CWE plausibility, and reporter signal.
"""

from __future__ import annotations

import math
import re
import subprocess
from collections import Counter
from collections.abc import Sequence
from dataclasses import dataclass
from pathlib import Path

from slopguard.advisories import Advisory, load_advisories
from slopguard.schema import (
    CheckOutcome,
    CodeReference,
    Report,
    VerificationCheck,
)


def verify_report(
    report: Report,
    repo_path: str,
    advisories: Sequence[Advisory] | None = None,
) -> list[VerificationCheck]:
    """Run all static checks against a report.

    `advisories` is the corpus the dedup check matches against. If None, it's
    loaded from the local cache (empty when nothing's been fetched yet, which
    just makes dedup INDETERMINATE rather than failing).
    """
    checks: list[VerificationCheck] = []
    checks.extend(_check_code_references(report, repo_path))
    if advisories is None:
        advisories = load_advisories()
    checks.extend(_check_advisory_dedup(report, advisories))
    checks.extend(_check_cwe_plausibility(report, repo_path))
    checks.extend(_check_reporter_signal(report))
    return checks


def _check_code_references(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Do the cited files/lines actually exist at the claimed commit?

    For each CodeReference in the report:
      - Resolve the target commit (claimed_commit, else HEAD)
      - Check the file exists at that commit
      - If a line number is given, check the line is in range
      - If a symbol is given, do a coarse substring search (tree-sitter later)

    Symbol-level checks are intentionally lax for now: we only flag
    `symbol_never_found` when the symbol literally doesn't appear anywhere in
    the file. Tree-sitter integration (planned for Phase 2) will tighten this.
    """
    if not report.code_references:
        return []

    repo = Path(repo_path)
    if not (repo / ".git").is_dir():
        return [
            VerificationCheck(
                name="code_references",
                outcome=CheckOutcome.INDETERMINATE,
                detail=f"{repo_path} is not a git repository.",
            )
        ]

    target_commit = report.claimed_commit or "HEAD"
    if not _commit_exists(repo, target_commit):
        return [
            VerificationCheck(
                name="code_references",
                outcome=CheckOutcome.INDETERMINATE,
                detail=(
                    f"Claimed commit {target_commit} not found locally. "
                    f"Cannot verify code references."
                ),
            )
        ]

    results: list[VerificationCheck] = []
    for ref in report.code_references:
        results.append(_check_one_reference(repo, target_commit, ref))
    return results


def _check_one_reference(
    repo: Path, commit: str, ref: CodeReference
) -> VerificationCheck:
    """Check a single CodeReference against a specific commit."""
    file_content = _git_show(repo, commit, ref.file_path)
    if file_content is None:
        return VerificationCheck(
            name="file_not_found",
            outcome=CheckOutcome.FAIL,
            detail=(
                f"{ref.file_path} does not exist at commit {commit[:8]}."
            ),
        )

    lines = file_content.splitlines()
    if ref.line_number is not None:
        if ref.line_number < 1 or ref.line_number > len(lines):
            return VerificationCheck(
                name="line_out_of_range",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"{ref.file_path}:{ref.line_number} is out of range "
                    f"(file has {len(lines)} lines at commit {commit[:8]})."
                ),
            )

    if ref.symbol is not None:
        if ref.symbol not in file_content:
            return VerificationCheck(
                name="symbol_never_found",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"Symbol {ref.symbol!r} not found anywhere in "
                    f"{ref.file_path} at commit {commit[:8]}."
                ),
            )

    return VerificationCheck(
        name="code_reference_ok",
        outcome=CheckOutcome.PASS,
        detail=(
            f"{ref.file_path}"
            + (f":{ref.line_number}" if ref.line_number else "")
            + (f" ({ref.symbol})" if ref.symbol else "")
            + f" exists at {commit[:8]}."
        ),
    )


def _commit_exists(repo: Path, commit: str) -> bool:
    """Returns True if `commit` resolves to a known object in `repo`."""
    try:
        subprocess.run(
            ["git", "-C", str(repo), "rev-parse", "--verify", f"{commit}^{{commit}}"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return True
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return False


def _git_show(repo: Path, commit: str, path: str) -> str | None:
    """Returns the file contents at `commit:path`, or None if missing."""
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "show", f"{commit}:{path}"],
            check=True,
            capture_output=True,
            timeout=5,
        )
        return result.stdout.decode("utf-8", errors="replace")
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None


# Validated on the 30-report benchmark: exact CVE/GHSA-id recycling scores 1.0
# and is caught at any threshold, while no genuine report there scores above
# ~0.3, so 0.6 leaves a wide false-positive margin. Reworded dupes that share
# no id (fuzzy matches) still need real examples to tune against (issue #1).
DEDUP_THRESHOLD = 0.6


def _check_advisory_dedup(
    report: Report,
    corpus: Sequence[Advisory],
    *,
    threshold: float = DEDUP_THRESHOLD,
    top_n: int = 3,
) -> list[VerificationCheck]:
    """Is this a near-dupe of something already in GHSA or NVD?

    Two signals, combined per advisory:

      - TF-IDF cosine over (title + first 500 chars of description). Catches
        reports that are textually the same advisory reworded.
      - Technical-term overlap: a shared CVE/GHSA id is a near-certain dupe
        (those are unique handles); otherwise char-4-gram Dice over the code
        identifiers (function names, dotted paths) the two texts mention.

    A shared CVE/GHSA id pins the score to 1.0. Otherwise the score is a blend
    of cosine and term overlap. Anything at or above `threshold` is surfaced
    as a possible duplicate for the maintainer to confirm. We never close it.
    """
    if not corpus:
        return [
            VerificationCheck(
                name="advisory_dedup",
                outcome=CheckOutcome.INDETERMINATE,
                detail=(
                    "No advisory data cached, so dedup was skipped. "
                    "Run `slopguard refresh` to populate GHSA + NVD."
                ),
            )
        ]

    report_text = f"{report.title} {report.description[:500]}"
    report_ids = _advisory_ids(report_text) | {
        c.upper() for c in (report.claimed_cwe or [])
    }
    report_terms = _code_terms(report_text) | {
        ref.symbol.lower() for ref in report.code_references if ref.symbol
    }
    report_ngrams = _char_ngrams(" ".join(sorted(report_terms)))

    index = _TfidfIndex([f"{a.title} {a.summary[:500]}" for a in corpus])
    cosines = index.similarities(report_text)

    scored: list[tuple[float, Advisory, set[str]]] = []
    for advisory, cosine in zip(corpus, cosines):
        adv_ids = {
            x.upper() for x in (advisory.id, *advisory.aliases, *advisory.cwe_ids)
        }
        shared = report_ids & adv_ids
        strong = {i for i in shared if i.startswith(("CVE-", "GHSA-"))}
        adv_terms = _code_terms(f"{advisory.title} {advisory.summary}")
        term_sim = _dice(report_ngrams, _char_ngrams(" ".join(sorted(adv_terms))))
        score = 1.0 if strong else 0.7 * cosine + 0.3 * term_sim
        scored.append((score, advisory, shared))

    scored.sort(key=lambda row: row[0], reverse=True)
    hits = [row for row in scored if row[0] >= threshold][:top_n]

    if not hits:
        best = scored[0][0] if scored else 0.0
        return [
            VerificationCheck(
                name="no_known_duplicate",
                outcome=CheckOutcome.PASS,
                detail=(
                    f"No near-duplicate among {len(corpus)} known advisories "
                    f"(closest match scored {best:.2f})."
                ),
            )
        ]

    parts = []
    for score, advisory, shared in hits:
        shared_note = f", shares {', '.join(sorted(shared))}" if shared else ""
        parts.append(
            f"{advisory.id} ({advisory.title[:60]}) score {score:.2f}{shared_note}"
        )
    return [
        VerificationCheck(
            name="possible_duplicate",
            outcome=CheckOutcome.FAIL,
            detail="Possible duplicate of: " + "; ".join(parts),
        )
    ]


# --- text matching primitives ---------------------------------------------

# Small stopword set so TF-IDF weights real terms over English filler.
_STOPWORDS = frozenset(
    "a an and are as at be by for from has have in into is it its of on or "
    "that the this to was were when which with".split()
)
_TOKEN_RE = re.compile(r"[a-z0-9]+")

_CVE_RE = re.compile(r"CVE-\d{4}-\d{4,}", re.IGNORECASE)
_CWE_RE = re.compile(r"CWE-\d+", re.IGNORECASE)
_GHSA_RE = re.compile(r"GHSA(?:-[0-9a-z]{4}){3}", re.IGNORECASE)
# Code-identifier shapes: snake_case, camelCase, dotted.paths, and name( calls.
_SNAKE_RE = re.compile(r"\b[A-Za-z][A-Za-z0-9]*(?:_[A-Za-z0-9]+)+\b")
_CAMEL_RE = re.compile(r"\b[a-z]+[A-Z][A-Za-z0-9]*\b")
_DOTTED_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]+)+\b")
_CALL_RE = re.compile(r"\b([A-Za-z_][A-Za-z0-9_]{2,})\s*\(")


def _tokenize(text: str) -> list[str]:
    return [
        t
        for t in _TOKEN_RE.findall(text.lower())
        if len(t) > 1 and t not in _STOPWORDS
    ]


def _advisory_ids(text: str) -> set[str]:
    """Exact advisory identifiers (CVE/CWE/GHSA) mentioned in the text."""
    found: set[str] = set()
    for pattern in (_CVE_RE, _CWE_RE, _GHSA_RE):
        found.update(m.group(0).upper() for m in pattern.finditer(text))
    return found


def _code_terms(text: str) -> set[str]:
    """Code-identifier-looking tokens (function names, dotted paths)."""
    found: set[str] = set()
    for pattern in (_SNAKE_RE, _CAMEL_RE, _DOTTED_RE):
        found.update(m.group(0).lower() for m in pattern.finditer(text))
    found.update(m.group(1).lower() for m in _CALL_RE.finditer(text))
    return found


def _char_ngrams(text: str, n: int = 4) -> set[str]:
    """Character n-grams of the whitespace-stripped text."""
    squashed = re.sub(r"\s+", "", text.lower())
    if len(squashed) < n:
        return {squashed} if squashed else set()
    return {squashed[i : i + n] for i in range(len(squashed) - n + 1)}


def _dice(a: set[str], b: set[str]) -> float:
    """Sorensen-Dice overlap of two sets, in [0, 1]."""
    if not a or not b:
        return 0.0
    return 2 * len(a & b) / (len(a) + len(b))


class _TfidfIndex:
    """A tiny TF-IDF index. Pure Python, no numpy.

    Built once per corpus. `similarities` returns the cosine similarity of a
    query against every document, in corpus order. Fine for the small,
    project-scoped corpora we expect; a full GHSA+NVD mirror would want a real
    vector index (TODO Phase 1 if perf bites).
    """

    def __init__(self, documents: Sequence[str]) -> None:
        tfs = [Counter(_tokenize(doc)) for doc in documents]
        df: Counter[str] = Counter()
        for tf in tfs:
            df.update(tf.keys())
        n = len(tfs)
        # Smoothed idf (sklearn-style), so a term in every doc still weighs > 0.
        self._idf = {
            term: math.log((n + 1) / (count + 1)) + 1.0 for term, count in df.items()
        }
        self._vectors: list[dict[str, float]] = []
        self._norms: list[float] = []
        for tf in tfs:
            vec = {term: count * self._idf[term] for term, count in tf.items()}
            self._vectors.append(vec)
            self._norms.append(math.sqrt(sum(w * w for w in vec.values())))

    def similarities(self, query: str) -> list[float]:
        qtf = Counter(_tokenize(query))
        qvec = {t: c * self._idf[t] for t, c in qtf.items() if t in self._idf}
        qnorm = math.sqrt(sum(w * w for w in qvec.values()))
        sims: list[float] = []
        for vec, norm in zip(self._vectors, self._norms):
            if qnorm == 0.0 or norm == 0.0:
                sims.append(0.0)
                continue
            small, large = (qvec, vec) if len(qvec) < len(vec) else (vec, qvec)
            dot = sum(weight * large.get(term, 0.0) for term, weight in small.items())
            sims.append(dot / (qnorm * norm))
        return sims


# CWE plausibility is a conservative heuristic. It flags a claim implausible
# only when the project shows no sign of the surface that CWE needs (a SQL
# injection claim against a project with no database code, say). When unsure it
# stays quiet: burying a real report is worse than letting one through. It
# downgrades a claim, it never rejects it.
MIN_SCAN_FOR_IMPLAUSIBLE = 3

_SOURCE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php",
    ".c", ".cc", ".cpp", ".h", ".hpp", ".cs", ".scala", ".kt", ".ex", ".exs",
    ".pl", ".swift",
}
_MANIFEST_FILES = {
    "requirements.txt", "pyproject.toml", "setup.py", "setup.cfg", "Pipfile",
    "package.json", "go.mod", "Cargo.toml", "Gemfile", "pom.xml",
    "build.gradle", "composer.json",
}
# Deliberately broad: over-detecting a capability only makes us MORE likely to
# call a CWE plausible, which is the safe direction. Markers are matched
# lowercased against source + manifest text.
_CAPABILITY_MARKERS = {
    "database": [
        "sqlite3", "psycopg", "pymysql", "mysqlclient", "sqlalchemy",
        "django.db", "mongo", "sequelize", "gorm", "diesel", "activerecord",
        "jdbc", "cursor.execute", "select ", "insert into",
    ],
    "web_output": [
        "flask", "django", "fastapi", "starlette", "express", "koa", "sinatra",
        "rails", "render_template", "jinja", "text/html", "res.send", "<html",
    ],
    "deserialization": [
        "pickle", "yaml.load", "marshal.load", "objectinputstream",
        "readobject", "unserialize(", "jackson", "fasterxml",
    ],
    "command_exec": [
        "subprocess", "os.system", "os.popen", "exec(", "eval(",
        "child_process", "runtime.exec", "shell=true", "popen(",
    ],
    "xml": [
        "lxml", "xml.etree", "elementtree", "xml.dom", "expat",
        "documentbuilder", "saxparser", "xmlreader", "<!doctype",
    ],
    "http_client": [
        "requests.", "urllib.request", "httpx", "http.client", "aiohttp",
        "axios", "fetch(", "net/http", "reqwest", "urlopen",
    ],
    "regex": ["import re", "re.compile", "regexp", "pattern.compile", "regex::"],
}
_CWE_CAPABILITY = {
    "CWE-89": "database",
    "CWE-564": "database",
    "CWE-79": "web_output",
    "CWE-80": "web_output",
    "CWE-502": "deserialization",
    "CWE-78": "command_exec",
    "CWE-77": "command_exec",
    "CWE-94": "command_exec",
    "CWE-611": "xml",
    "CWE-776": "xml",
    "CWE-918": "http_client",
    "CWE-1333": "regex",
}


@dataclass(frozen=True)
class _Profile:
    capabilities: frozenset[str]
    scanned_files: int


def _check_cwe_plausibility(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Could the claimed CWE happen here, given the project's surface?

    Flags `cwe_implausible` only when a modeled CWE needs a surface the project
    shows no sign of. Otherwise PASS (surface present) or INDETERMINATE (no
    claim, an unmodeled CWE, or too little scanned). Downgrades, never rejects.
    """
    if not report.claimed_cwe:
        return []
    profile = _derive_project_profile(repo_path)
    if profile is None:
        return [
            VerificationCheck(
                name="cwe_plausibility",
                outcome=CheckOutcome.INDETERMINATE,
                detail="Could not profile the project (not a git repo or unreadable).",
            )
        ]
    modeled = [
        (cwe.upper(), _CWE_CAPABILITY[cwe.upper()])
        for cwe in report.claimed_cwe
        if cwe.upper() in _CWE_CAPABILITY
    ]
    if not modeled:
        return [
            VerificationCheck(
                name="cwe_plausibility",
                outcome=CheckOutcome.INDETERMINATE,
                detail=(
                    f"Claimed CWE(s) {report.claimed_cwe} are not modeled by the "
                    f"plausibility check."
                ),
            )
        ]
    missing = [
        (cwe, cap) for cwe, cap in modeled if cap not in profile.capabilities
    ]
    if missing:
        if profile.scanned_files < MIN_SCAN_FOR_IMPLAUSIBLE:
            return [
                VerificationCheck(
                    name="cwe_plausibility",
                    outcome=CheckOutcome.INDETERMINATE,
                    detail=(
                        f"Only {profile.scanned_files} source files scanned, too "
                        f"few to judge whether the surface is really absent."
                    ),
                )
            ]
        detail = "; ".join(
            f"{cwe} needs a {cap} surface, none detected" for cwe, cap in missing
        )
        return [
            VerificationCheck(
                name="cwe_implausible",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"Claimed class looks implausible here: {detail}. "
                    f"Downgraded, not rejected."
                ),
            )
        ]
    present = ", ".join(f"{cwe} ({cap})" for cwe, cap in modeled)
    return [
        VerificationCheck(
            name="cwe_plausible",
            outcome=CheckOutcome.PASS,
            detail=f"Project has the surface the claimed CWE needs: {present}.",
        )
    ]


def _derive_project_profile(repo_path: str) -> _Profile | None:
    """Scan the repo's tracked source + manifests for capability markers.

    Reads the working tree (not a specific commit) and is bounded: it skips
    large files and stops after a file/byte budget, so it stays cheap on big
    repos. Returns None when the path isn't a readable git repo.
    """
    repo = Path(repo_path)
    if not (repo / ".git").is_dir():
        return None
    try:
        result = subprocess.run(
            ["git", "-C", str(repo), "ls-files"],
            check=True,
            capture_output=True,
            timeout=10,
        )
    except (subprocess.CalledProcessError, subprocess.TimeoutExpired):
        return None

    capabilities: set[str] = set()
    scanned = 0
    budget = 8_000_000
    for rel in result.stdout.decode("utf-8", errors="replace").splitlines():
        rel_path = Path(rel)
        if (
            rel_path.suffix not in _SOURCE_EXTENSIONS
            and rel_path.name not in _MANIFEST_FILES
        ):
            continue
        path = repo / rel
        try:
            if path.stat().st_size > 512_000:
                continue
            text = path.read_text(encoding="utf-8", errors="replace").lower()
        except OSError:
            continue
        scanned += 1
        budget -= len(text)
        for capability, markers in _CAPABILITY_MARKERS.items():
            if capability not in capabilities and any(m in text for m in markers):
                capabilities.add(capability)
        if scanned >= 1500 or budget <= 0:
            break
    return _Profile(capabilities=frozenset(capabilities), scanned_files=scanned)


# Reporter signal is soft and never decisive (the decision layer weights it
# low). Only a very high cross-project submission rate counts against a report;
# a new account is routed to normal review, not penalized.
REPORTER_VELOCITY_SUSPICIOUS = 50  # reports per 30 days, across all projects


def _check_reporter_signal(report: Report) -> list[VerificationCheck]:
    """Soft reputation signal. Never decisive (see decision.py weights).

    High 30-day submission velocity is a slight negative (spray pattern); a
    track record of prior credited advisories is a positive; a new or unknown
    reporter is neutral, not penalized.
    """
    info = report.reporter
    has_data = (
        info.handle is not None
        or info.account_age_days is not None
        or info.prior_credited_advisories > 0
        or info.submission_velocity_30d > 0
    )
    if not has_data:
        return [
            VerificationCheck(
                name="reporter_signal",
                outcome=CheckOutcome.INDETERMINATE,
                detail="No reporter metadata available.",
            )
        ]
    if info.submission_velocity_30d >= REPORTER_VELOCITY_SUSPICIOUS:
        return [
            VerificationCheck(
                name="reporter_signal",
                outcome=CheckOutcome.FAIL,
                detail=(
                    f"{info.submission_velocity_30d} reports filed in the last 30 "
                    f"days across projects — high-volume pattern. Soft signal only."
                ),
            )
        ]
    if info.prior_credited_advisories >= 1:
        return [
            VerificationCheck(
                name="reporter_signal",
                outcome=CheckOutcome.PASS,
                detail=(
                    f"{info.prior_credited_advisories} prior credited "
                    f"advisories — established track record."
                ),
            )
        ]
    return [
        VerificationCheck(
            name="reporter_signal",
            outcome=CheckOutcome.INDETERMINATE,
            detail="New or unknown reporter, no track record. Not penalized.",
        )
    ]
