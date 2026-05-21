"""Static verification layer.

Cheap, deterministic checks. Runs before any LLM call.
Conservative by default — burying a real report is worse than letting slop through.

`_check_code_references` and `_check_advisory_dedup` are implemented and tested.
CWE plausibility and reporter signal are still TODOs (Phase 1 continues).
"""

from __future__ import annotations

import math
import re
import subprocess
from collections import Counter
from collections.abc import Sequence
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
    # TODO Phase 1: CWE plausibility, reporter signal
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


# Provisional and untuned. Phase 1 evaluation against the benchmark set will
# set this for real. Leaning high on purpose: a false "duplicate" flag that
# buries a novel report is worse than letting a real dupe through to the LLM.
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


def _check_cwe_plausibility(
    report: Report, repo_path: str
) -> list[VerificationCheck]:
    """Could the claimed CWE actually happen here? (SQLi on a no-DB project = no.)

    TODO Phase 1: project profile derivation.
    """
    raise NotImplementedError("Phase 1.")


def _check_reporter_signal(report: Report) -> list[VerificationCheck]:
    """Soft signals only. Account age, prior credits, velocity.

    TODO Phase 1.
    """
    raise NotImplementedError("Phase 1.")
