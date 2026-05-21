# Benchmark

A small, labeled set of vulnerability reports for evaluating SlopGuard end to end.

Status: seed set. 8 slop, 7 genuine. Hand-authored. Expect it to grow.

## What these are (and aren't)

Each file is one report in the [`Report`](../slopguard/schema.py) schema. The
label is the directory:

- `slop/` reports that a maintainer should be able to dismiss or downgrade.
- `genuine/` reports that describe a real, plausible vulnerability.

These are **hand-authored** to represent the failure modes documented in public:
hallucinated file paths and function names, reused CVE ids from unrelated
projects, confident but content-free LLM prose, impossible CWE-for-this-project
claims, and high-volume templated submissions. They are **not** verbatim copies
of anyone's real report, and every reporter handle is fictional. The point is to
capture the *shape* of slop without republishing other people's words or
inventing quotes and attributing them to real people.

Background that informed the slop examples: Daniel Stenberg's writing on the
curl HackerOne reports, Seth Larson's "AI slop security reports" (PSF, Dec 2024),
the urllib3 issue closures, and the pattern of reusing famous CVEs (Log4Shell)
against projects that can't possibly be affected.

Real, labeled reports from willing maintainers are a Phase 5-6 goal, coordinated
with the OpenSSF Vulnerability Disclosures Working Group. This seed set is what
lets us start tuning thresholds before then.

## Layout

```
benchmark/
  slop/      8 reports a maintainer should dismiss or downgrade
  genuine/   7 reports describing a real, plausible vulnerability
```

## What each report exercises

The signal column is where SlopGuard *should* get traction. Some signals are not
implemented yet (CWE plausibility, reporter signal, the LLM layer); those rows
are here so the data is ready when the checks land.

| id | signal | note |
|---|---|---|
| slop-001 | code reference grounding | cites `lib/curl_sasl_handler.c` / `curl_sasl_decode_challenge()`, neither in curl |
| slop-002 | advisory dedup + CWE plausibility | reuses CVE-2021-44228 (Log4Shell, Java) against a non-Java project |
| slop-003 | LLM layer + vagueness | no specifics, no code refs, bounty-seeking |
| slop-004 | CWE plausibility | SQL injection claim against a library with no database surface |
| slop-005 | code reference grounding | `inject_headers()` does not exist in urllib3 |
| slop-006 | temporal grounding | claims a feature in v0.1.0 that did not exist until later |
| slop-007 | CWE/severity consistency | labels an info-leak (CWE-209) as critical RCE |
| slop-008 | reporter signal | templated body, velocity 147 reports / 30 days |
| genuine-001 | should pass | ReDoS, concrete pattern, measured timing |
| genuine-002 | should pass | path traversal, concrete payload |
| genuine-003 | should pass | stored XSS, specific sink |
| genuine-004 | should pass | broken authorization, specific logic flaw |
| genuine-005 | should pass | SSRF via redirect to link-local address |
| genuine-006 | should pass | non-constant-time token comparison |
| genuine-007 | should pass | unsafe `yaml.load` on uploaded config |

The slop reports that name a real upstream (curl, urllib3) are meant to be run
against a clone of that project, where the cited path or symbol will fail to
ground. The rest are self-contained: they exercise the text-based and metadata
signals without needing a specific repo checkout.

## How to use

Load a report and run it through the static layer:

```python
import json
from slopguard.schema import Report
from slopguard.verification import verify_report

report = Report(**json.loads(open("benchmark/slop/slop-001-curl-hallucinated-sasl-overflow.json").read()))
for check in verify_report(report, repo_path="/path/to/curl"):
    print(check.outcome.value, check.name, check.detail)
```

`tests/test_benchmark.py` loads every file here and asserts it still validates
against the schema, so the dataset can't silently drift out of sync.

## License

The benchmark data in this directory is licensed CC-BY-4.0
(SPDX-License-Identifier: CC-BY-4.0), separate from the MIT license on the code.
Full text: https://creativecommons.org/licenses/by/4.0/legalcode

Attribution: SlopGuard contributors (github.com/foudreeeee/SlopGuard).
