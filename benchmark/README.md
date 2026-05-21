# Benchmark

A small, labeled set of vulnerability reports for evaluating SlopGuard end to end.

Status: 15 slop, 15 genuine. Hand-authored. Expect it to grow.

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

The recycled-CVE reports cite real, famous CVE ids (Log4Shell, Heartbleed,
Shellshock, Dirty COW, Spring4Shell, EternalBlue) against projects that can't
possibly be affected. That's a common slop pattern, and the ids are real so the
dedup check has something concrete to match.

Background that informed the slop examples: Daniel Stenberg's writing on the
curl HackerOne reports, Seth Larson's "AI slop security reports" (PSF, Dec 2024),
and the urllib3 issue closures.

Real, labeled reports from willing maintainers are a Phase 5-6 goal, coordinated
with the OpenSSF Vulnerability Disclosures Working Group. This set is what lets
us start tuning thresholds before then.

## Layout

```
benchmark/
  slop/      15 reports a maintainer should dismiss or downgrade
  genuine/   15 reports describing a real, plausible vulnerability
```

## What each report exercises

The signal column is where SlopGuard *should* get traction. The static checks
all exist now; the LLM layer does not yet, so rows that lean on it are
aspirational.

| id | signal | note |
|---|---|---|
| slop-001 | code reference grounding | cites `lib/curl_sasl_handler.c` / `curl_sasl_decode_challenge()`, neither in curl |
| slop-002 | advisory dedup + CWE plausibility | recycles CVE-2021-44228 (Log4Shell, Java) against a non-Java project |
| slop-003 | LLM layer + vagueness | no specifics, no code refs, bounty-seeking |
| slop-004 | CWE plausibility | SQL injection claim against a library with no database surface |
| slop-005 | code reference grounding | `inject_headers()` does not exist in urllib3 |
| slop-006 | temporal grounding | claims a feature in v0.1.0 that did not exist until later |
| slop-007 | CWE/severity consistency | labels an info-leak (CWE-209) as critical RCE |
| slop-008 | reporter signal | templated body, velocity 147 reports / 30 days |
| slop-009 | advisory dedup | recycles CVE-2014-0160 (Heartbleed, OpenSSL/C) against a pure-Python lib |
| slop-010 | advisory dedup | recycles CVE-2014-6271 (Shellshock) against a project with no shell/CGI |
| slop-011 | advisory dedup | recycles CVE-2016-5195 (Dirty COW, kernel) against a userland app |
| slop-012 | advisory dedup | recycles CVE-2022-22965 (Spring4Shell, Java) against a non-Java project |
| slop-013 | advisory dedup | recycles CVE-2017-0144 (EternalBlue, SMB) against a web library |
| slop-014 | reporter signal | templated "AI scan" spam, velocity 210 / 30 days |
| slop-015 | reporter signal | dependency-FUD spam selling remediation, velocity 88 / 30 days |
| genuine-001 | should pass | ReDoS, concrete pattern, measured timing |
| genuine-002 | should pass | path traversal, concrete payload |
| genuine-003 | should pass | stored XSS, specific sink |
| genuine-004 | should pass | broken authorization, specific logic flaw |
| genuine-005 | should pass | SSRF via redirect to link-local address |
| genuine-006 | should pass | non-constant-time token comparison |
| genuine-007 | should pass | unsafe `yaml.load` on uploaded config |
| genuine-008 | should pass | CSRF on an email-change endpoint |
| genuine-009 | should pass | IDOR exposing other users' invoices |
| genuine-010 | should pass | open redirect via the `next` parameter |
| genuine-011 | should pass | integer overflow leading to undersized allocation |
| genuine-012 | should pass | TOCTOU symlink race in temp-file write |
| genuine-013 | should pass | prototype pollution in a merge helper |
| genuine-014 | should pass | hardcoded API token in source |
| genuine-015 | should pass | admin metrics endpoint missing authentication |

The slop reports that name a real upstream (curl, urllib3) are meant to be run
against a clone of that project, where the cited path or symbol will fail to
ground. The rest are self-contained: they exercise the text-based and metadata
signals without needing a specific repo checkout.

## Evaluation

`python -m benchmark.evaluate` runs every report through the pipeline and prints
a table plus a summary. It exercises the *portable* signals only, advisory dedup
and the reporter signal, because code-reference grounding and CWE plausibility
need the repo each report cites, which the harness does not clone.

On the current set, portable signals flag 6/15 slop (the recycled-CVE reports,
caught by dedup) and 0/15 genuine. No real report is buried, which is the
property the project cares most about. The remaining slop is designed to be
caught by code-reference grounding or CWE plausibility; point the pipeline at
the cited upstream to exercise those.

The recycled-CVE reports also pin down the dedup threshold: an exact CVE/GHSA-id
match scores 1.0, and no genuine report here scores above ~0.3, so the 0.6
default separates them with a wide margin. Reworded duplicates that share no id
still need real examples to tune (issue #1).

## How to use

Load a report and run it through the static layer:

```python
import json
from slopguard.schema import Report
from slopguard.verification import verify_report

path = "benchmark/slop/slop-001-curl-hallucinated-sasl-overflow.json"
report = Report(**json.loads(open(path).read()))
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
