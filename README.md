# SlopGuard

Triage layer for incoming vulnerability reports, aimed at open-source maintainers drowning in AI-generated slop.

Early days. No releases yet. The schema works and the tests pass, the rest is being written.

## Why

Since late 2024 the same story has been repeating across OSS:

- cURL shut down its HackerOne bounty in Jan 2026 because most submissions were hallucinated. Confirmed-vuln rate went from above 15% to below 5%.
- Linus called the kernel security list "almost entirely unmanageable" in the 6.x release notes.
- Jazzband closed.
- Seth Larson (PSF) has been writing about this since his Dec 2024 post.

GitHub announced they're building AI triage into Private Vulnerability Reporting (Discussion #189802, March 2026). Fine, but: not shipped yet, GitHub-only, closed source. Maintainers on GitLab, Codeberg, Forgejo, SourceHut, or plain email get nothing.

The OpenSSF Vulnerability Disclosures Working Group is asking for community contributions. This is my attempt.

## What it does

You point it at a vulnerability report. It runs two passes:

1. **Static checks** (no LLM, fast, cheap):
   - Does the cited file actually exist at the claimed commit?
   - Does line 471 actually exist in that file?
   - Does the cited symbol exist or is it hallucinated?
   - Is this a near-dupe of a public GHSA/NVD entry?
   - Is the claimed CWE even possible for this project? (SQLi on a project with no DB = suspicious)
   - Reporter signals (account age, prior advisories, velocity) — soft only.

2. **Grounded LLM pass** (only if static didn't already trash it):
   - Model gets the report + the actual code excerpts the static layer pulled out + SECURITY.md.
   - One question: given the code I'm showing you, can this vuln exist? PLAUSIBLE / IMPLAUSIBLE / UNDETERMINED.
   - Output is Pydantic-validated. If it cites a file or symbol not in the context, override to UNDETERMINED.

Result: a confidence score, the list of checks that passed/failed, a suggested action, a draft reply.

Maintainer decides. Tool never closes anything on its own.

## What it isn't

- Not a PR slop detector. CodeRabbit and peakoss/anti-slop do that.
- Not HackerOne Hai Triage. That one's paid + tied to their platform.
- Not GitHub Security Lab Taskflow Agent. That one helps researchers find bugs, this one helps maintainers filter incoming reports.

## Architecture

See `docs/architecture.md` for the longer version.

```
report → adapter → static checks → (if not trashed) → LLM grounded pass → triage view
```

GitHub App, GitLab webhook, Maildir watcher, or stdin CLI. Same internal schema for all of them.

## Status

- [x] Schema (Pydantic, tested)
- [x] Architecture doc
- [x] Code reference grounding (git-based, 60 tests passing)
- [x] GHSA / NVD dedup
- [ ] CWE plausibility
- [ ] LLM layer with grounded prompts
- [ ] Prompt injection hardening
- [ ] GitHub App
- [ ] GitLab / email adapters
- [x] Benchmark dataset

Target: prototype usable by mid-2026.

## Roadmap (rough)

Month 1: static layer, CLI works.
Month 2: LLM layer on top, end-to-end.
Months 3-4: other adapters, hardening, 1.0.
Months 5-6: pilot with whichever maintainer is brave enough, refine.

## Running tests

```bash
pip install -e ".[dev]"
pytest
```

## License

MIT.

## Acknowledgements

The framing of the problem comes from Seth Larson's "A new era of slop security reports for open source" (Dec 2024) and Stenberg's writing on the cURL bounty shutdown. The grounded-LLM-as-reasoner approach is borrowed from HalluJudge (Tantithamthavorn et al., 2026). None of them know I exist.
