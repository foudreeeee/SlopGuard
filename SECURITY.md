# Security Policy

A vulnerability triage tool needs to take its own security posture seriously. This policy is deliberately simple, written for the project's current early-development stage.

## Reporting a vulnerability

If you find a security issue in SlopGuard itself, please open a [GitHub Security Advisory](../../security/advisories/new) on this repository. Private vulnerability reporting is enabled.

Please do **not** open a public issue for security problems. Use the advisory flow, or if it is unavailable, send an email to the address listed in the project's maintainer profile.

A coordinated disclosure window of 90 days from the date of report is preferred. Shorter windows are acceptable when actively exploited.

## What is in scope

- Logic errors in the static verification layer that could cause SlopGuard to wrongly fast-track a slop report or wrongly reject a genuine report.
- Prompt-injection bypasses against the LLM claim assessment layer, including techniques that manipulate the model into producing an inflated confidence score on a hallucinated report.
- Credential leakage paths in the platform adapters (GitHub App private keys, GitLab personal access tokens, etc.).
- Supply-chain risks in dependencies (we will accept dependency vulnerability reports here even though the underlying issue is upstream).

## What is out of scope

- Performance issues unless they constitute a denial-of-service condition.
- Reports about hypothetical AI capabilities not demonstrated against the actual codebase.
- Reports generated without verification by the reporter. SlopGuard's own anti-slop methodology applies recursively: please verify your finding before reporting it.

## Acknowledgements

Verified reporters will be credited in release notes unless they request anonymity.

## A note on AI-assisted security research

AI-assisted vulnerability research is welcome here, with the same expectation we hold for the projects SlopGuard helps: the human reporter is responsible for the quality of the submission. Reports that show clear signs of LLM hallucination without human verification will be closed without further engagement.
