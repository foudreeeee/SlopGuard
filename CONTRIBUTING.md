# Contributing to SlopGuard

The project is in early development. Once the first prototype is published (estimated June 2026), code contributions will be welcomed under the usual GitHub fork-and-pull-request flow.

For now, the most useful contributions are:

## Feedback from maintainers

If you maintain an open-source project and have been receiving AI-generated vulnerability reports, please [open an issue](../../issues/new) describing your experience:

- How many slop reports per week or month do you receive?
- What are the most common slop patterns you see?
- What would make a triage tool actually useful for your workflow?
- What would make a triage tool actively harmful?

Anonymous reports are fine.

## Sample slop reports

If you can share an example of a slop report you have received, with personal information of the reporter redacted, please attach it to an issue. These reports are extraordinarily valuable for building the benchmark dataset that will calibrate SlopGuard's static and LLM layers.

By default, contributed samples will be incorporated into the public benchmark dataset under CC-BY-4.0. If you prefer your sample to remain private, please say so in the issue and we will use it for development only.

## Code contributions (when the project opens to them)

- Run `ruff` and `pytest` before pushing.
- Keep PRs focused. Architectural changes get their own issue first.
- The project's anti-slop methodology applies recursively: AI-assisted contributions are welcome but the human contributor is responsible for the quality of the submission.

## Code of conduct

Standard contributor expectations apply: be respectful, assume good faith, and remember that the people most affected by AI slop are already exhausted. Adding to that exhaustion through unkind communication defeats the project's purpose.
