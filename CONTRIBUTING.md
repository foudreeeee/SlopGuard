# Contributing

The project is in design phase. Code contributions will be opened up once there's a real prototype to contribute to (mid-2026 target).

What's actually useful right now:

**If you maintain an OSS project getting hit by slop**, open an issue. Tell me:
- How much slop per week/month?
- What patterns? (specific tooling? specific styles?)
- What would a triage tool need to do to actually help you?
- What would make it actively harmful?

Anonymous is fine.

**If you can share an example slop report** (PII redacted), attach it. These build the benchmark dataset that calibrates the static and LLM layers. By default samples go into the public CC-BY dataset; say so if you want yours kept private.

**Code (later):**
- `ruff` and `pytest` clean before pushing.
- Architectural changes get an issue first.
- The project's anti-slop logic applies to its own PRs. If you used AI assistance, you're still responsible for what you submit.

Be decent to each other. The people most affected by slop are already worn out, no need to add to it.
