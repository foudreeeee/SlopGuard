# Research notes

Background reading that shaped the design of SlopGuard. Living document.

## The problem itself

- **Seth Larson** (Python Software Foundation, security developer-in-residence), [*A new era of slop security reports for open source*](https://sethmlarson.dev/slop-security-reports), Dec 2024.
  First public framing of the problem. Names it. Lists concrete examples from CPython, pip, urllib3, Requests.

- **Daniel Stenberg** (curl). Multiple posts on his blog ([daniel.haxx.se](https://daniel.haxx.se/blog/)) through 2025 and the [HackerOne shutdown announcement](https://daniel.haxx.se/blog/) in January 2026.
  The economic argument: bounty rate above 15% → below 5%, hours-to-refute dominates.

- **Linus Torvalds**, Linux 6.x release notes, May 2026.
  "Almost entirely unmanageable." Public, on-record, from the highest-profile maintainer.

- **Help Net Security**, [AI is drowning software maintainers in junk security reports](https://www.helpnetsecurity.com/2026/05/18/problems-with-ai-assisted-vulnerability-research/), 18 May 2026.
  Recent synthesis. Useful for the broader context.

## Platform response

- **GitHub Community Discussion #189802**, [Investing in the security advisory experience on GitHub](https://github.com/orgs/community/discussions/189802), March 2026.
  GitHub's roadmap announcement. Confirms: AI-assisted triage is coming to PVR. Confirms: it'll be GitHub-only and proprietary.

- **HackerOne Hai Triage**, [launch announcement](https://www.hackerone.com/press-release/hackerone-unveils-hai-triage-upgraded-ai-powered-vulnerability-response), July 2025.
  Paid enterprise solution. Useful as a reference point for what "good" looks like, not as a tool the volunteer OSS maintainers can actually use.

- **OpenSSF Vulnerability Disclosures Working Group**.
  Active community call for contributions on this exact problem. Natural upstream home for this project.

- **Linux Foundation $12.5M grant announcement**, [March 2026](https://www.linuxfoundation.org/press/linux-foundation-announces-12.5-million-in-grant-funding-from-leading-organizations-to-advance-open-source-security).
  Anthropic, AWS, GitHub, Google, Microsoft, OpenAI jointly funding Alpha-Omega and OpenSSF specifically on this problem domain. Establishes that the industry consensus is real.

## Technical methodology

- **Tantithamthavorn et al.**, [*HalluJudge: A Reference-Free Hallucination Detection for Context Misalignment in Code Review Automation*](https://arxiv.org/abs/2601.19072), ICSE 2026.
  The grounded-LLM-as-reasoner approach. F1=0.85 at ~$0.009 per assessment when the LLM operates over structured context. This is the methodological backbone of the LLM layer.

- **Agrawal & Ahi**, [*LLM-Driven SAST-Genius*](https://arxiv.org/abs/2509.15433), 2025.
  Hybrid static + LLM pipeline. 89.5% precision on vulnerability triage when SAST and LLM are combined. Useful pattern: static layer first, LLM as enrichment.

- **Raff et al.**, [*Automatic Yara Rule Generation Using Biclustering*](https://arxiv.org/pdf/2009.03779), 2020.
  Earlier work on automating detection rule generation. Not directly applicable but useful for thinking about the dedup layer.

## Adjacent tooling (what NOT to duplicate)

- **CodeRabbit slop detection** ([docs](https://docs.coderabbit.ai/pr-reviews/slop-detection)). PR-side, not PVR-side.
- **Anti-Slop GitHub Action** ([peakoss/anti-slop](https://github.com/peakoss/anti-slop)). PR-side, not PVR-side.
- **GitHub Security Lab Taskflow Agent** ([blog post](https://github.blog/security/community-powered-security-with-ai-an-open-source-framework-for-security-research/)). Finds bugs in OSS, the inverse problem.
- **AgentShield AI / sigma-ai**, **Agent-Threat-Rule (ATR)**. Sigma rules for AI agents under attack. Different problem (defending an AI agent, not detecting AI in vulnerability reports).

## To read

- The OpenSSF Vulnerability Disclosures Working Group meeting notes (if/when public).
- Tree-sitter language bindings, for the symbol-grounding phase 2.
- The Mistral / GPT / Claude structured-output documentation, for cost benchmarking.
