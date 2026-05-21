# Security

Found a real bug? Use [GitHub Security Advisories](../../security/advisories/new) (PVR is enabled on this repo). Don't open a public issue.

90 days coordinated disclosure preferred, shorter if exploited.

## In scope

- Static checks that wrongly trash legit reports or fast-track slop.
- Prompt injection bypasses against the LLM layer (manipulating confidence score, smuggled instructions, etc).
- Credential leaks in the adapters (GitHub App keys, GitLab PATs).
- Dependency vulns — yeah, even though it's upstream, ping us.

## Out of scope

- Perf issues unless they DoS the thing.
- Theoretical AI capabilities not demonstrated on the actual code.
- Reports that were obviously LLM-generated without verification. The whole point of this project is calling out unverified slop. Don't be funny.

## Credit

I'll credit you in release notes unless you'd rather stay anonymous.
