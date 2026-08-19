# Sigma Detection Rulepack

Vendor based detection rules written in Sigma and validated for cross-platform conversion (Sentinel/KQL, Splunk/SPL). Each rule is built, converted, and manually trace-through validated.

## Why Sigma

Detection logic written once, in Sigma's field-name format, should be portable across SIEMs without rewriting the logic per platform. This repo tests that claim directly: every rule here has been run through at least two backend conversions, and the conversion failures are documented as findings.

## Rules

| Rule | Technique | Status | Case study |
|---|---|---|---|
| [`lsass_credential_access.yml`](lsass_credential_access.yml) | T1003.001 (LSASS Credential Access) | Solo-built, field-verified, Splunk-validated | [Full write-up](docs/lsass-case-study.md) |

## What "validated" means here

A rule isn't marked validated because it converts without error. Each rule's filter logic is manually traced against both real captured telemetry and synthetic test cases specifically constructed to exercise every branch of the condition — including filters that a real capture might bypass without actually testing. See the [LSASS case study](docs/lsass-case-study.md) for a worked example of this.

## Key cross-platform findings

- **Sentinel/KQL:** conversion can fail silently - a query can convert without error and still never match anything, because Sentinel workspaces ingest Windows Event Logs either raw (unparsed XML) or parsed (queryable Sysmon fields), and that's environment-specific, not something the conversion tooling can infer.
- **Splunk/SPL:** the search-command `IN` operator supports wildcards; the `eval`/`where` `IN()` function does not. Easy to lose wildcard filter behaviour silently when extending a converted query with post-processing.
