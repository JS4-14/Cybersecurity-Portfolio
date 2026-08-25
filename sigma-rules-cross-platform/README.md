# Sigma Detection Rulepack

Vendor-agnostic detection rules written in Sigma and validated for cross-platform conversion (Sentinel/KQL, Splunk/SPL). Each rule is built, converted, and manually trace-through validated.

## Why Sigma

Detection logic written once, in Sigma's field-name format, should be portable across SIEMs without rewriting the logic per platform. This repo tests that claim directly: every rule here has been run through at least two backend conversions, and the conversion failures are documented as findings.

| Rule | Technique | Status |
|---|---|---|
| `lsass_credential_access.yml` | T1003.001 — LSASS Credential Access | Validated (KQL blocked/documented, SPL clean, real-telemetry for all 3 logic paths) |
| `mshta_suspicious_execution.yml` | T1218.005 — Mshta | KQL blocked/documented, SPL clean, real-telemetry (single-path, no filter blocks) |

## What "validated" means here

A rule isn't marked validated just because it converts cleanly or passes a hand-built test case. For LSASS credential access (T1003.001), every logical path through the rule is backed by real captured telemetry, not synthetic data:

| Path | What it proves | Validated by |
|---|---|---|
| False-negative | Benign background access to LSASS doesn't fire | Real telemetry |
| Suppression | A trusted-source access attempt shaped like a true positive (Task Manager's own dump feature) is correctly excluded | Real telemetry |
| Detection | An untrusted-source malicious access attempt (ProcDump, `PROCESS_ALL_ACCESS`) correctly fires | Real telemetry |

Early in validation, a synthetic test case (`GrantedAccess: 0x1fffff` from `taskmgr.exe`, hand-constructed) confirmed the suppression filter was internally consistent. That's a real result, but it only proves the rule agrees with itself — it doesn't prove the logic holds up against an actual tool. The rule wasn't called fully validated until each path had a real, independently-generated event behind it. Full write-up: [`docs/lsass-case-study.md`](docs/lsass-case-study.md).

## Key cross-platform findings

- **Sentinel/KQL:** conversion can fail silently - a query can convert without error and still never match anything, because Sentinel workspaces ingest Windows Event Logs either raw (unparsed XML) or parsed (queryable Sysmon fields), and that's environment-specific, not something the conversion tooling can infer.
- **Splunk/SPL:** the search-command `IN` operator supports wildcards; the `eval`/`where` `IN()` function does not. Easy to lose wildcard filter behaviour silently when extending a converted query with post-processing.
