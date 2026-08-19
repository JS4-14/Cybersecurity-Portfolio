# Detecting LSASS Credential Access with Sigma: Case Study

**Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Data source:** Sysmon Event ID 10 (ProcessAccess)

## The problem

LSASS (`lsass.exe`) holds live credential material in memory - NTLM hashes, Kerberos tickets - making it a primary target for tools like Mimikatz. Sysmon's Event ID 10 logs every process that opens a handle to another process, including the specific access rights requested. That's enough to detect credential dumping, but only if the detection logic correctly separates malicious access attempts from the legitimate ones that also touch LSASS (AV/EDR agents, Task Manager).
The program itself is not necessarily malicious but the access rights requested/granted.

## The rule

```yaml
logsource:
  product: windows
  category: process_access
detection:
  selection:
    TargetImage: 'C:\Windows\System32\lsass.exe'
    GrantedAccess:
      - '0x1010'
      - '0x1410'
      - '0x143a'
      - '0x40'
      - '0x1fffff'
  filter_defender:
    SourceImage|endswith: '\MsMpEng.exe'
  filter_taskmgr:
    SourceImage: 'C:\Windows\System32\taskmgr.exe'
  condition: selection and not (filter_defender or filter_taskmgr)
```

`GrantedAccess` values are access-rights bitmasks, not arbitrary IDs - `0x1fffff` (`PROCESS_ALL_ACCESS`) is the broadest and most suspicious; the others are narrower but still credential dumping combinations.

## Finding 1: Portability breaks, not query syntax

Converting to Sentinel/KQL (`sigma-cli` + `pysigma-backend-kusto`, `azure_monitor_pipeline`) failed twice:

1. `Unable to determine table name for category: process_access` - the pipeline has no built-in table mapping for this Sigma category.
2. After supplying a custom pipeline pointing at the generic `Event` table: `Invalid SigmaDetectionItem field name encountered: TargetImage` - only generic unparsed columns (`EventData`, `ParameterXml`) were available.

**Root cause:** Sentinel/Log Analytics can ingest Windows Event Logs two structurally different ways - **raw** (full XML dumped unparsed into `EventData`/`ParameterXml`) or **parsed** (a purpose-built DCR extracts fields like `TargetImage`/`GrantedAccess` into real columns). 
A Sigma rule using Sysmon-native field names only converts into a working query against the parsed path - and which path a given workspace uses is environment-specific, not something the conversion tooling can infer.

## Finding 2: clean Splunk conversion, subtler gotcha

```
sigma convert -t splunk -p splunk_windows lsass_credential_access.yml
```source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
TargetImage="C:\Windows\System32\lsass.exe"
GrantedAccess IN ("0x1010", "0x1410", "0x143a", "0x40", "0x1fffff")
NOT (SourceImage IN ("*\MsMpEng.exe", "C:\Windows\System32\taskmgr.exe"))
```


Clean conversion - Splunk's Windows/Sysmon pipeline maps neutral Sigma field names directly, avoiding the raw-vs-parsed problem entirely.

But: Splunk has two different `IN` behaviors. The bare search-command `IN` operator (used above) supports wildcards; the `eval`/`where` `IN()` *function* does not - strict equality only. The converted query uses the search-command form, so `"*\MsMpEng.exe"` correctly preserves the original `endswith` semantics - but the same string dropped into a post-processing `|eval` or `|where` clause would silently stop matching.

## Finding 3: a passing test isn't proof the logic works

A real captured event (`SourceImage: taskmgr.exe`, `GrantedAccess: 0x1400`) correctly didn't trigger the rule - but tracing the logic showed why: `0x1400` isn't in the `selection` list, so `selection` was already `False`, short-circuiting the `AND` before `filter_taskmgr` was ever reached. The filter was never exercised.

A synthetic event was constructed to actually test it: `GrantedAccess: 0x1fffff` (in the selection list) + `SourceImage: taskmgr.exe`. Trace: `selection` → `True`, `SourceImage IN (...)` → `True`, `NOT(...)` → `False`, `True AND False` → **`False`, correctly suppressed.** This confirmed `filter_taskmgr` actually works.

## Takeaways

- Vendor-neutral detection logic decouples *what* you're detecting from *how* a SIEM stores it - but field-mapping and ingestion-shape assumptions are backend-specific and must be verified, not assumed.
- "Converted without error" and "works" are different claims.
- A test case that passes for the wrong reason is worse than no test - it looks like coverage without providing any.
