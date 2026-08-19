# Detecting LSASS Credential Access with Sigma: Case Study

**Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Data source:** Sysmon Event ID 10 (ProcessAccess)

## The problem

LSASS.exe contains credentials such as NTLM hashes, kerberos tickets and plaintext passwords in memory. Mimikatz-class tools are used by attackers for credential dumping (T1003.001).
- Sysmon Event ID 10 fires an alert when process A opens a handle to the memory of another process (process B). The access rights requested is logged in the GrantedAccess field of the alert. 

This is where the issue is, there are genuine Microsoft binary signed programs and services that request access to lsass such as task manager and antiviruses - there needs to be a rule which can differentiate reputable software from illegitimate software.

## The Rule

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

`GrantedAccess` is how a detection engineer can differentiate between a normal request and a malicious request. The `SourceImage` may not be a inherently suspicious itself but rather the access rights requested - that is what determines malicious intent.     

## Finding 1: Sentinel/KQL Failure

I attempted to convert my sigma rule from YAML into Sentinel/KQL.
Tools: sigma-cli + pysigma-backend-kusto, pipeline azure_monitor_pipeline

Error 1: `Unable to determine table name for category: process_access` the pipeline had no table mapping for this sigma category
I tried fixing this issue by using a custom pipeline and pointing query_table at generic Event table.

Error 2: `Invalid SigmaDetectionItem field name encountered: TargetImage`
Sentinel ingests Windows logs 2 ways - raw (XML dumped into `EventData/ParameterXml`, no named columns) or parsed (DCR extracts fields like `TargetImage` into real columns) 

## Finding 2: Splunk

Command: sigma convert -t splunk -p splunk_windows lsass_credential_access.yml

```
source="WinEventLog:Microsoft-Windows-Sysmon/Operational"
TargetImage="C:\Windows\System32\lsass.exe"
GrantedAccess IN ("0x1010", "0x1410", "0x143a", "0x40", "0x1fffff")
NOT (SourceImage IN ("*\MsMpEng.exe", "C:\Windows\System32\taskmgr.exe"))
```

Why it worked: Splunk's Windows/Sysmon pipeline maps Sigma's neutral field names directly
I found out Splunk has 2 `IN` behaviours: 
- Search-command `IN` supports wildcards
- eval/where IN() function *doesn't* support wildcards - strict equality

The `*\MsMpEng.exe` wildcard only worked because it landed in the search-command `IN` behaviour.


## Finding 3 & 4: Telemetry capture

When i first tried dumping, EID 10 alert was generated in Sysmon: 
- SourceImage: taskmgr.exe
- GrantedAccess: 0x1400 / 0x3200
The rule did not fire an alert correctly since 0x1400 wasn't part of the 5 selection values in my sigma rule. This means selection is False on its own hence never reaches the filters (filter_taskmgr was never reached)

The second time i tried, 
