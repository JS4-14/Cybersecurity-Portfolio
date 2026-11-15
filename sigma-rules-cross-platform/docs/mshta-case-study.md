# Detecting Suspicious Mshta Execution with Sigma

**Technique:** T1218.005 · **Source:** Sysmon EID 1

## The problem
Mshta is the executable for the Microsoft HTML Application Host - its a legitimate, signed binary used to run HTML Applications outside of a browser. 
It being a legitimate utility is the issue, attackers will use it as a LOLBin since its a trusted program on every Windows device so easier to infiltrate through as opposed to writing custom software which Windows will not recognise.

Used to proxy malicious code execution by invoking URL requests and scripts.

## The rule

```yaml
logsource:
    service: sysmon
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName: MSHTA.EXE
        CommandLine|contains:
            - "http://"
            - "https://"
            - "vbscript:"
            - "javascript:"
            - "about:"
    condition: selection
falsepositives:
    - None known
level: high
```

## Decisions
I did not include any filter since I determined that there are no apps which need to invoke a URL request or scripts through mshta, this is not normal behaviour seen by apps or users hence it would only occur if there was an adversary with an ulterior goal - there is no legitimate caller.

I originally used `Image` instead of `OriginalFileName` (Image: C:\Windows\System32\mshta.exe) but this can be overcome by copying mshta.exe to a different location whereas `OriginalFileName` is a field which reads the PE metadata of mshta.exe rather than the file path so attackers can't simply rename and save it elsewhere. 

# Finding 1: Sentinel/KQL
- LSASS's `process_access` category has no mapping in the pipeline (`azure_monitor_pipeline`) i used, so the deployment had errors. 
- Mshta had an issue with conversion but it was a silent failure, it converted. The issue was `process_creation` had a wrong table match - sigma convert successfully converted but produced KQL for `SecurityEvent (EID 4688)` which is windows' in built Security Auditing whereas my home lab used Sysmon hence it mapped to an entirely different table (SecurityEvent instead of Sysmon's).
- The pipeline (`azure_monitor_pipeline`) has a built in mapping for `process_creation` (maps to SecurityEvent) where Windows Security Auditing is enabled so it chose that automatically, having not known my lab only has Sysmon.
- This was a silent error because the pipeline worked - SecurityEvent is a table in many environments, the mismatch was with my lab (I had Sysmon only and `Windows Security Auditing` wasn't enabled) but `sigma-cli` could not know that - it just converted.

`SecurityEvent
| where NewProcessName =~ "C:\\Windows\\System32\\mshta.exe" and (CommandLine contains "http://" or CommandLine contains "https://" or CommandLine contains "vbscript:" or CommandLine contains "javascript:" or CommandLine contains "about:")`

The mshta issue is worse than LSASS since the person who deployed the mshta conversion would assume it was successful with coverage on any attempts since there were no errors however it would return no alerts or results.


# Finding 2: SPL 
Converting to SPL was successful, targeting the right source.
The converted query used wildcards in the `IN` operator - Splunk's search command `IN` supports wildcards.


# Finding 3: CommandLine
`mshta.exe about:"<script language=\"vbscript\">CreateObject(\"Wscript.Shell\").Run \"calc.exe\":window.close</script>"`
`"C:\WINDOWS\system32\mshta.exe" "about:<script language=\vbscript\>CreateObject(\Wscript.Shell\).Run \calc.exe\:window.close</script>"`

- `CommandLine|contains` is a literal string check, the payload has \vbscript\ - no ':' which is why 'vbscript:' will never match. 
This means a rule with 'vbscript' is not flagged.
- This shows a rule relying only on vbscript: as a selection value would have missed this payload - `about:` is what actually catches VBScript.

