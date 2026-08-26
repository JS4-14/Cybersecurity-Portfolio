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

I originally used `Image` instead of `OriginalFileName` however realised that an attacker could copy and paste the legitimate mshta.exe then rename it or replace it and it would not be flagged however `OriginalFileName` is a Sysmon field from the PE header's metadata

# Finding 1: Sentinel/KQL
Converting to Sentinel's KQL was successful but the issue was it returned no results because the field names in my sigma rule only work if my workspace parsed raw sysmon XML into columns so it looked like it worked but no results were returned.

# Finding 2: SPL 
Converting to SPL was successful, targeting the right source


