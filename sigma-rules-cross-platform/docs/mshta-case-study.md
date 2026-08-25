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
