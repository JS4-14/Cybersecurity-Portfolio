# Detecting LSASS Credential Access with Sigma: Case Study

**Technique:** T1003.001 (OS Credential Dumping: LSASS Memory)
**Data source:** Sysmon Event ID 10 (ProcessAccess)

## The problem
LSASS.exe contains credentials such as NTLM hashes, kerberos tickets and plaintext passwords in memory. Mimikatz-class tools are used by attackers for credential dumping (T1003.001).
Sysmon Event ID 10 fires an alert when process A opens a handle to the memory of another process (process B). The access rights requested is logged in the GrantedAccess field of the alert. 
This is where the issue is, there are genuine Microsoft binary signed programs and services that request access to lsass such as task manager and antiviruses - there needs to be a rule which can differentiate reputable software from illegitimate software.

## The Rule
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
