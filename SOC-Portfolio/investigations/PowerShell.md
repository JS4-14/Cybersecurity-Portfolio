# SOC Incident Investigation: Suspicious PowerShell Execution

## Executive Summary

A suspicious security event was identified involving **Suspicious PowerShell activity with a series of executable files executed based on Sysmon logs, Windows Event logs and DNS logs**.

The investigation determined that **the adversary used a complex and hard to identify attack by using the system itself**.

Immediate containment actions were recommended to reduce further risk.

---

## Incident Overview

| Field | Details |
|--------|---------|
| Incident Type | PowerShell Activity |
| Severity | Medium |
| Status | New |
| Detection Method | Endpoint Alert |
| Affected Assets | device: FINANCE-PC-O22, user: mturner |

---

## Initial Alert

The incident was identified after:

- Sysmon Events - multiple events identified 
- Windows Security Logs - multiple events 
- DNS and Firewall Logs

---

## Timeline of Events

| Time | Event |
|------|--------|
| 09:02 | Email received |
| 09:04 | Word document opened |
| 09:05 | WINWORD.EXE spawned PowerShell |
| 09:05 | Encoded PowerShell executed |
| 09:05 | Network connection established |
| 09:06 | Registry Run key modified |  
| 09:07 | File update.ps1 created |
| 09:09 | Alert generated |

---

## Indicators of Compromise (IOCs)

- Based on the email, the user received an attachment appearing to be their payment schedule however the attachment was a .docm filetype. This is the first IOC since a .docm filetype has macro support which means it allows the creator to execute code - .docm are common vectors for malware and viruses.
The attackers goal could have been to infiltrate the system with an unsuspecting word doc file and execute several commands whether its to exfiltrate data, lateral movement or privilege escalation.
- The Firewall Logs also exposes an IOC, there was an outbound HTTPS connection allowed to an unknown IP destination on port 443.
  Here the attackers goal could have been to transmit data from the affected device to their personal device or alternate device (ransom or sell the data).
- Endpoint Protection generated a behaviour based detection alert. This means the system identified an activity or pattern that significantly deviates from the established "normal" behaviour of the user / device.
- EDR timeline shows that update.ps1 was created, this is a Windows Powershell Script file indicating compromise since Event ID 4104 of the Windows Security Logs shows "Invoke-WebRequest", this is typical behaviour of .ps1 files where they attempt to download files from the internet (Invoke-WebRequest).
This file type is a primary vector for cyber attacks and this is a potential probable cause of the behaviour based detection, the attacker potentially wants to run a malicious script or an automated script to scrape for data or execute certain tasks.

---

## Investigation Notes

### Evidence Supporting Compromise

- Once the .ps1 file was created, there was a Windows Security Log, Event ID 4104 which proves the adversary broke into the device using PowerShell (a trusted program) to avoid detection.
DownloadString retrieved remote PowerShell code, while Invoke-Expression executed it directly in memory without writing a traditional executable to the disk. Those instructions were than ran in memory.
- The senders address is "finance-notification@invoice-review.com", this address is basic (templated to invoice) and untrustworthy since it does not include the company name or department name or any personalisation which can indicate the email is potentially coming from outside the company since its a generic address to try persuade the user its invoice related. The user also mentioned the file asked to enable editing to *view* the content however the contents of word files can be viewed *without needing to enable editing* since they are two different operations - this shows suspicious activity going on 
- There was a registry run key modified. 

### Alternative Explanations Considered

| Possibility | Reason Ruled Out |
|------------|------------------|
| Ransomware | No ransom note, no encryption |
| Standard Phishing | PowerShell was used for the attack through the .docm file the user opened. This cannot be phishing since a trusted program was used for the attack rather than trying to obtain credentials through fake links, this is more likely to be a malware attack |

---

## Analysis

### What Happened?

The user received an email with a supposed "invoice" .docm attachment. The user enabled permissions and shortly after PowerShell started and executed, establishing a network connection likely from the instructions  within the .exe file of .docm. All logs indicate multiple events occuring in cohesion which means all the events are related. The attacker had hidden code which executed once the file had editing permissions consequently causing instructions to be downloaded and ran on the device itself under the radar (Start-Sleep), there was then DNS lookups and connections being made as observed in the Firewall Logs

### How Was It Detected?

The attack was detected by Endpoint Protection when a behaviour-based detection was generated which signifies suspicious and irregular behaviour patterns were occurring on the affected device where these events would not happen if the device/user behaviour was normal.

### Why Is It Suspicious?

What made the event suspicious was the editing permissions being asked to view content, then multiple logs being observed

### Likely Attacker Objective


- Malware
- Privilege Escalation
- Data Exfiltration
- Lateral Movement

---

## Confidence Assessment

**Confidence Level:** [High / Medium / Low]

**Reason:**

[Explain how confident you are in your findings and identify any assumptions.]

---

## Impact Assessment

Potential impacts include:

- Data exfiltration - private data was accessed through the victims device and transmitted to another device/IP for personal or financial gain
- [Impact 2]
- [Impact 3]

Severity was assessed as **[Low / Medium / High / Critical]** because **[reason]**.

---

## Containment Actions

- Block outbound connections
- Terminate the powershell session
- [Action 3]
- [Action 4]

---

## Recommendations

1. Enforce Principle of Least Privilege, this happened because PowerShell did not have any restrictions 
2. Weak Firewall rules - Enforce outbound and inbound connections whether its allowlisting user devices only or blocklisting unknown IP addresses
3. Train staff to identify any signs of suspicious emails by checking the senders address and checking any attachments with VirusTotal or with peers

---

## Lessons Learned

The incident highlights the importance of:

- Ensuring applications, programs and processes be granted the minimum level of access necessary to perform their specific functions. This greatly reduces the attack surface.
- Knowing how to identify and determine whether or not emails are safe, trusted and expected.

---

## MITRE ATT&CK Techniques

| Technique | Description |
|------------|------------|
| T1566.001 | Spearphishing Attachment - The adversary sends a targeted email containing the .docm file as an attachment to trick the user |
| T1204.002 | User Execution: Malicious File - The attack relies on a human clicking the file and manually clicking "Enable Editing" to bypass Microsoft Office's default security blocks |

---

## Key Skills Demonstrated

`Incident Response` `Threat Analysis` `Investigation` `Security Operations` `Log Analysis` `Risk Assessment`
