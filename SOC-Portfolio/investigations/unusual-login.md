# SOC Incident Investigation: Unusual Login Activity

## Executive Summary

A suspicious security event was identified involving **unusual authentication activity with VPN use and failed login attemtps**.

The investigation determined that **a third party succesfully authenticated to Microsoft 365 and established a PowerShell remote session leading to a SOC alert**.

Immediate containment actions were recommended to reduce further risk.

---

## Incident Overview

| Field | Details |
|--------|---------|
| Incident Type | Unusual Login Activity |
| Severity | Medium |
| Status | Open |
| Detection Method | SIEM Dashboard |
| Affected Assets | User Account, HR-LAPTOP-014 |

---

## Initial Alert

The incident was identified after:

- Three failed SMB logons to FS-01
- Payroll.zip created
- Outbound HTTPS - Destination was to unknown IP Address and unknown country

---

## Timeline of Events

| Time | Event |
|------|--------|
| 08:11 | Successful VPN login from Manchester, UK |
| 08:18 | Successful Microsoft 365 authentication |
| 08:34 | Successful authentication to HR-APP01 |
| 08:36 | PowerShell Remoting session established |
|  08:39 | Three failed SMB logons to FS-01 |
|  08:40 | Successful SMB authentication to FS-01 | 
|  08:45 | Payroll.zip created |
|  08:46 | Alert generated |

---

## Indicators of Compromise (IOCs)

- Successful SMB authentication to FS-01 after 3 failed attempts 
- Based on Endpoint Activity, PowerShell Remote initiated and a WinRM Session created with the destination to FS-01, a device not typically connected too
- Authentication log: Payroll.zip created after connecting to FS-01

---

## Investigation Notes

### Evidence Supporting Compromise

- Based on the users typical login history, there is no prior authentication to FS-01, only to the users device (HR-LAPTOP-014/HR-APP01)
- Network activity shows that the created file, payroll.zip was sent to a unknown device
- User stated they logged in and opened some payroll documents however their device connected to another

### Alternative Explanations Considered

| Possibility | Reason Ruled Out |
|------------|------------------|
| Malware | Endpoint Protection indicates no malware was detected |
| Form of Trojan or phishing | Antivirus did not generate an alert indicating it was not a form of malware or virus |

---

## Analysis

### What Happened?

[User Statement: "I logged in this morning like normal and opened some payroll documents. I wasn't aware anything unusual happened." ] 
The authentication logs indicate that there was a login from Manchester with a VPN, followed by a successful Microsoft 365 authentication. 
There was then a connection to the users laptop and a PowerShell session established.
Logs caught 3 failed attempts to the unknown device - FS-01 until a connection was finally established.
Payroll.zip was created and the SIEM alert was then generated.

### How Was It Detected?

Detection was primiarly due to the SIEM alert with inidicators also being observed in the login history, endpoint activity, file activity and network activity which all potentiallly contributed to the alert being generated.
Other evidence could include Firewall logs, Sysmon logs and Active Directory Audit logs.

### Why Is It Suspicious?

[Explain the evidence and reasoning.]

### Likely Attacker Objective

- [Credential Theft]
- [Malware Delivery]
- [Persistence]
- [Privilege Escalation]
- [Data Exfiltration]
- [Lateral Movement]
- [Other]

---

## Confidence Assessment

**Confidence Level:** [High / Medium / Low]

**Reason:**

[Explain how confident you are in your findings and identify any assumptions.]

---

## Impact Assessment

Potential impacts include:

- [Impact 1]
- [Impact 2]
- [Impact 3]

Severity was assessed as **[Low / Medium / High / Critical]** because **[reason]**.

---

## Containment Actions

- [Action 1]
- [Action 2]
- [Action 3]
- [Action 4]

---

## Recommendations

1. [Recommendation 1]
2. [Recommendation 2]
3. [Recommendation 3]
4. [Recommendation 4]

---

## Lessons Learned

The incident highlights the importance of:

- [Lesson 1]
- [Lesson 2]
- [Lesson 3]

---

## MITRE ATT&CK Techniques

| Technique | Description |
|------------|------------|
| [Txxxx] | [Technique Name] |
| [Txxxx] | [Technique Name] |

---

## Evidence

### Screenshot(s)

![Investigation Evidence](../images/example.png)

*Figure 1: [Description of evidence]*

---

## Key Skills Demonstrated

`Incident Response` `Threat Analysis` `Investigation` `Security Operations` `Log Analysis` `Risk Assessment`
