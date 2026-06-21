# SOC Incident Investigation: Phishing Incident

## Executive Summary

A suspicious security event was identified involving **a login from 2 different locations**.

The investigation determined that a user account was likely **compromised following a phishing attack that harvested Microsoft credentials**. This resulted in multiple phishing emails being sent internally.

Immediate containment actions were recommended to reduce further risk.

---

## Incident Overview

| Field | Details |
|--------|---------|
| Incident Type | Phishing |
| Severity | High |
| Status | Contained |
| Detection Method | Monitoring / Alert |
| Affected Assets | User Account, Workstation, Email |

---

## Initial Alert

The incident was identified after:

- Two logins 7 mins apart from 2 different locations from the same account 
- Multiple emails sent internally from same account (Compromised account)

---

## Timeline of Events

| Time | Event |
|------|--------|
| 09:12 | Email Received |
| 09:15 | Link clicked |
| 09:17 | Credentials Entered |
| 09:34 | Login - London |
| 09:41 | Login - Nigeria |
| 09:44 | 27 emails sent internally |

---

## Indicators of Compromise (IOCs)

- Login from the same account minutes apart but in 2 different locations
- Multiple emails outbound from the compromised account

---

## Investigation Notes

### Evidence Supporting Compromise

- Multiple internal emails sent out from the initial affected device 
- Email from microsoft urging users password to be changed 
- 'Verify Account' button which masks the address 

### Alternative Explanations Considered

| Possibility | Reason Ruled Out |
|------------|------------------|
| Potential Trojan | No software or files downloaded |
| [Alternative Explanation] | [Reason] |

---

## Analysis

### What Happened?

1. Employee received email thought to be from microsoft

2. User was told their account password would expire in 24 hours

3. Due to the sense of urgency the user pressed the button

4. Pressing the button opened a replicate Microsoft site

5. The employer entered their details

6. At 9:34 & 9:44 the same account logged in from 2 different countries

7. 9:44: Multiple internal emails sent from employer

### How Was It Detected?

[Explain how the suspicious activity was identified.]

### Why Is It Suspicious?

[Explain the evidence and reasoning.]

### Likely Attacker Objective

- Credential Theft


- Data Exfiltration
- Other

---

## Confidence Assessment

**Confidence Level:** High

**Reason:**

Evidence indicates the attack was a phishing attempt due to the typical phishing signals identified. These were:

 1. Impersonating a company
 2. Sense of urgency to make the user take quick action
 3. 'Verify Now' button which redirects to a site 

---

## Impact Assessment

Potential impacts include:

- Company security breached 
- Confidentiality of data infiltrated 
- Multiple emails exposed

Severity was assessed as **High** because **the adversaries phishing email can easily spread and compromise many employers** and has the potential to reach higher priveliged employers.
The attacker has full access to emails that were accessed hence can view the companies private conversations and gain access to unauthorised information.

---

## Containment Actions

- [Action 1]
- [Action 2]
- [Action 3]
- [Action 4]

---

## Recommendations

1. Train staff to be aware of social engineering and typical signs
2. Always verify any links or buttons 
3. Regularly update passwords and have MFA enabled 

---

## Lessons Learned

The incident highlights the importance of:

- Being aware of the contents of the email and checking it
- Verifying sender address and any links 
- Staff to be regularly trained in order to be aware of phishing attempt and what it generally looks like

---

## MITRE ATT&CK Techniques

| Technique | Description |
|------------|------------|
| [Txxxx] | [Technique Name] |
| [Txxxx] | [Technique Name] |

---

## Reflection and Improvements

### What I Missed Initially

- I focused too heavily on phishing indicators rather than the resulting account compromise.
- Entering credentials does not prove compromise by itself; attacker activity provides stronger evidence.
- The incident should be classified as account compromise caused by phishing rather than simply a phishing attempt.

### What I Learned

- Differentiate between initial access and the resulting incident.
- Distinguish supporting evidence from direct evidence.
- Consider business impact, not just technical indicators.
- Build a complete attack chain when analysing incidents.

---

## Key Skills Demonstrated

`Incident Response` `Threat Analysis` `Investigation` `Security Operations` `Log Analysis` `Risk Assessment`