# SOC Incident Investigation: [Incident Name]

## Executive Summary

A suspicious security event was identified involving **[brief description]**.

The investigation determined that **[finding]**.

Immediate containment actions were recommended to reduce further risk.

---

## Incident Overview

| Field | Details |
|---------|---------|
| Incident Type | Phishing / Account Compromise / Malware |
| Severity | Low / Medium / High |
| Status | Resolved |
| Detection Method | User Report / Alert / Monitoring |
| Affected Assets | User Account, Laptop, Email System |

---

## Initial Alert

The incident was identified after:

- Suspicious login detected
- User reported unusual activity
- Security alert triggered

---

## Timeline of Events

| Time | Event |
|--------|--------|
| 09:00 | User received phishing email |
| 09:05 | User clicked malicious link |
| 09:07 | Credentials entered |
| 09:20 | Attacker login observed |
| 09:25 | Alert generated |
| 09:40 | Investigation initiated |

---

## Indicators of Compromise (IOCs)

- Suspicious sender domain
- Unusual login location
- Multiple failed login attempts
- Unexpected outbound emails

---

## Analysis

The phishing email impersonated a trusted service and persuaded the user to enter credentials.

Following credential theft, an attacker successfully authenticated using the compromised account.

The unusual login location and subsequent email activity indicate likely account compromise.

---

## Impact Assessment

Potential impacts include:

- Account compromise
- Data exposure
- Internal phishing propagation
- Reputational damage

Severity was assessed as **Medium** due to successful account access.

---

## Containment Actions

- Password reset
- Session revocation
- MFA enforcement
- Block malicious domains
- Notify affected users

---

## Lessons Learned

The incident highlights the importance of:

- Security awareness training
- Multi-factor authentication
- Email filtering controls
- Monitoring for anomalous logins

---

## Recommendations

1. Improve phishing awareness training.
2. Enable MFA for all users.
3. Monitor unusual login locations.
4. Strengthen email security controls.

---

## Key Skills Demonstrated

`Incident Response` `Threat Analysis` `Investigation` `Security Operations` `Risk Assessment`