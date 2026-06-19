# SOC Incident Investigation: Phishing-Induced Account Compromise

## Executive Summary

A suspicious security event was identified involving a user account compromise following a phishing attack.

The investigation determined that the user entered credentials into a malicious website after interacting with a phishing email. The attacker subsequently gained access to the account and attempted further malicious activity.

Immediate containment actions were recommended to reduce further risk.

---

## Incident Overview

| Field | Details |
|---------|---------|
| Incident Type | Phishing / Account Compromise |
| Severity | Medium |
| Status | Resolved |
| Detection Method | Suspicious Login Alert |
| Affected Assets | User Account, Email System |

---

## Incident Flow

```text
Phishing Email
      ↓
User Clicks Link
      ↓
Credential Theft
      ↓
Attacker Login
      ↓
Security Alert
      ↓
Investigation
      ↓
Containment
```

---

## Initial Alert

The incident was identified after a security monitoring system detected an unusual login to a user account.

Indicators included:

- Login from an unfamiliar location
- Login shortly after a phishing email was received
- Unusual account activity following authentication

---

## Timeline of Events

| Time | Event |
|--------|--------|
| 09:00 | User received phishing email |
| 09:05 | User clicked malicious link |
| 09:07 | User entered credentials |
| 09:20 | Attacker authenticated successfully |
| 09:25 | Security alert generated |
| 09:40 | Investigation initiated |
| 10:00 | Account password reset |
| 10:05 | Active sessions terminated |

---

## Indicators of Compromise (IOCs)

- Suspicious sender domain
- Credential harvesting link
- Unusual login location
- Unexpected account activity
- Multiple login attempts from unknown IP addresses

---

## Investigation & Analysis

Analysis determined that the phishing email impersonated a trusted organisation and contained a malicious link designed to steal user credentials.

After the user submitted credentials, the attacker successfully authenticated using the compromised account.

The timing of the suspicious login and the phishing email strongly suggests that credential theft was the initial access vector.

No evidence of malware execution was identified during the investigation.

---

## Impact Assessment

Potential impacts included:

- Unauthorised account access
- Exposure of sensitive information
- Internal phishing attempts
- Reputational damage

The incident was classified as **Medium Severity** because the attacker gained access to a legitimate user account.

---

## Containment Actions

The following actions were taken:

- Password reset initiated
- Existing sessions revoked
- Multi-factor authentication enforced
- Malicious domains blocked
- Users notified of the phishing campaign

---

## Lessons Learned

This incident highlighted the importance of:

- Security awareness training
- Multi-factor authentication (MFA)
- Monitoring unusual login activity
- Rapid reporting of suspicious emails

---

## Recommendations

1. Conduct additional phishing awareness training.
2. Require MFA for all user accounts.
3. Improve monitoring for impossible travel and unusual login locations.
4. Strengthen email filtering controls.
5. Encourage users to report suspicious messages immediately.

---

## Key Skills Demonstrated

`Incident Response`
`Threat Analysis`
`Security Operations`
`Investigation`
`Risk Assessment`
`Cybersecurity`