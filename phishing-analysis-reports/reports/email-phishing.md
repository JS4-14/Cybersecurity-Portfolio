# Threat Analysis Report: Fake American Express Alert


![Fake Email Alert](../images/email-phishing.jpg)

*Figure 1: Example phishing email.*

---

## Summary
This email impersonates Better Business Bureau (BBB) using urgency and a call to action (downloading from link) to pressure the recipient into downloading a document from the link provided.

## Attack Vector
A byt.ly link (allows to mask and shorten original address so users don't see the full domain name) which directs the user to a site where they can download a document.

## Red Flags
1. The sender address, `jrsmith@securitymmgt.com`, does not match BBB.
2. The message uses urgent language to pressure the user into acting quickly.
3. The link is a Bit.ly link which masks the original address hence users will naturally click it since it looks harmless.
4. The email contains grammar issues that reduces credibility.

## What Failed
- Sender address does not match the brand being impersonated.
- The message relies on urgency rather than legitimate communication.
- The email contains wording issues that are inconsistent with a professional institution.

## Indicators of Compromise
- Suspicious sender domain: `jrsmith@securitymmgt.com`
- Brand impersonation: Better Business Bureau
- Phishing urgency ("within 24 hours to us")
- Potential malicious link

## Detection Ideas

- SPF, DKIM and DMARC validation
- Lookalike domain detection
- URL scanning (VirusTotal) and sandboxing
- User reporting

## Mitigation
- Train staff to inspect sender domains carefully
- Hover over links before clicking
- Use MFA to reduce the impact of stolen credentials
- Report suspicious emails to security teams
- Block impersonation domains at the mail gateway

## Key Takeaways
Phishing emails often succeed by combining urgency with brand impersonation. Careful inspection of the sender domain and link destination is often enough to reveal the attack.

Phishing succeeds because users focus on the urgency of the message.

