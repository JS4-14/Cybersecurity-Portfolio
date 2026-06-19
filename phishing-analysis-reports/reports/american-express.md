# Threat Analysis Report: Fake American Express Alert

## Summary

An American Express email sent with various indicators proving its a phishing email. The email incorporates a sense of urgency which many users could fall for and follow any links or download any files without checking the contents of the email (in this case, a link disguised as a button).

------

## Attack Vector

A blue "review your account" button which leads to a fake, malicious website.

------

## Red Flags

1. The first sign that the email is fake is the senders address (administraciones@pentagon-seguridad.cl) - this has no relation to American Express hence showing indications of phishing.

2. Another sign the email could be fake and malicious is not noticed by many but those aware of phishing can spot it.

In the email it says "with us now on 11/872019 10.28:38 AM To continue using"
This is a sign of phishing, typically used in emails to create a sense of urgency to force the user to act quickly, paying no attention to the actual contents of the email.

3. The third sign is the first thing a user would see - the big blue button which would redirect the user to another site. 
The site would be malicious, storing the details the user would submit provided they don't check the email.

------

## What Failed

Senders email visible and unrelated to American Express hence a user could become wary of the email.

Spelling mistake made in the email - until spelt "untill". A large company like American Express would not make a grammar mistake like that.

## Indicators of Compromise

- Sender domain: pentagon-seguridad.cl

- Brand mismatch: sender does not match American Express

- Urgent language: temporary suspension / verify now

- Call To Action (Urgency): “review your account now” button

- Grammar/spelling issues

------

## Detection Ideas

If on a company pc, have software which checks grammar in an email or integrated as part of the antivirus. The contents of the email could be read provided permission granted and AI can determine if its real based on the contents.

------

## Mitigation

Train staff to look out for signs like grammar mistakes, sense of urgency and if the sender email appears to match the company or emails of the company branches e.g. Support@AmericanExpress. 
If there are emails with links, staff can be taught to hover over the button or link to see its full domain name and check it matches - they can also copy the link address and paste it into VirusTotal.

------

## Key Takeaways

Phishing emails can sometimes be hard to spot especially when the email creates a sense of urgency making the user act quickly.

![Fake American Express Alert](../images/american-express.png)