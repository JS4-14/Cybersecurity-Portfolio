# SOC Investigation Reflections

This document records how my investigation methodology has evolved across each simulated SOC incident. The aim is not only to improve technical knowledge, but to improve the reasoning process used during incident investigations.

---

# Report 1 — Phishing

## New Concepts

- Discovered the MITRE ATT&CK framework and began using it to classify attacker behaviour.
- Learned that an incident report should explain why evidence matters, not simply list observations.

## Initial Weaknesses

- Focused mainly on describing events.
- Jumped to conclusions without clearly separating observations from assumptions.
- Had limited understanding of how analysts justify confidence levels.

## Key Takeaway

A SOC report should explain **why** evidence supports a conclusion, not simply describe what happened.

---

# Report 2 — Malware

## Improvements

- Began analysing attack progression rather than isolated events.
- Started considering alternative explanations before reaching a conclusion.
- Incorporated ATT&CK mappings more naturally.

## Mistakes

- Confused Indicators of Compromise (IOCs) with investigation evidence.
- Sometimes stated conclusions that were not fully supported.
- Recommendations were often generic rather than directly addressing root causes.

## What I Learned

Evidence answers:

> "Why do I believe this?"

IOCs answer:

> "What could another analyst search for?"

Those are different purposes.

## Skills To Improve

- Confidence assessment
- ATT&CK mapping
- Evidence evaluation
- Root-cause based recommendations

---

# Report 3 — Unusual Login Activity

## Improvements

- Began correlating multiple log sources instead of analysing events individually.
- Started identifying which events were actually significant.
- Considered alternative hypotheses before selecting the most likely explanation.

## Mistakes

- Treated every event as equally important.
- Still occasionally assumed attacker involvement before sufficient evidence existed.
- Needed stronger reasoning linking authentication events together.

## Key Takeaway

Not every log entry matters equally.

The analyst's job is identifying which events change the understanding of the incident.

---

# Report 4 — Suspicious PowerShell Execution

## Improvements

- Investigated a significantly more realistic enterprise attack chain.
- Considered attacker techniques such as LOLBins, PowerShell abuse and in-memory execution.
- Began relating endpoint, Windows, Sysmon and network telemetry together.

## Mistakes

- Relied on internet research to understand unfamiliar PowerShell behaviour.
- Sometimes explained technical concepts incorrectly.
- Included assumptions that extended beyond available evidence.
- Recommendations occasionally focused on symptoms instead of preventing the attack chain.

## Key Takeaway

The hardest part of SOC work is not recognising malicious activity.

It is understanding exactly what the evidence proves—and equally importantly—what it does **not** prove.

---

# Overall Development

Across these investigations I noticed my thinking change from:

Describe events

↓

Interpret evidence

↓

Evaluate competing explanations

↓

Build evidence-supported conclusions

I still have significant room for improvement, particularly in enterprise Windows environments, PowerShell abuse, Active Directory and detection engineering, but these reports have shown me where those gaps exist.

---

# Questions I Continue Asking During Every Investigation

- What actually happened?
- What evidence proves that?
- What assumptions am I making?
- What alternative explanations exist?
- What evidence would increase or decrease my confidence?
- What would I investigate next if I had access to the SIEM or EDR?
- Which ATT&CK techniques best explain the observed behaviour?
- How would I prevent this attack from succeeding again?

These questions now guide every investigation I perform.
