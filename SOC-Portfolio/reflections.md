# SOC REPORT 1: PHISHING


## New Concepts Learned

### MITRE ATT&CK Framework

While researching this incident, I discovered the MITRE ATT&CK framework, which provides a standardised way of categorising attacker techniques and behaviours.

I used ATT&CK mappings to understand how phishing attacks progress from initial access to account compromise.



# SOC REPORT 2: MALWARE

## What I Did Well

- Included MITRE ATT&CK - previously i was unaware of the concept during the Phishing report writeup
- Started to think about the chain of events rather than stating what happened
- Started to think about potential alternative possibilities compared to report 1 (phishing)

---

## Mistakes I Made

- I confuse IOCs with evidence. Not everything observed is an IOC - detection events indicate something happened whereas IOCs are things other analysts could search for
- Stated something occured despite the evidence not fully supporting / not substantial
- I still describe events rather than explaining why events matter - an analyst explains that 

---

## What I Learnt

- Recommendations should prevent recurrence so I cannot include vague things such as "train staff" but rather "Implement Firewall rules allowlisting certain IPs" etc.
- No assumptions, i should identify.
- My reports would be better with more analyst thinking - i need to ask myself questions to help build a high quality report

---

## How I Would Investigate This Differently Next Time

- Ask myself questions to develop my reasoning rather than stating the obvious and describing whats already known
- Ensure i understand the difference between evidence and IOCs
- Not assuming and avoiding certainty unless supported as a SOC analyst would

---

## Skills To Improve

- MITRE ATT&CK mapping
- Confidence assessment
- Distinguishing observations from evidence

---

## Analyst Questions

- What does this tell me?
- Could there be a legitimate explanation?
- What evidence would strengthen or weaken my conclusion?
- What would I search for next if I had access to the SIEM or EDR?
- What action would I take immediately, and why?

## Questions to research

- How does Microsoft Defender detect malware?
- What is EDR and how does it differ from antivirus?
- How does reputation scoring work?
- How does PowerShell execute malicious payloads?
- What happens after malware establishes persistence?




# SOC REPORT 3: UNUSUAL LOGIN ACTIVITY

## What I did well

- Compared to Report 2:
    
    - I looked at multiple sources of evidence instead of only focusing on one 
    - I started to consider logs anf determining their implications 
    
---

## Mistakes I Made

- I treated every event equally rather than asking myself which events changed my understanding of the incident 
- I slipped back into conclusions mentioning a 
3rd party 
- I drew to a conclusion to quick when it came to Alternate Explanations, ruling out too quick


