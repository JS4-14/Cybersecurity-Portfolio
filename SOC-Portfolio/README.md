# SOC Portfolio

Simulated SOC incident investigations, written to the same standard as a real analyst report — evidence, timeline, ATT&CK mapping, and a defensible conclusion for each.

## Start Here

- **[Investigation Reflections](reflections.md)** — how my investigation methodology and reasoning evolved across all four reports below, including the specific mistakes I made and corrected (confusing IOCs with evidence, jumping to conclusions, generic recommendations). Read this first — it's the clearest evidence of how I actually think, not just what I concluded.

## Investigations

- [Malware Infection](investigations/malware.md) — a user workstation compromised via a spearphishing-delivered executable, resulting in a trojan install and outbound C2-style connections
- [Phishing Incident](investigations/phishing.md) — investigation into a suspicious login flagged from two different locations
- [Unusual Login Activity](investigations/unusual-login.md) — authentication anomaly investigation involving VPN use and failed login attempts
- [Suspicious PowerShell Execution](investigations/PowerShell.md) — a more advanced enterprise attack chain, correlating Sysmon, Windows Event, and DNS logs to trace a PowerShell-based intrusion

Each report follows the same structure: executive summary, incident overview, timeline, evidence and analysis, MITRE ATT&CK mapping, and recommended remediation — the sequence the reflections doc tracks improving across.
