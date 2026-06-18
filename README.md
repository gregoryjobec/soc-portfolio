# SOC Portfolio — Gregory Jobe

Security Analyst II at Ernst & Young (EY), with 1.5+ years of hands-on SOC experience across incident response, threat hunting, and detection engineering.

This repository documents detection rules, SOAR playbook designs, and automation scripts built and refined through daily SOC work — fully sanitized for public sharing (no client data, real IPs, tenant IDs, or production identifiers).

**Stack:** Microsoft Sentinel · Microsoft Defender for Endpoint · Microsoft Entra ID · KQL · Python · PowerShell
**Certifications:** SC-200 (Security Operations Analyst Associate)

---

## What's inside

| Folder | Description |
|---|---|
| [`kql-detection-rules/`](./kql-detection-rules) | KQL queries for identity threats, phishing, BEC, and malware detection in Microsoft Sentinel |
| [`sigma-rules/`](./sigma-rules) | Vendor-neutral Sigma rule conversions of select detections |
| [`soar-playbooks/`](./soar-playbooks) | SOAR automation playbook designs for phishing response and account containment |
| [`ioc-enrichment-script/`](./ioc-enrichment-script) | Python script for automated IOC enrichment via VirusTotal and AbuseIPDB |
| [`writeups/`](./writeups) | Notes and writeups from hands-on security training (TryHackMe, Microsoft Learn) |

---

## Background

I investigate 30-50 security alerts per shift across multi-client enterprise environments at EY, covering malware, phishing, trojans, BEC, and ransomware — from initial triage through containment. I also conduct proactive threat hunting in Microsoft Sentinel and contribute to SIEM detection tuning.

**Connect:** [LinkedIn](https://linkedin.com/in/gregoryjobe) · gregorycheruvathur@gmail.com
