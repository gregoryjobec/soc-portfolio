# KQL detection rules

A collection of Microsoft Sentinel KQL queries built through SOC analyst work — covering identity threats, phishing, BEC, and malware detection.

All queries are fully sanitized — no client names, real IPs, tenant IDs, or production data. Table and field names reflect standard Microsoft Sentinel / Defender schemas.

| Rule | MITRE ATT&CK | Detects |
|---|---|---|
| [01-suspicious-signin-impossible-travel.kql](./01-suspicious-signin-impossible-travel.kql) | T1078 — Valid Accounts | Geographically impossible sign-ins within a short time window |
| [02-mfa-bypass-detection.kql](./02-mfa-bypass-detection.kql) | T1556 — Modify Authentication Process | Repeated MFA failures followed by a successful sign-in |
| [03-phishing-url-click-correlation.kql](./03-phishing-url-click-correlation.kql) | T1566 — Phishing | Correlates email link clicks with subsequent suspicious sign-in or process activity |
| [04-mass-mailbox-rule-creation-bec.kql](./04-mass-mailbox-rule-creation-bec.kql) | T1114.003 — Email Forwarding Rule | Detects mailbox rule creation often used in BEC to hide or auto-forward emails |
| [05-suspicious-process-from-office-app.kql](./05-suspicious-process-from-office-app.kql) | T1204.002 — Malicious File | Detects suspicious child processes spawned from Office applications, common in malware/trojan delivery |
