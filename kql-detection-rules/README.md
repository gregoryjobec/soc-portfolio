# KQL detection rules

A collection of Microsoft Sentinel KQL queries built and refined through SOC analyst work — covering identity threats, phishing, BEC, and malware detection.

All queries are fully sanitized — no client names, real IPs, tenant IDs, or production data.

| Rule | MITRE ATT&CK | Detects |
|---|---|---|
| 01-suspicious-signin-impossible-travel.kql | T1078 | Geographically impossible sign-ins |
| 02-mfa-bypass-detection.kql | T1556 | MFA bypass attempts |
| 03-phishing-url-click-correlation.kql | T1566 | Phishing link clicks correlated to mailbox events |
