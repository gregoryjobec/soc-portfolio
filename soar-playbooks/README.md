# SOAR playbooks

Documented SOAR automation playbook designs for Microsoft Sentinel, built on adapted Microsoft official playbook templates and Logic Apps architecture.

| Playbook | Trigger | Action | MITRE ATT&CK |
|---|---|---|---|
| [phishing-response-playbook](./phishing-response-playbook) | Phishing incident created | Extract IOCs, enrich via VirusTotal, notify Teams channel, comment on incident | T1566 |
| [account-disable-playbook](./account-disable-playbook) | Suspicious sign-in incident created | Disable Entra ID account, notify SOC team, comment on incident | T1078 |
