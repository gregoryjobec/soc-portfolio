# Sigma rules

Vendor-neutral Sigma rule conversions of select detections from the KQL folder — written to demonstrate detection logic that's portable across SIEM platforms, not just Microsoft Sentinel.

Validated using the [Sigma online converter](https://sigconverter.io/).

| Rule | Converted from | MITRE ATT&CK |
|---|---|---|
| [suspicious-signin-impossible-travel.yml](./suspicious-signin-impossible-travel.yml) | 01-suspicious-signin-impossible-travel.kql | T1078 |
| [mfa-bypass-detection.yml](./mfa-bypass-detection.yml) | 02-mfa-bypass-detection.kql | T1556 |
| [mailbox-rule-creation-bec.yml](./mailbox-rule-creation-bec.yml) | 04-mass-mailbox-rule-creation-bec.kql | T1114.003 |
