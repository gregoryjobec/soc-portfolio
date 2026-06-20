# Sigma rules

Vendor-neutral Sigma rule conversions written to demonstrate detection logic that's portable across SIEM platforms, not just Microsoft Sentinel.

Validated using [Uncoder.io](https://uncoder.io) — each rule below converts cleanly to a working native query.

| Rule | Converted from | MITRE ATT&CK | Converts to |
|---|---|---|---|
| [mailbox-rule-creation-bec.yml](./mailbox-rule-creation-bec.yml) | 04-mass-mailbox-rule-creation-bec.kql | T1114.003 | Microsoft Sentinel (KQL) |

## A note on Sigma's aggregation limitations

Sigma's `detection` block is intentionally simpler than full KQL — it's designed for portable, declarative pattern matching, not complex stateful aggregation (time-windowed grouping, joins, etc.). Detections that rely on this kind of logic — such as impossible travel correlation or MFA-bypass-by-failure-count — are better expressed natively in the SIEM's own query language, where the corresponding KQL rules in [`../kql-detection-rules/`](../kql-detection-rules) implement the full logic. This repo includes one Sigma rule that's well-suited to Sigma's strengths (simple field/keyword matching) to demonstrate a complete, working conversion.
