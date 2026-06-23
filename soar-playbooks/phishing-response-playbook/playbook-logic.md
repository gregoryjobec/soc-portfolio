# Phishing response playbook — Logic Apps implementation reference

This document describes the Logic Apps configuration for the phishing response playbook, based on Microsoft Sentinel's standard playbook architecture.

## Connectors used
- **Microsoft Sentinel connector** — trigger ("When Azure Sentinel incident creation rule was triggered")
- **HTTP connector** — used to call the VirusTotal API
- **Microsoft Teams connector** — "Post message in a chat or channel" action
- **Microsoft Sentinel connector** — "Add comment to incident" action

## Step-by-step logic

### 1. Trigger

Trigger: When Azure Sentinel incident creation rule was triggered
Filter: Incident severity >= Medium AND Title contains "Phishing"

### 2. Parse entities
The Sentinel incident trigger provides an `Entities` array. We extract:
- `Account` entity → sender email address
- `URL` entity → suspicious link
- `FileHash` entity → attachment hash (if present)

Initialize variable: SenderEmail = entities('Account')?['Name']
Initialize variable: SuspiciousURL = entities('URL')?['Url']

### 3. Enrich via VirusTotal

HTTP Action:
Method: GET
URI: https://www.virustotal.com/api/v3/urls/{base64-encoded-url}
Headers: x-apikey: <stored securely in Logic App parameters, not hardcoded>

Parse the JSON response to extract:
- `last_analysis_stats.malicious` (count of engines flagging it malicious)
- `last_analysis_stats.harmless`

### 4. Notify Teams

Teams Action: Post message in a channel
Channel: SOC-Alerts

Message:
🚨 Phishing Alert
Sender: @{variables('SenderEmail')}
URL: @{variables('SuspiciousURL')}
VirusTotal malicious score: @{body('HTTP')?['data']?['attributes']?['last_analysis_stats']?['malicious']}
Incident severity: @{triggerBody()?['object']?['properties']?['severity']}

### 5. Comment on incident

Sentinel Action: Add comment to incident
Comment: "Automated enrichment complete — VirusTotal malicious score:
@{body('HTTP')?['data']?['attributes']?['last_analysis_stats']?['malicious']}.
Reviewed by automation at @{utcNow()}."

## Security considerations
- API keys stored in Logic App parameters (encrypted), never hardcoded in the workflow definition
- Logic App uses a system-assigned managed identity scoped to least-privilege permissions on the Sentinel workspace



