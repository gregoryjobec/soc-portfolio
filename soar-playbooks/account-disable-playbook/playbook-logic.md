# Account containment playbook — Logic Apps implementation reference

This document describes the Logic Apps configuration for the account containment playbook, based on Microsoft Sentinel's standard playbook architecture.

## Connectors used
- **Microsoft Sentinel connector** — trigger ("When Azure Sentinel incident creation rule was triggered")
- **HTTP connector** — used to call Microsoft Graph API for user lookup and account disable
- **Microsoft Teams connector** — "Post message in a chat or channel" action
- **Microsoft Sentinel connector** — "Add comment to incident" action

## Step-by-step logic

### 1. Trigger
```
Trigger: When Azure Sentinel incident creation rule was triggered

Filter: Incident severity >= Medium AND (Title contains "Impossible Travel" OR Title contains "Suspicious Sign-In")
```

### 2. Parse entities
The Sentinel incident trigger provides an `Entities` array. We extract:
- `Account` entity → affected user account UPN
```
Initialize variable: UPN = entities('Account')?['Name']
```

### 3. Lookup user object
Retrieve the full user object from Microsoft Entra ID so we can modify it:
```
HTTP Action:

Method: GET

URI: https://graph.microsoft.com/v1.0/users/@{variables('UPN')}

Headers: Authorization: Bearer <managed identity token>
```
Store the returned user object:
```
Initialize variable: UserObject = body('HTTP')
```

### 4. Contain — disable account
Send a PATCH request to set `accountEnabled` to false, immediately disabling the compromised account:
```
HTTP Action (Disable Account):

Method: PATCH

URI: https://graph.microsoft.com/v1.0/users/@{variables('UPN')}

Headers: Authorization: Bearer <managed identity token>

Body:

{

"accountEnabled": false

}
```

### 5. Notify SOC team
```
Teams Action: Post message in a channel

Channel: SOC-Alerts

Message:

🚨 Account Containment Action

Account disabled: @{variables('UPN')}

Reason: Suspicious sign-in detected

Action taken: Account automatically disabled at @{utcNow()}

Status: PENDING ANALYST REVIEW FOR RE-ENABLEMENT
```

### 6. Document on incident
```
Sentinel Action: Add comment to incident

Comment: "Automated containment action completed.

Account @{variables('UPN')} has been disabled due to suspicious sign-in pattern.

Disabled at @{utcNow()}.

This account requires analyst review and manual re-enablement once the threat is confirmed resolved."
```

## Security considerations
- API calls use managed identity with least-privilege scope — only permission to read and modify the specific user account, nothing broader
- Account disable is immediate but reversible — analyst review is required before re-enabling
- All actions are logged in the incident comment for audit trail
