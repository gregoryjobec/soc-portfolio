# Lab 1: Suspicious IAM Activity Detection

## Scenario
Simulate an attacker creating a new user and immediately escalating to admin privileges. This is a common post-compromise persistence technique.

## Attack Simulation Steps

### Step 1: Create IAM User
- User name: `attacker`
- Console access: Disabled
- Initial permissions: None
- Status: Created successfully

### Step 2: Attach Admin Policy
- Policy: `AdministratorAccess`
- Target user: `attacker`
- Method: Direct policy attachment
- Result: User now has full AWS access

### Step 3: Create Access Key
- User: `attacker`
- Purpose: CLI/SDK access
- Type: Command Line Interface (CLI)
- Status: Created successfully
- Access Key ID: `AKIA2ZB5NXPUKT4LX255`

### Step 4: Add to Admin Group
- Group name: `Admin` (created with AdministratorAccess policy)
- Target user: `attacker`
- Method: Add user to existing group
- Result: User has admin access via group membership

---

## CloudTrail Events Captured

### Event 1: CreateUser
**What happened:**
- Event name: `CreateUser`
- User created: `attacker`
- Creator: root account
- Status: Success
- Time: June 30, 2026, ~07:28 UTC

**Why suspicious:**
- New user created
- Named "attacker" (unusual naming)
- No explicit authorization visible

**CloudTrail Event Structure:**
```json
{
  "eventName": "CreateUser",
  "eventSource": "iam.amazonaws.com",
  "requestParameters": {
    "userName": "attacker"
  },
  "userIdentity": {
    "principalId": "AIDAI...",
    "type": "IAMUser"
  },
  "eventTime": "2026-06-30T07:28:00Z"
}
```

---

### Event 2: AttachUserPolicy
**What happened:**
- Event name: `AttachUserPolicy`
- Policy: `AdministratorAccess`
- Target user: `attacker`
- Status: Success

**Why suspicious:**
- Admin policy attached to newly created user
- Immediate escalation (seconds after user creation)
- Gives full AWS access

**CloudTrail Event Structure:**
```json
{
  "eventName": "AttachUserPolicy",
  "eventSource": "iam.amazonaws.com",
  "requestParameters": {
    "userName": "attacker",
    "policyName": "AdministratorAccess"
  },
  "eventTime": "2026-06-30T07:28:15Z"
}
```

---

### Event 3: CreateAccessKey
**What happened:**
- Event name: `CreateAccessKey`
- Target user: `attacker`
- Status: Success
- Access Key ID: `AKIA2ZB5NXPUKT4LX255`

**Why suspicious:**
- API credentials created for new user
- Enables programmatic/CLI access
- User can now access AWS without console login
- Attacker can access remotely with just API key

**CloudTrail Event Structure:**
```json
{
  "eventName": "CreateAccessKey",
  "eventSource": "iam.amazonaws.com",
  "requestParameters": {
    "userName": "attacker"
  },
  "responseElements": {
    "accessKey": {
      "accessKeyId": "AKIA2ZB5NXPUKT4LX255",
      "status": "Active"
    }
  },
  "eventTime": "2026-06-30T07:28:30Z"
}
```

---

### Event 4: AddUserToGroup
**What happened:**
- Event name: `AddUserToGroup`
- Group: `Admin`
- Target user: `attacker`
- Status: Success

**Why suspicious:**
- User added to admin group
- Redundant admin access (already has direct policy)
- Indicates attacker establishing multiple persistence methods

**CloudTrail Event Structure:**
```json
{
  "eventName": "AddUserToGroup",
  "eventSource": "iam.amazonaws.com",
  "requestParameters": {
    "groupName": "Admin",
    "userName": "attacker"
  },
  "eventTime": "2026-06-30T07:28:45Z"
}
```

---

## Detection Logic

### Pattern Recognition

All 4 events share these characteristics:
- **Same principal/creator:** Root account (us)
- **Time window:** ~17 seconds (07:28:00 to 07:28:45)
- **Target:** Same user ("attacker")
- **Severity escalation:** None → Admin → Admin (CLI) → Admin (group)

### Alert Trigger Conditions

**Alert 1: Multiple IAM privilege changes in short timeframe**
- Condition: 3+ IAM modification events in 5 minutes
- Target: Same user
- Severity: HIGH
- Action: Investigate user creation

**Alert 2: Admin policy on new user**
- Condition: CreateUser followed by AttachUserPolicy (AdministratorAccess)
- Timeframe: Within 5 minutes
- Severity: CRITICAL
- Action: Disable user immediately

**Alert 3: API key creation for new user**
- Condition: CreateAccessKey within 5 minutes of user creation
- Severity: HIGH
- Action: Revoke access key

**Alert 4: User added to privileged group**
- Condition: AddUserToGroup to admin group
- Target: Newly created user
- Severity: MEDIUM-HIGH
- Action: Review group membership

---

## KQL Detection Queries

### Query 1: List All IAM Events for Suspicious User
**Purpose:** Investigation query — find all privilege-related activity for a specific user

**When to use:**
- You've identified a suspicious user
- Need complete activity history
- Investigating potential compromise

**Query:**
```kql
AWSCloudTrail
| where EventName in ("CreateUser", "AttachUserPolicy", "AddUserToGroup", "CreateAccessKey")
| where UserIdentity_principalId == "attacker" or RequestParameters contains "attacker"
| project TimeGenerated, EventName, UserIdentity_principalId, EventSource, RequestParameters, SourceIPAddress
| order by TimeGenerated asc
```

**Expected result:**
- 4 events in chronological order
- All targeting "attacker" user
- Clear attack progression

**How to interpret:**
- CreateUser first = account creation
- AttachUserPolicy second = privilege escalation
- CreateAccessKey third = persistence mechanism
- AddUserToGroup fourth = backup access method

---

### Query 2: Detect Rapid Privilege Escalation (DETECTION ALERT)
**Purpose:** Real-time detection of privilege escalation attacks

**When to use:**
- Automated alerting
- Real-time threat detection
- Security monitoring dashboards

**Query:**
```kql
AWSCloudTrail
| where EventName in ("CreateUser", "AttachUserPolicy", "AddUserToGroup", "CreateAccessKey")
| summarize EventCount = count(), Events = make_list(EventName) by UserIdentity_principalId, SourceIPAddress, bin(TimeGenerated, 5m)
| where EventCount >= 3
| project TimeGenerated, UserIdentity_principalId, SourceIPAddress, EventCount, Events
```

**Alert threshold:** EventCount >= 3 in 5 minutes

**Expected result:**
- Flags attack pattern as suspicious
- Groups events by user and time window
- Shows all events in sequence

**How to interpret:**
- EventCount = 3: User escalated privileges 3+ times in 5 min = SUSPICIOUS
- Events list: Shows exact escalation sequence
- SourceIPAddress: Where attack came from

---

### Query 3: Detect Admin Policy Attachment (DETECTION ALERT)
**Purpose:** Catch admin access grants in real-time

**When to use:**
- Alert on any admin policy attachment
- Sensitive operation monitoring
- Compliance tracking

**Query:**
```kql
AWSCloudTrail
| where EventName == "AttachUserPolicy"
| where RequestParameters contains "AdministratorAccess"
| project TimeGenerated, UserIdentity_principalId, EventName, RequestParameters, SourceIPAddress, UserAgent
```

**Alert threshold:** Always alert (no threshold)

**Expected result:**
- Every admin policy attachment appears
- Shows who attached it, when, from where
- No false negatives (catches all admin grants)

**How to interpret:**
- Each row = someone gave someone admin access
- Review: Was this authorized?
- If not authorized → disable user immediately

---

## Real-World Attack Scenarios

### Scenario 1: Compromised Developer Account
**What happened:**
1. Developer's AWS credentials compromised (phishing, credential theft)
2. Attacker uses developer account to create backdoor user
3. We detect: 3+ IAM events in 5 minutes from developer account
4. Alert triggers: "Privilege escalation detected"
5. We investigate and find backdoor user "attacker"
6. Action: Disable developer account, force password reset, rotate all keys

### Scenario 2: Insider Threat
**What happened:**
1. Disgruntled employee creates secret admin account before leaving
2. Account named "attacker" (perhaps intentionally suspicious)
3. We detect: Admin policy attached to new user
4. Alert triggers: "Admin policy on new user"
5. We investigate and catch before employee leaves
6. Action: Disable user, audit all actions, review access logs

### Scenario 3: Post-Compromise Persistence
**What happened:**
1. Attacker gains initial access to AWS account (supply chain attack)
2. First action: Create persistent admin access
3. We detect: All 4 events in rapid succession
4. Alert triggers: "Rapid privilege escalation"
5. We catch attacker's persistence attempt
6. Action: Kill session, audit all created resources, force re-authentication

---

## Defense Recommendations

### Preventive Controls
1. **Require MFA** for creating users and attaching policies
2. **Resource-based policies** — restrict who can create IAM users
3. **Service Control Policies (SCPs)** — block admin policy attachment
4. **IAM Access Analyzer** — review who has admin access
5. **Least privilege** — users should not have admin by default

### Detective Controls
1. **CloudTrail logging** — enable on all accounts (we did this ✓)
2. **Alert on privilege changes** — detect rapid escalation
3. **Alert on access key creation** — especially for new users
4. **Monitor group membership** — especially admin groups
5. **Regular access reviews** — quarterly audit of user permissions

### Responsive Controls
1. **Disable user immediately** — block access
2. **Revoke access keys** — stop programmatic access
3. **Force re-authentication** — invalidate sessions
4. **Audit logs** — what did the user access?
5. **Root cause analysis** — how did they gain access originally?

---

## MITRE ATT&CK Mapping

| Technique | ID | Description | Our Lab |
|-----------|-----|-------------|---------|
| Account Manipulation | T1098 | Modifying account attributes | Attaching policies |
| IAM Policy Change | T1098.001 | Changing IAM policies | AttachUserPolicy event |
| Valid Accounts | T1078 | Using legitimate credentials | "attacker" user |
| Account Discovery | T1087 | Enumerating accounts/permissions | CreateUser discovery |

---

## Lab Timeline
```
07:28:00      Create user            CreateUser
07:28:15      Attach admin policy    AttachUserPolicy
07:28:30      Create access key      CreateAccessKey
07:28:45      Add to admin group     AddUserToGroup
Total time: 45 seconds
Pattern: Rapid privilege escalation
```
---

## Evidence

### Screenshots Captured
1. IAM user "attacker" created (user list view)
2. AdministratorAccess policy attached (permissions tab)
3. Access key created (security credentials tab)
4. User added to Admin group (groups tab)
5. S3 CloudTrail bucket showing logs stored

### CloudTrail Evidence
- CloudTrail trail "SecurityLab" status: **Logging** ✓
- S3 bucket with CloudTrail logs: **cloudtrail-logs-...** ✓
- Regions logging: **ap-southeast-2/, us-east-1/** ✓

---

## Key Takeaways

1. **CloudTrail logs ALL API calls** — nothing escapes detection
2. **Rapid privilege escalation** is a red flag — investigate immediately
3. **Multiple persistence methods** (direct policy + group + API key) = intentional attacker
4. **Detection queries** catch attack patterns automatically
5. **Timeline matters** — 45 seconds for 4 events = very suspicious

---

## Next Steps

- [ ] Set up CloudTrail alerts for similar patterns
- [ ] Create automated response (disable user on alert)
- [ ] Test detection queries against real account
- [ ] Document response procedures
- [ ] Train team on privilege escalation detection
