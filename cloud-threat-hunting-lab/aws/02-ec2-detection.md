# Lab 2: EC2 Exposed Security Group Detection

## Scenario
Attacker launches EC2 instance with security group allowing unrestricted SSH access from entire internet (0.0.0.0/0). This creates a major attack surface.

## Attack Simulation Steps

### Step 1: Launch Instance with Exposed Security Group
- Instance name: `exposed-instance`
- Instance type: `m7i-flex.large`
- Security group: Created new with unrestricted SSH access
- SSH (port 22): Allowed from 0.0.0.0/0 (entire internet)
- Status: Running

### Step 2: Verify Exposed Access
- Instance is now accessible via SSH from any IP address
- Anyone on internet can attempt to connect
- No network restrictions in place

---

## CloudTrail Events Captured

### Event 1: RunInstances
**What happened:**
- Event name: `RunInstances`
- Instance type: `m7i-flex.large`
- Instance name: `exposed-instance`
- Region: us-east-1
- Status: Success

**Why suspicious:**
- Instance launched with specific configuration
- Named "exposed-instance" (suspicious naming)
- Created with custom security group

**CloudTrail Event Structure:**
```json
{
  "eventName": "RunInstances",
  "eventSource": "ec2.amazonaws.com",
  "requestParameters": {
    "instanceType": "m7i-flex.large",
    "minCount": 1,
    "maxCount": 1,
    "securityGroupId": "sg-1234567890abcdef0"
  },
  "responseElements": {
    "instancesSet": {
      "items": [
        {
          "instanceId": "i-1234567890abcdef0",
          "groupSet": [
            {
              "groupId": "sg-1234567890abcdef0"
            }
          ]
        }
      ]
    }
  },
  "eventTime": "2026-06-30T10:25:00Z"
}
```

---

### Event 2: AuthorizeSecurityGroupIngress (SSH 0.0.0.0/0)
**What happened:**
- Event name: `AuthorizeSecurityGroupIngress`
- Port: 22 (SSH)
- Protocol: TCP
- Source: 0.0.0.0/0 (entire internet)
- Status: Success

**Why suspicious:**
- Security group now allows SSH from anywhere
- Anyone on internet can attempt to login
- Best practice: Restrict to specific IPs only
- Violates principle of least privilege

**CloudTrail Event Structure:**
```json
{
  "eventName": "AuthorizeSecurityGroupIngress",
  "eventSource": "ec2.amazonaws.com",
  "requestParameters": {
    "groupId": "sg-1234567890abcdef0",
    "ipPermissions": [
      {
        "ipProtocol": "tcp",
        "fromPort": 22,
        "toPort": 22,
        "ipRanges": [
          {
            "cidrIp": "0.0.0.0/0",
            "description": ""
          }
        ]
      }
    ]
  },
  "eventTime": "2026-06-30T10:25:15Z"
}
```

---

## Detection Logic

### Alert Trigger 1: Unrestricted SSH Access
**Condition:** 
- Port 22 (SSH) allowed from 0.0.0.0/0
- Any security group modification allowing this

**Why:** 
- Critical vulnerability
- Entire internet can attempt SSH brute force
- Gateway to system compromise

**Severity:** CRITICAL

---

### Alert Trigger 2: Instance with Public Access
**Condition:**
- Instance launched
- Security group allows 0.0.0.0/0 on any port

**Why:**
- Instance is exposed to public internet
- Easy attack surface
- Should be in private subnet with bastion access

**Severity:** HIGH

---

### Alert Trigger 3: Security Group Configuration Change
**Condition:**
- AuthorizeSecurityGroupIngress events
- Specifically port 22 to 0.0.0.0/0

**Why:**
- Attacker opening access
- Insider creating backdoor
- Misconfiguration with high risk

**Severity:** CRITICAL

---

## KQL Detection Queries

### Query 1: Detect Unrestricted SSH Access
**Purpose:** Find security groups allowing SSH from 0.0.0.0/0

```kql
AWSCloudTrail
| where EventName == "AuthorizeSecurityGroupIngress"
| where RequestParameters contains "0.0.0.0/0" and RequestParameters contains "22"
| project TimeGenerated, UserIdentity_principalId, EventName, RequestParameters, SourceIPAddress
| order by TimeGenerated desc
```

**Expected result:**
- Shows every time SSH (port 22) is opened to entire internet
- Who did it, when, from where
- Critical for detecting unauthorized access

**Alert threshold:** Alert on every match (no threshold)

---

### Query 2: Detect All Unrestricted Security Group Access
**Purpose:** Find ANY port opened to 0.0.0.0/0

```kql
AWSCloudTrail
| where EventName == "AuthorizeSecurityGroupIngress"
| where RequestParameters contains "0.0.0.0/0"
| project TimeGenerated, UserIdentity_principalId, EventName, RequestParameters, SourceIPAddress
| order by TimeGenerated desc
```

**Expected result:**
- Every port opened to entire internet
- Shows all exposed access points
- Helps identify misconfigured security groups

**Alert threshold:** Alert on every match

---

### Query 3: Detect Instances with Exposed Security Groups
**Purpose:** Find RunInstances events using exposed security groups

```kql
AWSCloudTrail
| where EventName == "RunInstances"
| where RequestParameters contains "sg-" // Security group ID present
| project TimeGenerated, UserIdentity_principalId, EventName, RequestParameters, SourceIPAddress
| order by TimeGenerated desc
```

**Expected result:**
- Shows instance launches with custom security groups
- Correlate with Query 1 to find exposed instances
- Identify instances launched with specific groups

**Alert threshold:** None (informational)

---

### Query 4: Timeline of Security Group Changes (Investigation)
**Purpose:** Show sequence of events for incident investigation

```kql
AWSCloudTrail
| where EventName in ("AuthorizeSecurityGroupIngress", "RunInstances")
| where RequestParameters contains "exposed" or RequestParameters contains "0.0.0.0/0"
| project TimeGenerated, EventName, UserIdentity_principalId, RequestParameters
| order by TimeGenerated asc
```

**Expected result:**
- Chronological sequence of events
- Shows: Instance launched → Security group exposed
- Helps understand attacker progression

**Alert threshold:** None (investigational)

---

### Query 5: Baseline - All Security Group Authorization Events
**Purpose:** Establish baseline of who modifies security groups

```kql
AWSCloudTrail
| where EventName == "AuthorizeSecurityGroupIngress"
| project TimeGenerated, UserIdentity_principalId, EventName, RequestParameters, SourceIPAddress
| order by TimeGenerated desc
| limit 50
```

**Expected result:**
- Last 50 security group changes
- Shows normal vs suspicious modifications
- Helps tuning detection rules

**Alert threshold:** None (baseline)

---

## Real-World Attack Scenarios

### Scenario 1: Compromised AWS Account
1. Attacker gains AWS credentials (phishing, credential theft)
2. First action: Launch instance with public SSH access
3. Uses instance as jump box to access company network
4. Creates persistent backdoor access
5. **Detection:** Query 1 catches SSH 0.0.0.0/0

**Impact:**
- Attacker has SSH access to your infrastructure
- Can SSH brute force attempt login
- Can use as pivot point to company network
- Persistence mechanism established

---

### Scenario 2: Insider Threat
1. Disgruntled employee creates exposed instance
2. Opens SSH access to entire internet
3. Plans to access system remotely after leaving company
4. **Detection:** Query 1 triggers alert

**Impact:**
- Former employee maintains access
- Can exfiltrate data
- Can sabotage systems
- Creates security liability

---

### Scenario 3: Misconfiguration Turned Malicious
1. Developer creates test instance
2. Opens SSH to 0.0.0.0/0 "temporarily"
3. Attacker discovers exposed instance (port scanning)
4. Compromises system
5. **Detection:** Query 1 would have caught during change

**Impact:**
- Production system compromise
- Data theft
- Lateral movement to network

---

## Defense Recommendations

### Preventive Controls

**1. Use AWS Security Groups Properly**
- Always restrict to specific IPs
- Use bastion host for SSH access
- Never allow 0.0.0.0/0 for SSH

**2. Service Control Policies (SCPs)**
- Prevent creating security groups with public access
- Block RunInstances without approval
- Require private subnets only

**3. VPC Network Design**
- Private subnets for instances
- Bastion host in public subnet
- NAT gateway for outbound access

**4. IAM Policies**
- Restrict who can create security groups
- Restrict who can launch instances
- Require approval for RunInstances

### Detective Controls

**1. CloudTrail Alerts (Query 1)**
- Alert on ANY SSH (port 22) to 0.0.0.0/0
- No exceptions, no threshold
- Immediate response required

**2. CloudTrail Alerts (Query 2)**
- Alert on ANY port to 0.0.0.0/0
- Captures all public access attempts
- Lower severity than SSH but still important

**3. Security Group Audits (Query 5)**
- Regular review of all security group changes
- Understand baseline activity
- Identify anomalies

**4. Network ACLs**
- Additional layer of protection
- Block suspicious traffic patterns
- Prevent SSH access to sensitive subnets

### Responsive Controls

**1. Immediate Actions**
- Terminate exposed instance
- Delete/restrict security group
- Check CloudTrail for what accessed instance

**2. Forensics**
- Preserve instance for analysis
- Check SSH logs for login attempts
- Review AWS CloudTrail for all actions

**3. Investigation**
- Who created the instance?
- Who opened the security group?
- What credentials were used?
- Was this authorized?

**4. Follow-up**
- Force password reset for creator
- Audit all instances/security groups
- Review recent instance terminations
- Check for data exfiltration

---

## MITRE ATT&CK Mapping

| Technique | ID | Description | Our Lab |
|-----------|-----|-------------|---------|
| Create Cloud Instance | T1578.001 | Launch EC2 with exposed config | RunInstances |
| Lateral Movement | T1570 | Use exposed instance as jump box | SSH 0.0.0.0/0 |
| Valid Accounts | T1078 | SSH brute force on exposed instance | Port 22 open |
| Persistence | T1098 | Maintain access via exposed instance | Continuous SSH access |
| Exfiltration | T1020 | Use exposed instance to exfil data | Network access |

---

## Lab Timeline
