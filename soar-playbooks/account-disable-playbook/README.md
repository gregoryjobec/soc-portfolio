# Account containment playbook

## Overview
Automates initial containment for suspicious sign-in incidents by disabling the affected Entra ID account, pending analyst review — reducing time-to-containment for identity-based threats.

## MITRE ATT&CK
T1078 — Valid Accounts

## Trigger
Microsoft Sentinel incident created, matching analytics rules for impossible travel, MFA bypass, or anomalous sign-in patterns.

## Workflow

1. **Trigger** — Sentinel incident created
2. **Parse entities** — Extract the affected user account (UPN) from incident entities
3. **Lookup** — Retrieve user object from Microsoft Entra ID
4. **Contain** — Disable the user account (`accountEnabled: false`) via Microsoft Graph API
5. **Notify** — Send email/Teams notification to SOC team confirming containment action and account affected
6. **Document** — Add comment to Sentinel incident logging the automated action and timestamp, flagged for analyst review before re-enabling

## Architecture

Sentinel Incident (Suspicious Sign-In)

|

v

Parse Entities (UPN)

|

v

Microsoft Graph API - Get User

|

v

Microsoft Graph API - Disable Account

|

v

+----+----+

|         |

v         v

Notify SOC    Incident Comment

(Teams/Email) (audit trail)

## Why this matters
Cuts containment time for compromised accounts from minutes (manual triage) to seconds, limiting the window for lateral movement or further account abuse.

## Implementation notes
This playbook design is adapted from Microsoft's official Sentinel playbook templates (Logic Apps connectors for Sentinel and Microsoft Graph). This is a design and architecture reference, not a deployed/tested playbook.

## Files
- `playbook-logic.md` — step-by-step Logic Apps configuration reference
