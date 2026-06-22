# Phishing response playbook

## Overview
Automates initial triage of phishing incidents in Microsoft Sentinel by extracting indicators, enriching them via threat intelligence, and notifying the SOC team — reducing manual triage time on high-volume phishing alerts.

## MITRE ATT&CK
T1566 — Phishing

## Trigger
Microsoft Sentinel incident created, filtered to incidents tagged "Phishing" or matching analytics rules for email-based threats.

## Workflow

1. **Trigger** — Sentinel incident created
2. **Parse entities** — Extract sender email address and URL/file hash entities from the incident
3. **Enrich** — Call VirusTotal API with extracted URL/hash to retrieve detection score
4. **Notify** — Post a formatted summary card to a Microsoft Teams SOC channel:
   - Sender, subject, URL, VirusTotal score, incident severity
5. **Document** — Add an automated comment to the Sentinel incident confirming enrichment was completed and attaching the VirusTotal result

## Architecture
Sentinel Incident (Phishing)

|
v

Parse Entities (sender, URL, hash)

|
v

VirusTotal API Lookup

|
v

+----+----+
|         |
v         v
Teams Alert   Incident Comment
(SOC channel) (audit trail)

## Why this matters
Reduces time-to-first-enrichment on phishing incidents, letting analysts start investigation with context already attached rather than performing manual IOC lookups for every alert. At 30-50 alerts/shift, automating this first enrichment step meaningfully reduces analyst triage load.

## Implementation notes
This playbook design is adapted from Microsoft's official Sentinel playbook templates (Logic Apps connectors for Sentinel, HTTP, and Microsoft Teams). The workflow above reflects standard SOAR automation patterns used in production Microsoft Sentinel environments.

## Files
- `playbook-logic.md` — step-by-step Logic Apps configuration reference
