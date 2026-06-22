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
