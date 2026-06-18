# IOC enrichment script

A Python script that automates indicator-of-compromise (IOC) enrichment by querying VirusTotal and AbuseIPDB, returning a consolidated threat summary — reducing manual lookup time during incident triage.

## Usage

```bash
pip install -r requirements.txt
python enrich_ioc.py --ip 8.8.8.8
python enrich_ioc.py --hash <file_hash>
```

## What it does
- Accepts an IP address or file hash as input
- Queries VirusTotal API for detection ratio and reputation
- Queries AbuseIPDB for abuse confidence score (IP only)
- Outputs a clean, readable threat summary

## Requires
API keys for VirusTotal and AbuseIPDB (free tier available), set as environment variables.
