# Threat Intelligence Dashboard

A dashboard that pulls threat data from public sources into one place, helps prioritize vulnerabilities, and maps malware families to MITRE ATT&CK techniques.

![Overview](screenshots/overview.png,overview2.png,overview3.png)

## What it does

- Collects actively exploited vulnerabilities from **CISA KEV**
- Adds exploit-probability scores from **FIRST.org EPSS**
- Tracks live botnet C2 servers from **abuse.ch Feodo Tracker**
- **IP lookup** using AbuseIPDB, plus a check against the local C2 list
- **MITRE ATT&CK mapping** from malware family to tactics and techniques
- Automatic refresh every 6 hours with cron, and a data-freshness panel

![IP lookup](screenshots/ip-lookup.png)
![ATT&CK mapping](screenshots/attack-mapping.png)

## How it works

Python collectors -> SQLite database -> Streamlit dashboard

| Part | File |
|---|---|
| Collectors | `collectors/kev.py`, `feodo.py`, `epss.py` |
| Refresh all feeds | `refresh.py` |
| IP lookup | `lookup.py` |
| ATT&CK data | `mitre.py` |
| Dashboard | `dashboard.py` |

## Setup

```bash
git clone https://github.com/roshinr/threat-intel-dashboard.git
cd threat-intel-dashboard
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

Copy `.env.example` to `.env` and add your free AbuseIPDB key:

```bash
cp .env.example .env
```

Then load the data and start the dashboard:

```bash
python3 refresh.py
streamlit run dashboard.py
```

## Red team notes

Attackers use spearphishing attachments (T1566.001) to gain initial access by emailing a malicious file to a target. In a lab I own, I would test this with a harmless test file and check whether email filtering or endpoint tools raise an alert. To detect it, I would monitor for Office applications launching scripts or command-line tools.

## Limitations and next steps

- The ATT&CK family-to-technique mapping is hand-curated and checked against attack.mitre.org
- Feeds can contain false positives, and some lists are small
- Next: more feeds (URLhaus, NVD), alerts for new critical CVEs, and a lab to test detection of the mapped techniques

## Data sources

CISA KEV, FIRST.org EPSS, abuse.ch Feodo Tracker, AbuseIPDB
