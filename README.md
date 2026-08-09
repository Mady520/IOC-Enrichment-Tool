# IOC Enrichment Tool

Automated threat intelligence pipeline for SOC analysts.  
Extracts Indicators of Compromise (IOCs) from log files and enriches them against multiple threat intel sources, then produces a colour-coded HTML report.

---

## What It Does

1. Parses raw log files and extracts: IPv4, IPv6, domains, URLs, file hashes (MD5/SHA1/SHA256), emails, CVE identifiers
2. Checks each IOC against AbuseIPDB, VirusTotal, OTX AlienVault, Shodan, URLhaus, MalwareBazaar, and NVD
3. Assigns a severity label: **CRITICAL / HIGH / MEDIUM / LOW / CLEAN**
4. Marks IOCs as **NEW** (first time seen) vs **SEEN** (appeared in previous runs)
5. Saves a JSON/CSV report and a self-contained HTML report
6. Optionally sends an email alert when CRITICAL or HIGH findings are detected (IF email alert is used).

---

## File Structure

```
project/
├── run.py            Entry point - orchestrates the full pipeline
├── index.py          IOC extractor - parses log files
├── enrich.py         Threat intel enrichment - queries all APIs
├── cache.py          Cache + history persistence
├── report_html.py    HTML report generator
├── config.yaml       All settings (thresholds, email, output)
├── whitelist.yaml    Known-good IOCs to skip.
├── .env.example      Template for .env
└── README.md
```

---

## Installation

**Windows:**
```bash
pip install requests python-dotenv rich pyyaml scapy
```

**Linux:**
```bash
pip3 install requests python-dotenv rich pyyaml scapy
```

Requires higher version of python on both platforms.

---
## Clone & Run

```bash
git clone https://github.com/Mady520/IOC-Enrichment-Tool.git
cd IOC-Enrichment-Tool
```
Windows:
```bash
pip install -r requirements.txt
copy .env.example .env
```
Linux:
``` bash
pip3 install -r requirements.txt
cp .env.example .env
```
Open .env and add your API keys, then run:

Windows:
```bash

python run.py access.log
```
Linux:
```bash

python3 run.py access.log
```
## Setup

**1. API keys** - copy `.env.example` to `.env` and fill in your keys:

```bash
ABUSEIPDB_KEY=your_key
VIRUSTOTAL_KEY=your_key
OTX_KEY=your_key
SHODAN_KEY=your_key      # optional
```
URLhaus, MalwareBazaar, and NVD require no key.

**2. Whitelist** - edit `whitelist.yaml` to add your internal IPs and trusted domains so they are skipped during enrichment.

**3. Config** - edit `config.yaml` to adjust severity thresholds, email settings, cache TTL, and output options.

---

## Usage

**Windows:**
```bash
# Single log file
python run.py access.log

# Multiple log files
python run.py firewall.log proxy.log ids.log

# Glob pattern
python run.py logs/*.log

# Custom output
python run.py access.log -o report.csv
python run.py access.log -o results.json

# Skip HTML report
python run.py access.log --no-html
```

**Linux:**
```bash
# Single file with full path
python3 run.py /var/log/auth.log

# Nginx or Apache logs
python3 run.py /var/log/nginx/access.log /var/log/apache2/error.log

# All logs in a directory
python3 run.py /var/log/*.log

# Multiple paths at once
python3 run.py /var/log/auth.log /var/log/syslog /tmp/capture.log

# Custom output location
python3 run.py /var/log/auth.log -o /home/analyst/reports/report.json
```


---

## Output

| File | Description |
|---|---|
| `enriched_report.json` | Full nested result with all API data |
| `enriched_report.csv` | Flat table, one row per IOC |
| `report.html` | Browser-viewable report with filters and colour coding |
| `cache.json` | API result cache (auto-managed) |
| `history.json` | IOC history across all runs (auto-managed) |

### HTML Report Features
- Summary cards: total IOCs, per-severity counts, new IOC count
- Filter buttons: All / Critical / High / Medium / Low / Clean / New Only
- Table columns: Severity, Type, Value, New/Seen, VT detections, AbuseIPDB score, OTX pulses, Shodan ports, Extra info

---

## Severity Logic

| Severity | Condition |
|---|---|
| CRITICAL | VT ≥ 10 malicious engines **OR** AbuseIPDB ≥ 80% |
| HIGH | VT ≥ 5 **OR** AbuseIPDB ≥ 50% **OR** (VT ≥ 2 and OTX ≥ 2 pulses) |
| MEDIUM | VT ≥ 1 **OR** VT suspicious ≥ 3 **OR** OTX ≥ 1 pulse **OR** URLhaus active **OR** MalwareBazaar found |
| LOW | AbuseIPDB > 0 **OR** VT suspicious ≥ 1 |
| CLEAN | No hits across all sources |

Thresholds are configurable in `config.yaml` under `severity:`.

---

## Rate Limits (Free Tiers)

| API | Limit | Handled by |
|---|---|---|
| VirusTotal | 4 req/min, 500/day | `RateLimiter` class - auto sleeps between calls |
| AbuseIPDB | 1,000/day | Parallel execution - no explicit delay needed |
| OTX | Generous | Parallel execution |
| Shodan | 1 req/sec | Parallel execution |
| URLhaus | No limit | Parallel execution |
| MalwareBazaar | No limit | Parallel execution |
| NVD | ~50/30s | Sequential per CVE |

AbuseIPDB, OTX, Shodan, URLhaus, and MalwareBazaar run **in parallel** per IOC. Only VirusTotal is sequential.

---

## Email Alerts

To enable email alerts when CRITICAL/HIGH IOCs are found:

1. Set `email.enabled: true` in `config.yaml`
2. Fill in `smtp_host`, `smtp_port`, `sender`, `password`, `recipients`
3. For Gmail: create an App Password at Google Account → Security → App Passwords

---

## Cache

Results are cached in `cache.json` with a default TTL of 7 days. On subsequent runs, cached IOCs return instantly without hitting the APIs. Change `cache.ttl_days` in `config.yaml` to adjust.

---

## History Tracking

Every IOC ever processed is stored in `history.json` with `first_seen`, `last_seen`, `severity`, and `count`. The HTML report and terminal output mark IOCs as **NEW** if they haven't appeared in any previous run.
