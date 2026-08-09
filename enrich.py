"""
enrich.py — Threat intelligence enrichment for IOCs extracted by index.py.

APIs used:
  AbuseIPDB     — IP reputation           free: 1,000/day      needs key
  VirusTotal    — IPs, domains, hashes, URLs  free:500/day,       needs key                                       4 req/min
  OTX           — IPs, domains, hashes,   free, generous       needs key
                  URLs
  Shodan        — IP port/service scan     free tier            needs key
  URLhaus       — malicious URLs           free, no key
  MalwareBazaar — file hashes             free, no key
  NVD           — CVE CVSS scores         free, no key

"""

import os
import json
import time
import base64
import csv
import smtplib
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart

import requests
from dotenv import load_dotenv
from rich.console import Console
from rich.table import Table
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TaskProgressColumn, TimeRemainingColumn

load_dotenv()

ABUSEIPDB_KEY  = os.getenv("ABUSEIPDB_KEY")
VIRUSTOTAL_KEY = os.getenv("VIRUSTOTAL_KEY")
OTX_KEY        = os.getenv("OTX_KEY")
SHODAN_KEY     = os.getenv("SHODAN_KEY")

console = Console()

HTTP_METHODS = {
    b"GET", b"POST", b"PUT", b"DELETE",
    b"PATCH", b"HEAD", b"OPTIONS", b"CONNECT", b"TRACE"
}

ENCRYPTED_PORTS = {443, 8443, 465, 587, 993, 995, 636, 5061}
HTTP_PORTS      = {80, 8080, 8000, 8008}


#  Rate limiter 

class RateLimiter:
    """Enforces a minimum gap between API calls. Only sleeps when needed."""
    def __init__(self, calls_per_minute):
        self.delay     = 60.0 / calls_per_minute
        self.last_call = 0.0

    def wait(self):
        elapsed = time.time() - self.last_call
        if elapsed < self.delay:
            time.sleep(self.delay - elapsed)
        self.last_call = time.time()


vt_limiter = RateLimiter(calls_per_minute=4)


#  Severity scoring 

def get_severity(vt_malicious=0, vt_suspicious=0, abuse_score=0,
                 otx_pulses=0, urlhaus_active=False, bazaar_found=False, cfg=None):
    """
    Combine signals from all sources into one severity label.
    Thresholds are read from config so you can tune them without changing code.
    """
    t = (cfg or {}).get("severity", {})
    crit_vt    = t.get("critical_vt_malicious", 10)
    high_vt    = t.get("high_vt_malicious",     5)
    crit_abuse = t.get("critical_abuse_score",   80)
    high_abuse = t.get("high_abuse_score",       50)

    if vt_malicious >= crit_vt or abuse_score >= crit_abuse:
        return "CRITICAL"
    if vt_malicious >= high_vt or abuse_score >= high_abuse or (vt_malicious >= 2 and otx_pulses >= 2):
        return "HIGH"
    if vt_malicious >= 1 or vt_suspicious >= 3 or otx_pulses >= 1 or urlhaus_active or bazaar_found:
        return "MEDIUM"
    if abuse_score > 0 or vt_suspicious >= 1:
        return "LOW"
    return "CLEAN"


def _severity_color(sev):
    return {"CRITICAL": "red", "HIGH": "bright_red", "MEDIUM": "yellow",
            "LOW": "blue", "CLEAN": "green", "INFO": "white",
            "WHITELISTED": "dim"}.get(sev, "white")


#  HTTP helpers 

def _safe_get(url, headers=None, params=None, timeout=10):
    """GET with automatic 429 back-off and retry."""
    try:
        r = requests.get(url, headers=headers, params=params, timeout=timeout)
        if r.status_code == 429:
            time.sleep(60)
            r = requests.get(url, headers=headers, params=params, timeout=timeout)
        return r
    except requests.exceptions.RequestException:
        return None


def _safe_post(url, data=None, headers=None, timeout=10):
    """POST with automatic 429 back-off and retry."""
    try:
        r = requests.post(url, data=data, headers=headers, timeout=timeout)
        if r.status_code == 429:
            time.sleep(60)
            r = requests.post(url, data=data, headers=headers, timeout=timeout)
        return r
    except requests.exceptions.RequestException:
        return None


#  API functions 

def check_abuseipdb(ip):
    if not ABUSEIPDB_KEY:
        return None
    r = _safe_get(
        "https://api.abuseipdb.com/api/v2/check",
        headers={"Key": ABUSEIPDB_KEY, "Accept": "application/json"},
        params={"ipAddress": ip, "maxAgeInDays": 90},
    )
    if not r or r.status_code != 200:
        return None
    d = r.json().get("data", {})
    return {
        "confidence_score": d.get("abuseConfidenceScore", 0),
        "total_reports":    d.get("totalReports", 0),
        "country":          d.get("countryCode", ""),
        "isp":              d.get("isp", ""),
        "usage_type":       d.get("usageType", ""),
    }


def check_virustotal(resource_type, value):
    """
    resource_type: 'ip_addresses' | 'domains' | 'files' | 'urls'
    URLs are base64-encoded per the VT v3 API spec.
    """
    if not VIRUSTOTAL_KEY:
        return None
    lookup = base64.urlsafe_b64encode(value.encode()).decode().rstrip("=") \
             if resource_type == "urls" else value

    vt_limiter.wait()
    r = _safe_get(
        f"https://www.virustotal.com/api/v3/{resource_type}/{lookup}",
        headers={"x-apikey": VIRUSTOTAL_KEY},
    )
    if not r:
        return None
    if r.status_code == 404:
        return {"found": False, "malicious": 0, "suspicious": 0, "harmless": 0, "undetected": 0}
    if r.status_code != 200:
        return None
    stats = r.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    return {
        "found":      True,
        "malicious":  stats.get("malicious",  0),
        "suspicious": stats.get("suspicious", 0),
        "harmless":   stats.get("harmless",   0),
        "undetected": stats.get("undetected", 0),
    }


def check_otx(indicator_type, value):
    """indicator_type: 'IPv4' | 'IPv6' | 'domain' | 'url' | 'file'"""
    if not OTX_KEY:
        return None
    r = _safe_get(
        f"https://otx.alienvault.com/api/v1/indicators/{indicator_type}/{value}/general",
        headers={"X-OTX-API-KEY": OTX_KEY},
    )
    if not r or r.status_code != 200:
        return None
    return {"pulse_count": r.json().get("pulse_info", {}).get("count", 0)}


def check_shodan(ip):
    """
    Returns open ports, organisation, country, OS, and any CVEs Shodan
    has detected on the host. Free tier = 1 query/second, no daily cap.
    """
    if not SHODAN_KEY:
        return None
    r = _safe_get(
        f"https://api.shodan.io/shodan/host/{ip}",
        params={"key": SHODAN_KEY},
    )
    if not r or r.status_code != 200:
        return None
    d = r.json()
    return {
        "org":        d.get("org",          ""),
        "country":    d.get("country_name", ""),
        "open_ports": d.get("ports",        [])[:10],
        "hostnames":  d.get("hostnames",    [])[:5],
        "os":         d.get("os",           ""),
        "vulns":      list(d.get("vulns",   {}).keys())[:5],
    }


def check_urlhaus(url):
    """No API key needed. Returns whether the URL is actively serving malware."""
    r = _safe_post("https://urlhaus-api.abuse.ch/v1/url/", data={"url": url})
    if not r or r.status_code != 200:
        return None
    status = r.json().get("query_status", "")
    return {"found": status != "no_results", "active": status == "is_active", "status": status}


def check_malwarebazaar(hash_value):
    """No API key needed. Works for MD5, SHA1, SHA256."""
    r = _safe_post("https://mb-api.abuse.ch/api/v1/",
                   data={"query": "get_info", "hash": hash_value})
    if not r or r.status_code != 200:
        return None
    data  = r.json()
    found = data.get("query_status") == "ok"
    name  = data["data"][0].get("signature", "") if found and data.get("data") else ""
    return {"found": found, "malware_name": name}


def check_nvd_cve(cve_id):
    """No API key. Returns CVSS score + severity label from NVD."""
    r = _safe_get("https://services.nvd.nist.gov/rest/json/cves/2.0",
                  params={"cveId": cve_id})
    if not r or r.status_code != 200:
        return None
    vulns = r.json().get("vulnerabilities", [])
    if not vulns:
        return {"found": False}
    cve_data = vulns[0].get("cve", {})
    desc = next((d["value"] for d in cve_data.get("descriptions", [])
                 if d.get("lang") == "en"), "")[:200]
    score, severity = None, None
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metrics = cve_data.get("metrics", {}).get(key, [])
        if metrics:
            cvss     = metrics[0].get("cvssData", {})
            score    = cvss.get("baseScore")
            severity = cvss.get("baseSeverity")
            break
    return {"found": True, "cvss_score": score, "cvss_severity": severity, "description": desc}


#  Parallel execution 

def _run_parallel(checks):
    """
    Run multiple zero-or-light-rate-limit API calls concurrently.
    checks: dict of {result_key: callable}
    Returns: dict of {result_key: result}

    VirusTotal is NOT included here - it is sequential due to its
    strict 4 req/min rate limit.
    """
    results = {}
    with ThreadPoolExecutor(max_workers=len(checks)) as executor:
        future_map = {executor.submit(fn): name for name, fn in checks.items()}
        for future in as_completed(future_map):
            name = future_map[future]
            try:
                results[name] = future.result()
            except Exception:
                results[name] = None
    return results


#  Per-IOC enrichment 

def _enrich_one(value, parallel_checks, vt_type,
                cache=None, history=None, whitelist_set=None, cfg=None):
    """
    Enrich a single IOC value:
      1. Whitelist check  → skip if found
      2. Cache check      → return instantly if fresh
      3. Parallel APIs    → AbuseIPDB + OTX + Shodan + URLhaus/MalwareBazaar
      4. VirusTotal       → sequential (rate limited)
      5. Severity         → combine all signals
      6. History + cache  → persist results
    """
    # 1. Whitelist
    if whitelist_set and value in whitelist_set:
        return {"value": value, "severity": "WHITELISTED", "is_new": False, "sources": {}}

    # 2. Cache
    cache_key = f"{vt_type}:{value}"
    if cache:
        cached = cache.get(cache_key)
        if cached:
            is_new = history.is_new(value) if history else False
            if history:
                history.mark_seen(value, cached.get("severity", "CLEAN"))
            return {**cached, "is_new": is_new}

    entry = {"value": value, "sources": {}}

    # 3. Parallel non-VT checks
    parallel_results = _run_parallel(parallel_checks)
    for key, result in parallel_results.items():
        if result:
            entry["sources"][key] = result

    # 4. VirusTotal (sequential - rate limited)
    if vt_type and VIRUSTOTAL_KEY:
        vt = check_virustotal(vt_type, value)
        if vt:
            entry["sources"]["virustotal"] = vt

    # 5. Severity
    vt  = entry["sources"].get("virustotal", {})
    ab  = entry["sources"].get("abuseipdb",  {})
    otx = entry["sources"].get("otx",        {})
    uh  = entry["sources"].get("urlhaus",    {})
    bz  = entry["sources"].get("malwarebazaar", {})

    entry["severity"] = get_severity(
        vt_malicious   = vt.get("malicious",        0),
        vt_suspicious  = vt.get("suspicious",        0),
        abuse_score    = ab.get("confidence_score",  0),
        otx_pulses     = otx.get("pulse_count",      0),
        urlhaus_active = uh.get("active",            False),
        bazaar_found   = bz.get("found",             False),
        cfg            = cfg,
    )

    # 6. History + cache
    is_new = history.is_new(value) if history else True
    if history:
        history.mark_seen(value, entry["severity"])
    if cache:
        cache.set(cache_key, {k: v for k, v in entry.items() if k != "is_new"})

    entry["is_new"] = is_new
    return entry


#  Main enrichment orchestrator 

def enrich_iocs(iocs, cfg=None, cache=None, history=None, whitelist=None):
    """
    Enrich all IOCs from index.py output.

    Parameters (all optional - omitting any disables that feature):
      cfg       - loaded config.yaml dict
      cache     - IOCCache instance
      history   - IOCHistory instance
      whitelist - dict loaded from whitelist.yaml
    """
    cfg       = cfg       or {}
    whitelist = whitelist or {}

    wl_ipv4    = set(whitelist.get("ipv4",    []))
    wl_ipv6    = set(whitelist.get("ipv6",    []))
    wl_domains = set(whitelist.get("domains", []))
    wl_urls    = set(whitelist.get("urls",    []))
    wl_hashes  = set(
        whitelist.get("hashes", {}).get("md5",    []) +
        whitelist.get("hashes", {}).get("sha1",   []) +
        whitelist.get("hashes", {}).get("sha256", [])
    )

    results         = {}
    severity_counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "CLEAN": 0, "WHITELISTED": 0}
    new_count       = 0
    scan_time       = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Count total for progress bar
    total = (
        len(iocs.get("ipv4",    []))
        + len(iocs.get("ipv6",  []))
        + len(iocs.get("domains", []))
        + len(iocs.get("urls",  []))
        + len(iocs.get("emails", []))
        + len(iocs.get("cves",  []))
        + sum(len(iocs.get("hashes", {}).get(h, [])) for h in ("md5", "sha1", "sha256"))
    )

    def _track(entry):
        """Update severity counters and new count from a finished entry."""
        sev = entry.get("severity", "CLEAN")
        if sev in severity_counts:
            severity_counts[sev] += 1
        if entry.get("is_new"):
            nonlocal new_count
            new_count += 1

    with Progress(
        SpinnerColumn(),
        TextColumn("[bold cyan]{task.description}"),
        BarColumn(),
        TaskProgressColumn(),
        TimeRemainingColumn(),
        console=console,
    ) as progress:
        task = progress.add_task("Starting...", total=total)

        #  IPv4 
        ipv4_results = []
        for ip in iocs.get("ipv4", []):
            progress.update(task, description=f"IPv4  {ip}")
            entry = _enrich_one(
                value          = ip,
                parallel_checks= {
                    "abuseipdb": lambda i=ip: check_abuseipdb(i),
                    "otx":       lambda i=ip: check_otx("IPv4", i),
                    "shodan":    lambda i=ip: check_shodan(i),
                },
                vt_type        = "ip_addresses",
                cache          = cache,
                history        = history,
                whitelist_set  = wl_ipv4,
                cfg            = cfg,
            )
            _track(entry)
            c = _severity_color(entry["severity"])
            progress.log(f"[{c}]{entry['severity']:12}[/{c}]  ipv4  {ip}")
            ipv4_results.append(entry)
            progress.advance(task)
        results["ipv4"] = ipv4_results

        #  IPv6 
        ipv6_results = []
        for ip in iocs.get("ipv6", []):
            progress.update(task, description=f"IPv6  {ip}")
            entry = _enrich_one(
                value          = ip,
                parallel_checks= {
                    "abuseipdb": lambda i=ip: check_abuseipdb(i),
                    "otx":       lambda i=ip: check_otx("IPv6", i),
                    "shodan":    lambda i=ip: check_shodan(i),
                },
                vt_type        = "ip_addresses",
                cache          = cache,
                history        = history,
                whitelist_set  = wl_ipv6,
                cfg            = cfg,
            )
            _track(entry)
            c = _severity_color(entry["severity"])
            progress.log(f"[{c}]{entry['severity']:12}[/{c}]  ipv6  {ip}")
            ipv6_results.append(entry)
            progress.advance(task)
        results["ipv6"] = ipv6_results

        #  Domains 
        domain_results = []
        for domain in iocs.get("domains", []):
            progress.update(task, description=f"domain  {domain}")
            entry = _enrich_one(
                value          = domain,
                parallel_checks= {
                    "otx": lambda d=domain: check_otx("domain", d),
                },
                vt_type        = "domains",
                cache          = cache,
                history        = history,
                whitelist_set  = wl_domains,
                cfg            = cfg,
            )
            _track(entry)
            c = _severity_color(entry["severity"])
            progress.log(f"[{c}]{entry['severity']:12}[/{c}]  domain  {domain}")
            domain_results.append(entry)
            progress.advance(task)
        results["domains"] = domain_results

        #  URLs 
        url_results = []
        for url in iocs.get("urls", []):
            progress.update(task, description=f"url  {url[:60]}")
            entry = _enrich_one(
                value          = url,
                parallel_checks= {
                    "urlhaus": lambda u=url: check_urlhaus(u),
                    "otx":     lambda u=url: check_otx("url", u),
                },
                vt_type        = "urls",
                cache          = cache,
                history        = history,
                whitelist_set  = wl_urls,
                cfg            = cfg,
            )
            _track(entry)
            c = _severity_color(entry["severity"])
            progress.log(f"[{c}]{entry['severity']:12}[/{c}]  url  {url[:80]}")
            url_results.append(entry)
            progress.advance(task)
        results["urls"] = url_results

        #  Hashes 
        hash_results = {"md5": [], "sha1": [], "sha256": []}
        for hash_type in ("md5", "sha1", "sha256"):
            for h in iocs.get("hashes", {}).get(hash_type, []):
                progress.update(task, description=f"hash [{hash_type}]  {h[:20]}...")
                entry = _enrich_one(
                    value          = h,
                    parallel_checks= {
                        "malwarebazaar": lambda hv=h: check_malwarebazaar(hv),
                        "otx":           lambda hv=h: check_otx("file", hv),
                    },
                    vt_type        = "files",
                    cache          = cache,
                    history        = history,
                    whitelist_set  = wl_hashes,
                    cfg            = cfg,
                )
                _track(entry)
                c = _severity_color(entry["severity"])
                bz_name = entry.get("sources", {}).get("malwarebazaar", {}).get("malware_name", "")
                suffix  = f"  ({bz_name})" if bz_name else ""
                progress.log(f"[{c}]{entry['severity']:12}[/{c}]  {hash_type}  {h}{suffix}")
                hash_results[hash_type].append(entry)
                progress.advance(task)
        results["hashes"] = hash_results

        #  Emails — carried through as-is (no free API) 
        email_results = []
        for e in iocs.get("emails", []):
            entry = {"value": e, "severity": "INFO",
                     "is_new": history.is_new(e) if history else True, "sources": {}}
            if history:
                history.mark_seen(e, "INFO")
            _track(entry)
            email_results.append(entry)
            progress.advance(task)
        results["emails"] = email_results

        #  CVEs — NVD lookup for CVSS score 
        cve_results = []
        for cve in iocs.get("cves", []):
            progress.update(task, description=f"CVE  {cve}")
            is_new = history.is_new(cve) if history else True
            nvd    = check_nvd_cve(cve)
            sev    = "INFO"
            if nvd and nvd.get("found"):
                sev = {"CRITICAL": "CRITICAL", "HIGH": "HIGH",
                       "MEDIUM": "MEDIUM", "LOW": "LOW"}.get(
                    (nvd.get("cvss_severity") or "").upper(), "INFO")
            if history:
                history.mark_seen(cve, sev if sev != "INFO" else "LOW")
            c = _severity_color(sev)
            progress.log(f"[{c}]{sev:12}[/{c}]  cve  {cve}")
            entry = {"value": cve, "severity": sev, "is_new": is_new,
                     "sources": {"nvd": nvd}}
            cve_results.append(entry)
            _track(entry)
            progress.advance(task)
        results["cves"] = cve_results

    total_iocs = (
        len(results.get("ipv4",    []))
        + len(results.get("ipv6",  []))
        + len(results.get("domains", []))
        + len(results.get("urls",  []))
        + len(results.get("emails", []))
        + len(results.get("cves",  []))
        + sum(len(v) for v in results.get("hashes", {}).values())
    )

    return {
        "scan_time": scan_time,
        "summary":   {**severity_counts, "total": total_iocs, "new": new_count},
        "results":   results,
    }


#  Output 

def save_report(report, output_file):
    """JSON → full nested structure. Anything else → flat CSV."""
    _, ext = os.path.splitext(output_file)
    if ext.lower() == ".json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(report, f, indent=2)
        return

    with open(output_file, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow([
            "type", "value", "severity", "is_new",
            "vt_malicious", "vt_suspicious",
            "abuse_score", "abuse_reports",
            "otx_pulses",
            "shodan_ports", "shodan_org",
            "urlhaus_active", "bazaar_found", "bazaar_name",
            "nvd_cvss_score", "nvd_cvss_severity",
        ])

        def _row(ioc_type, entry):
            s   = entry.get("sources", {})
            vt  = s.get("virustotal",    {})
            ab  = s.get("abuseipdb",     {})
            ox  = s.get("otx",           {})
            sh  = s.get("shodan",        {})
            uh  = s.get("urlhaus",       {})
            bz  = s.get("malwarebazaar", {})
            nv  = s.get("nvd",           {}) or {}
            writer.writerow([
                ioc_type,
                entry["value"],
                entry["severity"],
                entry.get("is_new", ""),
                vt.get("malicious",        ""),
                vt.get("suspicious",       ""),
                ab.get("confidence_score", ""),
                ab.get("total_reports",    ""),
                ox.get("pulse_count",      ""),
                ",".join(str(p) for p in sh.get("open_ports", [])),
                sh.get("org", ""),
                uh.get("active",           ""),
                bz.get("found",            ""),
                bz.get("malware_name",     ""),
                nv.get("cvss_score",       ""),
                nv.get("cvss_severity",    ""),
            ])

        res = report["results"]
        for e in res.get("ipv4",    []): _row("ipv4",   e)
        for e in res.get("ipv6",    []): _row("ipv6",   e)
        for e in res.get("domains", []): _row("domain", e)
        for e in res.get("urls",    []): _row("url",    e)
        for e in res.get("emails",  []): _row("email",  e)
        for e in res.get("cves",    []): _row("cve",    e)
        for ht, entries in res.get("hashes", {}).items():
            for e in entries: _row(f"hash_{ht}", e)


def print_summary(report):
    """Print severity table and list all CRITICAL/HIGH findings."""
    s = report["summary"]

    table = Table(title=f"Enrichment Summary  —  {report['scan_time']}", header_style="bold white")
    table.add_column("Severity",  style="bold", min_width=12)
    table.add_column("Count",     justify="right")

    for label, color in [("CRITICAL","red"),("HIGH","bright_red"),
                          ("MEDIUM","yellow"),("LOW","blue"),("CLEAN","green"),
                          ("WHITELISTED","dim")]:
        table.add_row(Text(label, style=color), str(s.get(label, 0)))

    console.print()
    console.print(table)
    console.print(f"\n[bold]Total IOCs: {s.get('total',0)}   New this run: [magenta]{s.get('new',0)}[/magenta][/bold]")

    console.print("\n[bold red]CRITICAL / HIGH findings:[/bold red]")
    res     = report["results"]
    found   = False
    all_entries = (
        [("ipv4",   e) for e in res.get("ipv4",    [])] +
        [("ipv6",   e) for e in res.get("ipv6",    [])] +
        [("domain", e) for e in res.get("domains", [])] +
        [("url",    e) for e in res.get("urls",    [])] +
        [("cve",    e) for e in res.get("cves",    [])] +
        [(f"hash_{ht}", e) for ht, entries in res.get("hashes",{}).items() for e in entries]
    )
    for ioc_type, e in all_entries:
        if e["severity"] in ("CRITICAL", "HIGH"):
            found = True
            c   = _severity_color(e["severity"])
            new = " [magenta][NEW][/magenta]" if e.get("is_new") else ""
            console.print(f"  [{c}]{e['severity']}[/{c}]{new}  [{ioc_type}]  {e['value'][:100]}")
    if not found:
        console.print("  [green]None[/green]")


#  Email alert 

def send_email_alert(report, cfg):
    """
    Send an HTML email listing CRITICAL/HIGH findings.
    Uses STARTTLS — works with Gmail App Passwords and most SMTP servers.

    Gmail setup:
      1. Enable 2-factor authentication
      2. Go to Google Account → Security → App Passwords
      3. Generate an App Password and put it in config.yaml email.password
    """
    email_cfg = cfg.get("email", {})
    if not email_cfg.get("enabled"):
        return

    alert_sevs = set(email_cfg.get("send_on", ["CRITICAL", "HIGH"]))
    res        = report["results"]
    findings   = []

    all_entries = (
        [("ipv4",   e) for e in res.get("ipv4",    [])] +
        [("ipv6",   e) for e in res.get("ipv6",    [])] +
        [("domain", e) for e in res.get("domains", [])] +
        [("url",    e) for e in res.get("urls",    [])] +
        [(f"hash_{ht}", e) for ht, entries in res.get("hashes",{}).items() for e in entries]
    )
    for ioc_type, e in all_entries:
        if e.get("severity") in alert_sevs:
            findings.append((ioc_type, e))

    if not findings:
        return

    s   = report["summary"]
    rows = "".join(
        f"<tr><td style='color:{'#ef4444' if e['severity']=='CRITICAL' else '#f97316'}"
        f";font-weight:bold'>{e['severity']}</td>"
        f"<td>{ioc_type}</td><td style='font-family:monospace'>{e['value']}</td>"
        f"<td>{'NEW' if e.get('is_new') else 'SEEN'}</td></tr>"
        for ioc_type, e in findings
    )

    html_body = f"""
    <html><body style="font-family:sans-serif;background:#0f1117;color:#e2e8f0;padding:20px">
    <h2>IOC Alert — {s.get('CRITICAL',0)} Critical, {s.get('HIGH',0)} High findings</h2>
    <p>Scan time: {report['scan_time']}</p>
    <table border="1" cellpadding="6" cellspacing="0"
           style="border-collapse:collapse;width:100%;border-color:#333">
    <tr style="background:#1a1d27">
      <th>Severity</th><th>Type</th><th>Value</th><th>Status</th>
    </tr>
    {rows}
    </table>
    <p style="color:#8892a4;font-size:12px;margin-top:20px">
    See attached report for full details.</p>
    </body></html>
    """

    msg             = MIMEMultipart("alternative")
    msg["Subject"]  = f"[IOC ALERT] {len(findings)} Critical/High IOCs detected"
    msg["From"]     = email_cfg["sender"]
    msg["To"]       = ", ".join(email_cfg.get("recipients", []))
    msg.attach(MIMEText(html_body, "html"))

    try:
        with smtplib.SMTP(email_cfg["smtp_host"], email_cfg["smtp_port"]) as server:
            server.starttls()
            server.login(email_cfg["sender"], email_cfg["password"])
            server.send_message(msg)
        console.print(f"[green]Email alert sent to {msg['To']}[/green]")
    except Exception as e:
        console.print(f"[red]Email failed: {e}[/red]")
