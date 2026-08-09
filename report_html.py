"""
report_html.py — Self-contained HTML report generator.

Produces a single .html file with inline CSS and JS (no external dependencies) that can be opened in any browser.

Features:
  - Severity-coloured rows (CRITICAL → red, HIGH → orange, MEDIUM → yellow …)
  - NEW badge on IOCs seen for the first time
  - Filter buttons: All | Critical | High | Medium | Low | Clean | New Only
  - Summary cards at the top (total + per-severity counts)
  - Shodan ports, VT detections, AbuseIPDB score, OTX pulses all in one table
"""

from html import escape


#  Helpers 

def _sev_color(sev):
    return {
        "CRITICAL":    "#ef4444",
        "HIGH":        "#f97316",
        "MEDIUM":      "#eab308",
        "LOW":         "#3b82f6",
        "CLEAN":       "#22c55e",
        "INFO":        "#8892a4",
        "WHITELISTED": "#4b5563",
    }.get(sev, "#8892a4")


def _make_row(ioc_type, entry):
    sev     = entry.get("severity", "CLEAN")
    value   = entry.get("value",    "")
    is_new  = entry.get("is_new",   False)
    sources = entry.get("sources",  {})

    vt  = sources.get("virustotal",    {}) or {}
    ab  = sources.get("abuseipdb",     {}) or {}
    otx = sources.get("otx",           {}) or {}
    sh  = sources.get("shodan",        {}) or {}
    bz  = sources.get("malwarebazaar", {}) or {}
    uh  = sources.get("urlhaus",       {}) or {}
    nv  = sources.get("nvd",           {}) or {}

    # VirusTotal - show malicious/total engines
    vt_total = sum(vt.get(k, 0) for k in ("malicious", "suspicious", "harmless", "undetected"))
    vt_text  = f"{vt.get('malicious', 0)}/{vt_total}" if vt.get("found") else "—"

    abuse_text = f"{ab.get('confidence_score', '—')}%" if ab else "—"
    otx_text   = str(otx.get("pulse_count", "—")) if otx else "—"
    ports_text = ", ".join(str(p) for p in sh.get("open_ports", [])[:8]) if sh else "—"

    # Extra column: malware name, URLhaus status, or CVSS score
    extras = []
    if bz.get("found"):
        extras.append(f"Malware: {bz.get('malware_name', 'unknown')}")
    if uh.get("active"):
        extras.append("URLhaus: active")
    elif uh.get("found"):
        extras.append("URLhaus: inactive")
    if nv.get("found"):
        extras.append(f"CVSS: {nv.get('cvss_score')} {nv.get('cvss_severity','')}")
    if sh.get("vulns"):
        extras.append(f"Shodan vulns: {', '.join(sh['vulns'][:3])}")
    extra_text = " | ".join(extras) if extras else "—"

    color      = _sev_color(sev)
    new_badge  = '<span style="color:#a855f7;border:1px solid #a855f7;border-radius:3px;padding:1px 5px;font-size:10px;font-weight:700;margin-left:6px">NEW</span>' if is_new else ""
    seen_label = "NEW" if is_new else "SEEN"

    return (
        f'<tr data-severity="{escape(sev)}" data-new="{str(is_new).lower()}">'
        f'<td><span style="color:{color};border:1px solid {color};border-radius:4px;'
        f'padding:2px 8px;font-size:11px;font-weight:700">{escape(sev)}</span></td>'
        f'<td style="color:#8892a4;font-size:12px">{escape(ioc_type)}</td>'
        f'<td style="font-family:monospace;font-size:13px;word-break:break-all">'
        f'{escape(value)}{new_badge}</td>'
        f'<td style="font-size:12px;color:{"#a855f7" if is_new else "#8892a4"}">{seen_label}</td>'
        f'<td style="text-align:right">{escape(vt_text)}</td>'
        f'<td style="text-align:right">{escape(abuse_text)}</td>'
        f'<td style="text-align:right">{escape(otx_text)}</td>'
        f'<td style="font-family:monospace;font-size:12px;color:#8892a4">{escape(ports_text)}</td>'
        f'<td style="font-size:12px;color:#8892a4">{escape(extra_text)}</td>'
        f'</tr>\n'
    )


def _collect_rows(results):
    rows = []
    for e in results.get("ipv4",    []): rows.append(_make_row("ipv4",   e))
    for e in results.get("ipv6",    []): rows.append(_make_row("ipv6",   e))
    for e in results.get("domains", []): rows.append(_make_row("domain", e))
    for e in results.get("urls",    []): rows.append(_make_row("url",    e))
    for e in results.get("emails",  []): rows.append(_make_row("email",  e))
    for e in results.get("cves",    []): rows.append(_make_row("cve",    e))
    for ht, entries in results.get("hashes", {}).items():
        for e in entries:
            rows.append(_make_row(f"hash_{ht}", e))
    return "".join(rows)


#  Main generator 

def generate_html_report(report, output_file):
    """
    Write a self-contained HTML report to output_file.
    report - the dict returned by enrich_iocs()
    """
    s        = report["summary"]
    results  = report["results"]
    log_files = ", ".join(report.get("log_files", [])) or "—"
    rows_html = _collect_rows(results)

    # Active sources line
    from enrich import (ABUSEIPDB_KEY, VIRUSTOTAL_KEY, OTX_KEY, SHODAN_KEY)
    sources = []
    if ABUSEIPDB_KEY:  sources.append("AbuseIPDB")
    if VIRUSTOTAL_KEY: sources.append("VirusTotal")
    if OTX_KEY:        sources.append("OTX")
    if SHODAN_KEY:     sources.append("Shodan")
    sources += ["URLhaus", "MalwareBazaar", "NVD"]
    sources_str = ", ".join(sources)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>IOC Enrichment Report — {escape(report['scan_time'])}</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0f1117;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;font-size:14px}}

  header{{background:#1a1d27;border-bottom:1px solid #2d3148;padding:20px 32px}}
  header h1{{font-size:20px;font-weight:600;margin-bottom:4px}}
  header p{{color:#8892a4;font-size:13px;margin-top:4px}}

  .summary{{display:flex;gap:16px;padding:20px 32px;flex-wrap:wrap}}
  .card{{background:#1a1d27;border:1px solid #2d3148;border-radius:8px;
         padding:16px 24px;min-width:110px}}
  .card .num{{font-size:28px;font-weight:700}}
  .card .lbl{{font-size:12px;color:#8892a4;margin-top:2px}}

  .filters{{padding:0 32px 16px;display:flex;gap:8px;flex-wrap:wrap;align-items:center}}
  .filters span{{color:#8892a4;font-size:13px;margin-right:4px}}
  button{{background:#1a1d27;border:1px solid #2d3148;border-radius:6px;
          padding:6px 14px;cursor:pointer;font-size:13px;color:#e2e8f0}}
  button.active,button:hover{{border-color:#8892a4}}

  .wrap{{padding:0 32px 40px;overflow-x:auto}}
  table{{width:100%;border-collapse:collapse;min-width:900px}}
  th{{background:#1a1d27;padding:10px 12px;text-align:left;font-weight:600;
      font-size:11px;color:#8892a4;text-transform:uppercase;letter-spacing:.05em;
      border-bottom:1px solid #2d3148;white-space:nowrap}}
  td{{padding:9px 12px;border-bottom:1px solid #1e2130;vertical-align:top}}
  tr:hover td{{background:rgba(255,255,255,.02)}}

  footer{{text-align:center;color:#4b5563;font-size:12px;padding:20px}}
</style>
</head>
<body>

<header>
  <h1>IOC Enrichment Report</h1>
  <p>Generated: {escape(report['scan_time'])}</p>
  <p>Log files: {escape(log_files)}</p>
  <p>Sources: {escape(sources_str)}</p>
</header>

<div class="summary">
  <div class="card">
    <div class="num">{s.get('total', 0)}</div>
    <div class="lbl">Total IOCs</div>
  </div>
  <div class="card" style="border-color:#ef4444">
    <div class="num" style="color:#ef4444">{s.get('CRITICAL', 0)}</div>
    <div class="lbl">Critical</div>
  </div>
  <div class="card" style="border-color:#f97316">
    <div class="num" style="color:#f97316">{s.get('HIGH', 0)}</div>
    <div class="lbl">High</div>
  </div>
  <div class="card" style="border-color:#eab308">
    <div class="num" style="color:#eab308">{s.get('MEDIUM', 0)}</div>
    <div class="lbl">Medium</div>
  </div>
  <div class="card" style="border-color:#3b82f6">
    <div class="num" style="color:#3b82f6">{s.get('LOW', 0)}</div>
    <div class="lbl">Low</div>
  </div>
  <div class="card" style="border-color:#22c55e">
    <div class="num" style="color:#22c55e">{s.get('CLEAN', 0)}</div>
    <div class="lbl">Clean</div>
  </div>
  <div class="card" style="border-color:#a855f7">
    <div class="num" style="color:#a855f7">{s.get('new', 0)}</div>
    <div class="lbl">New IOCs</div>
  </div>
  <div class="card">
    <div class="num" style="color:#4b5563">{s.get('WHITELISTED', 0)}</div>
    <div class="lbl">Whitelisted</div>
  </div>
</div>

<div class="filters">
  <span>Filter:</span>
  <button class="active" onclick="filter(this,'ALL')">All</button>
  <button style="color:#ef4444" onclick="filter(this,'CRITICAL')">Critical</button>
  <button style="color:#f97316" onclick="filter(this,'HIGH')">High</button>
  <button style="color:#eab308" onclick="filter(this,'MEDIUM')">Medium</button>
  <button style="color:#3b82f6" onclick="filter(this,'LOW')">Low</button>
  <button style="color:#22c55e" onclick="filter(this,'CLEAN')">Clean</button>
  <button style="color:#a855f7" onclick="filter(this,'NEW')">New Only</button>
</div>

<div class="wrap">
<table id="t">
<thead>
<tr>
  <th>Severity</th>
  <th>Type</th>
  <th>Value</th>
  <th>Status</th>
  <th>VT Det.</th>
  <th>Abuse%</th>
  <th>OTX</th>
  <th>Shodan Ports</th>
  <th>Extra</th>
</tr>
</thead>
<tbody>
{rows_html}
</tbody>
</table>
</div>

<footer>IOC Enrichment Tool &mdash; {escape(report['scan_time'])}</footer>

<script>
function filter(btn, sev) {{
  document.querySelectorAll('button').forEach(b => b.classList.remove('active'));
  btn.classList.add('active');
  document.querySelectorAll('#t tbody tr').forEach(r => {{
    if (sev === 'ALL') {{ r.style.display = ''; return; }}
    if (sev === 'NEW') {{ r.style.display = r.dataset.new === 'true' ? '' : 'none'; return; }}
    r.style.display = r.dataset.severity === sev ? '' : 'none';
  }});
}}
</script>
</body>
</html>"""

    with open(output_file, "w", encoding="utf-8") as f:
        f.write(html)
