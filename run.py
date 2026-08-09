"""
run.py — Single entry point for the full IOC pipeline.

  Step 1: Load config + whitelist
  Step 2: Collect log files (supports multiple files and glob patterns)
  Step 3: Extract IOCs from all log files and merge them
  Step 4: Enrich each IOC via threat intel APIs
  Step 5: Save JSON/CSV report + HTML report
  Step 6: Send email alert if CRITICAL/HIGH findings found

"""

import os
import sys
import glob as glob_module
import argparse
from itertools import chain

import yaml
from rich.console import Console
from rich.rule import Rule

from index       import parse_log
from cache       import IOCCache, IOCHistory
from enrich      import enrich_iocs, save_report, print_summary, send_email_alert
from report_html import generate_html_report

console = Console()


#  Config + whitelist loaders 

def load_config(path="config.yaml"):
    """Load config.yaml. Returns empty dict if file not found (all defaults apply)."""
    if not os.path.exists(path):
        console.print(f"[yellow]config.yaml not found — using defaults.[/yellow]")
        return {}
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


def load_whitelist(cfg):
    """Load whitelist.yaml path from config. Returns empty dict if not found."""
    wl_path = cfg.get("whitelist", {}).get("file", "whitelist.yaml")
    if not os.path.exists(wl_path):
        return {}
    with open(wl_path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f) or {}


#  Multi-file support 

def collect_files(patterns):
    """
    Expand glob patterns and collect unique log file paths.
    e.g. ['logs/*.log', 'extra.log'] → ['logs/a.log', 'logs/b.log', 'extra.log']
    """
    files = []
    for pattern in patterns:
        matched = glob_module.glob(pattern)
        if matched:
            files.extend(matched)
        elif os.path.exists(pattern):
            files.append(pattern)
        else:
            console.print(f"[yellow]Warning: '{pattern}' matched no files — skipping.[/yellow]")
    # Deduplicate while preserving order
    return list(dict.fromkeys(files))


def merge_iocs(ioc_list):
    """
    Merge IOC dicts from multiple log files, deduplicating across all of them.
    e.g. if file1 and file2 both contain 1.2.3.4, it appears only once.
    """
    return {
        key: sorted(set(chain.from_iterable(d.get(key, []) for d in ioc_list)))
        for key in ("ipv4", "ipv6", "domains", "urls", "emails", "cves")
    } | {
        "hashes": {
            ht: sorted(set(chain.from_iterable(
                d.get("hashes", {}).get(ht, []) for d in ioc_list
            )))
            for ht in ("md5", "sha1", "sha256")
        }
    }


def count_iocs(iocs):
    return (
        sum(len(iocs.get(k, [])) for k in ("ipv4","ipv6","domains","urls","emails","cves"))
        + sum(len(iocs.get("hashes",{}).get(h,[])) for h in ("md5","sha1","sha256"))
    )


# Main 

def main():
    parser = argparse.ArgumentParser(
        description="Extract IOCs from log files and enrich them via threat intel APIs."
    )
    parser.add_argument(
        "log_files", nargs="+",
        help="Log file(s) or glob patterns, e.g. access.log  or  logs/*.log"
    )
    parser.add_argument(
        "-o", "--output", default="enriched_report.json",
        help="Output file (.json or .csv)  [default: enriched_report.json]"
    )
    parser.add_argument(
        "--config", default="config.yaml",
        help="Path to config.yaml  [default: config.yaml]"
    )
    parser.add_argument(
        "--no-html", action="store_true",
        help="Skip generating the HTML report"
    )
    args = parser.parse_args()

    # ── Step 1: Load config + whitelist 
    console.print(Rule("[bold cyan]Step 1 — Loading Config[/bold cyan]"))
    cfg       = load_config(args.config)
    whitelist = load_whitelist(cfg)
    console.print(f"Config   : [bold]{args.config}[/bold]")
    console.print(f"Whitelist: [bold]{cfg.get('whitelist',{}).get('file','whitelist.yaml')}[/bold]")

    #  Step 2: Collect log files 
    console.print()
    console.print(Rule("[bold cyan]Step 2 — Collecting Log Files[/bold cyan]"))
    files = collect_files(args.log_files)
    if not files:
        console.print("[red]No log files found. Exiting.[/red]")
        sys.exit(1)
    console.print(f"Found [bold]{len(files)}[/bold] file(s):")
    for f in files:
        console.print(f"  {f}")

    #  Step 3: Extract + merge IOCs 
    console.print()
    console.print(Rule("[bold cyan]Step 3 — IOC Extraction[/bold cyan]"))
    all_iocs = []
    for log_file in files:
        console.print(f"  Parsing [bold]{log_file}[/bold]...")
        iocs = parse_log(log_file)
        all_iocs.append(iocs)
        console.print(
            f"    IPv4:{len(iocs.get('ipv4',[]))}  IPv6:{len(iocs.get('ipv6',[]))}  "
            f"Domains:{len(iocs.get('domains',[]))}  URLs:{len(iocs.get('urls',[]))}  "
            f"Hashes:{sum(len(iocs.get('hashes',{}).get(h,[])) for h in ('md5','sha1','sha256'))}  "
            f"CVEs:{len(iocs.get('cves',[]))}"
        )

    merged = merge_iocs(all_iocs)
    total  = count_iocs(merged)

    console.print(f"\n[bold]Total unique IOCs after merge: {total}[/bold]")
    if total == 0:
        console.print("[yellow]No IOCs found in any log file. Nothing to enrich.[/yellow]")
        sys.exit(0)

    #  Step 4: Enrich 
    console.print()
    console.print(Rule("[bold cyan]Step 4 — Threat Intel Enrichment[/bold cyan]"))

    # Set up cache
    cache_cfg = cfg.get("cache", {})
    cache = None
    if cache_cfg.get("enabled", True):
        cache = IOCCache(
            cache_file = cache_cfg.get("file", "cache.json"),
            ttl_days   = cache_cfg.get("ttl_days", 7),
        )
        console.print(f"Cache: [bold]{cache_cfg.get('file','cache.json')}[/bold]  "
                      f"({cache.size()} entries, TTL {cache_cfg.get('ttl_days',7)} days)")

    # Set up history
    history = IOCHistory(cfg.get("history", {}).get("file", "history.json"))
    console.print(f"History: [bold]{cfg.get('history',{}).get('file','history.json')}[/bold]  "
                  f"({history.total_tracked()} IOCs tracked so far)")

    report = enrich_iocs(merged, cfg=cfg, cache=cache, history=history, whitelist=whitelist)

    # Attach metadata
    report["log_files"] = files

    # Persist cache + history
    if cache:
        cache.save()
    history.save()

    #  Step 5: Save reports
    console.print()
    console.print(Rule("[bold cyan]Step 5 — Saving Reports[/bold cyan]"))

    save_report(report, args.output)
    console.print(f"[green]JSON/CSV report → {args.output}[/green]")

    html_enabled = not args.no_html and cfg.get("output", {}).get("html_report", True)
    if html_enabled:
        html_file = cfg.get("output", {}).get("html_file", "report.html")
        generate_html_report(report, html_file)
        console.print(f"[green]HTML report     → {html_file}[/green]")

    # Step 6: Email alert 
    if cfg.get("email", {}).get("enabled"):
        console.print()
        console.print(Rule("[bold cyan]Step 6 — Email Alert[/bold cyan]"))
        send_email_alert(report, cfg)

    #  Summary 
    print_summary(report)


if __name__ == "__main__":
    main()
