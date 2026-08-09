import re
import json
import csv
import os

IGNORE_DOMAINS = {"localhost","local","internal","private","example.com"}


def parse_log(log_file):
    """Parse a log file and return sorted unique IOC's."""

    #Check if file exists before opening
    if not os.path.exists(log_file):
        print(f"Error: File '{log_file}' not found.")
        return {"ipv4": [], "ipv6": [], "domains": [], "urls": [], "hashes": {"md5": [], "sha1": [], "sha256": []}, "emails": [], "cves": []}

    ip_pattern = re.compile(r"\b(?:\d{1,3}(?:\.\d{1,3}){3}|[A-Fa-f0-9:]{2,45})\b")
    domain_pattern = re.compile(r"\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)"r"+(?:com|net|org|edu|gov|io|co|uk|de|ru|cn|info|biz|me)\b")
    url_pattern = re.compile(r"https?://[^\s\"'<>]+", re.IGNORECASE)
    md5_pattern    = re.compile(r"\b[a-fA-F0-9]{32}\b")
    sha1_pattern   = re.compile(r"\b[a-fA-F0-9]{40}\b")
    sha256_pattern = re.compile(r"\b[a-fA-F0-9]{64}\b")
    email_pattern = re.compile(
    r"\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b")
    cve_pattern = re.compile(
    r"\bCVE-\d{4}-\d{4,7}\b")    
   
    #Storage for unique IOCs
    iocs = {
        "ipv4": set(),
        "ipv6": set(),
        "domains": set(),
        "urls": set(),
        "hashes": {"md5": set(), "sha1": set(), "sha256": set()},
        "emails": set(),
        "cves": set()
    }
    
    with open(log_file, "r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            for candidate in ip_pattern.findall(line):
                candidate = candidate.strip(".:")

                #  Handle IPv4 candidates
                if "." in candidate:
                    parts = candidate.split(".")
                    if len(parts) == 4 and all(
                        part.isdigit() and 0 <= int(part) <= 255
                        for part in parts
                    ):
                        iocs["ipv4"].add(candidate)

                #  Handle IPv6 candidates
                elif ":" in candidate:
                    #  Skip MAC addresses explicitly
                    if re.match(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$", candidate):
                        continue

                    if re.match(r"^\d{1,2}:\d{2}:\d{2}$", candidate):
                        continue

                    #  Corrected character class to also block uppercase G-Z
                    if (
                        candidate.count(":") >= 2
                        and not re.search(r"[g-zG-Z]", candidate)
                        and len(candidate) <= 39
                    ):
                        iocs["ipv6"].add(candidate.lower())

            for url in url_pattern.findall(line):
                iocs["urls"].add(url.strip(".,\"'>"))

            for domain in domain_pattern.findall(line):
                if domain.lower() not in IGNORE_DOMAINS:
                   iocs["domains"].add(domain.lower())

            for h in sha256_pattern.findall(line):
                iocs["hashes"]["sha256"].add(h.lower())                         

            for h in sha1_pattern.findall(line):
                iocs["hashes"]["sha1"].add(h.lower())

            for h in md5_pattern.findall(line):
                iocs["hashes"]["md5"].add(h.lower())

            for email in email_pattern.findall(line):
                iocs["emails"].add(email.lower())

            for cve in cve_pattern.findall(line):
                iocs["cves"].add(cve.upper())

    return {
        "ipv4": sorted(iocs["ipv4"]),
        "ipv6": sorted(iocs["ipv6"]),
        "domains": sorted(iocs["domains"]),
        "urls": sorted(iocs["urls"]),
        "hashes": {
            "md5": sorted(iocs["hashes"]["md5"]),
            "sha1": sorted(iocs["hashes"]["sha1"]),
            "sha256": sorted(iocs["hashes"]["sha256"])
        },
        "emails": sorted(iocs["emails"]),
        "cves": sorted(iocs["cves"])
    }



def save_iocs(iocs, output_file):
    """Save the extracted IOCs to a JSON or CSV file based on the output file extension."""
    _, ext = os.path.splitext(output_file)
    ext = ext.lower()

    if ext == ".json":
        with open(output_file, "w", encoding="utf-8") as f:
            json.dump(iocs, f, indent=2)
    else:
        with open(output_file, "w", newline="", encoding="utf-8") as f:
            writer = csv.writer(f)
            writer.writerow(["type", "subtype", "value"])
            for ip in iocs["ipv4"]:
                writer.writerow(["ip", "ipv4", ip])
            for ip in iocs["ipv6"]:
                writer.writerow(["ip", "ipv6", ip])
            for domain in iocs["domains"]:
                writer.writerow(["domain", "", domain])
            for url in iocs["urls"]:
                writer.writerow(["url", "", url])
            for md5 in iocs["hashes"]["md5"]:
                writer.writerow(["hash", "md5", md5])
            for sha1 in iocs["hashes"]["sha1"]:
                writer.writerow(["hash", "sha1", sha1])
            for sha256 in iocs["hashes"]["sha256"]:
                writer.writerow(["hash", "sha256", sha256])
            for email in iocs["emails"]:
                writer.writerow(["email", "", email])
            for cve in iocs["cves"]:
                writer.writerow(["cve", "", cve])

def main():
    import argparse

    parser = argparse.ArgumentParser(description="Parse a log file and extract unique IOCs.")
    parser.add_argument("log_file", help="Path to the log file")
    parser.add_argument("-o", "--output", default="unique_iocs.json", help="Output file path (json or csv)")
    args = parser.parse_args()

    iocs = parse_log(args.log_file)
    save_iocs(iocs, args.output)


    total = (
        len(iocs["ipv4"])
        + len(iocs["ipv6"])
        + len(iocs["domains"])
        + len(iocs["urls"])
        + len(iocs["hashes"]["md5"])
        + len(iocs["hashes"]["sha1"])
        + len(iocs["hashes"]["sha256"])
        + len(iocs["emails"])
        + len(iocs["cves"])
    )
     
    print(f"\n IOCs extracted: ")
    print(f"IPv4: {len(iocs['ipv4'])}")
    print(f"IPv6: {len(iocs['ipv6'])}") 
    print(f"Domains: {len(iocs['domains'])}")
    print(f"URLs: {len(iocs['urls'])}")
    print(f"MD5 Hashes: {len(iocs['hashes']['md5'])}")
    print(f"SHA1 Hashes: {len(iocs['hashes']['sha1'])}")
    print(f"SHA256 Hashes: {len(iocs['hashes']['sha256'])}")
    print(f"Emails: {len(iocs['emails'])}")
    print(f"CVE Identifiers: {len(iocs['cves'])}") 
    print(f"Total unique IOCs extracted: {total}")

if __name__ == "__main__":
    main()