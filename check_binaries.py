import argparse
import glob
import json
import os
import shutil
import sys


TOOLS = [
    {
        "name": "nmap",
        "category": "core-network",
        "availability": ["nmap"],
        "local_paths": [],
        "status": "core",
        "notes": "Primary network scanner and service detection engine.",
        "overlap": ["masscan", "rustscan", "naabu"],
    },
    {
        "name": "subfinder",
        "category": "core-recon",
        "availability": ["subfinder"],
        "local_paths": ["subfinder/subfinder"],
        "status": "core",
        "notes": "Preferred passive subdomain enumerator.",
        "overlap": ["sublist3r", "fierce", "amass"],
    },
    {
        "name": "httpx",
        "category": "core-web",
        "availability": ["httpx"],
        "local_paths": ["httpx/httpx"],
        "status": "core",
        "notes": "Preferred live-host and HTTP probe stage after subdomain discovery.",
        "overlap": ["whatweb"],
    },
    {
        "name": "naabu",
        "category": "recommended-addition",
        "availability": ["naabu"],
        "local_paths": ["naabu/naabu"],
        "status": "recommended",
        "notes": "Modern fast port scanner that complements Nmap.",
        "overlap": ["masscan", "rustscan", "nmap"],
    },
    {
        "name": "katana",
        "category": "recommended-addition",
        "availability": ["katana"],
        "local_paths": ["katana/katana"],
        "status": "recommended",
        "notes": "Modern crawling and spidering framework for web recon.",
        "overlap": ["photon", "dirsearch", "ffuf"],
    },
    {
        "name": "nuclei",
        "category": "core-web",
        "availability": ["nuclei"],
        "local_paths": ["nuclei/nuclei"],
        "status": "core",
        "notes": "Actively maintained templated vulnerability scanner.",
        "overlap": ["zap", "nikto"],
    },
    {
        "name": "trufflehog",
        "category": "core-secrets",
        "availability": ["trufflehog"],
        "local_paths": ["trufflehog/trufflehog"],
        "status": "core",
        "notes": "Preferred secret scanning engine in this stack.",
        "overlap": [],
    },
    {
        "name": "maigret",
        "category": "core-osint",
        "availability": ["maigret"],
        "local_paths": [],
        "status": "core",
        "notes": "Preferred username OSINT tool.",
        "overlap": ["sherlock", "social-analyzer"],
    },
    {
        "name": "sherlock",
        "category": "legacy-overlap",
        "availability": ["sherlock"],
        "local_paths": ["Sherlock/sherlock/sherlock.py"],
        "status": "keep-optional",
        "notes": "Useful, but overlaps heavily with Maigret.",
        "overlap": ["maigret", "social-analyzer"],
    },
    {
        "name": "social-analyzer",
        "category": "legacy-overlap",
        "availability": ["social-analyzer"],
        "local_paths": ["social-analyzer/app.py"],
        "status": "keep-optional",
        "notes": "Useful for niche cases, but overlaps with Maigret and Sherlock.",
        "overlap": ["maigret", "sherlock"],
    },
    {
        "name": "spiderfoot",
        "category": "core-osint",
        "availability": ["spiderfoot-cli", "spiderfoot"],
        "local_paths": ["spiderfoot/sf.py"],
        "status": "core",
        "notes": "Attack-surface and OSINT automation hub.",
        "overlap": ["recon-ng", "theharvester"],
    },
    {
        "name": "theharvester",
        "category": "core-osint",
        "availability": ["theHarvester", "theharvester"],
        "local_paths": ["theHarvester/bin/theHarvester", "theHarvester/theHarvester/__main__.py"],
        "status": "core",
        "notes": "Email/domain recon collector.",
        "overlap": ["spiderfoot", "recon-ng"],
    },
    {
        "name": "phoneinfoga",
        "category": "legacy-osint",
        "availability": ["phoneinfoga"],
        "local_paths": ["PhoneInfoga/bin/phoneinfoga"],
        "status": "legacy",
        "notes": "Upstream is stable but unmaintained; keep disabled unless explicitly needed.",
        "overlap": [],
    },
    {
        "name": "photon",
        "category": "legacy-osint",
        "availability": ["photon"],
        "local_paths": ["Photon/photon.py"],
        "status": "legacy",
        "notes": "Legacy crawler. Katana is the more modern addition.",
        "overlap": ["katana", "dirsearch", "ffuf"],
    },
    {
        "name": "metagoofil",
        "category": "optional-osint",
        "availability": ["metagoofil"],
        "local_paths": ["metagoofil/metagoofil.py"],
        "status": "optional",
        "notes": "Document metadata collection remains useful, but niche.",
        "overlap": [],
    },
    {
        "name": "whatweb",
        "category": "optional-web",
        "availability": ["whatweb"],
        "local_paths": ["WhatWeb/bin/whatweb", "WhatWeb/whatweb"],
        "status": "optional",
        "notes": "Technology fingerprinting. httpx already covers part of this space.",
        "overlap": ["httpx"],
    },
    {
        "name": "nikto",
        "category": "optional-web",
        "availability": ["nikto"],
        "local_paths": ["nikto/bin/nikto", "nikto/program/nikto.pl", "nikto/nikto.pl"],
        "status": "optional",
        "notes": "Legacy web scanner. Nuclei and ZAP are stronger modern defaults.",
        "overlap": ["nuclei", "zap"],
    },
    {
        "name": "gobuster",
        "category": "core-web",
        "availability": ["gobuster"],
        "local_paths": ["gobuster/gobuster"],
        "status": "core",
        "notes": "Fast content discovery.",
        "overlap": ["dirsearch", "ffuf", "katana"],
    },
    {
        "name": "dirsearch",
        "category": "core-web",
        "availability": ["dirsearch"],
        "local_paths": ["dirsearch/dirsearch.py"],
        "status": "core",
        "notes": "Rich recursive content discovery with Python workflows.",
        "overlap": ["gobuster", "ffuf", "katana"],
    },
    {
        "name": "ffuf",
        "category": "core-web",
        "availability": ["ffuf"],
        "local_paths": ["ffuf/ffuf"],
        "status": "core",
        "notes": "Preferred high-performance web fuzzing engine.",
        "overlap": ["dirsearch", "gobuster"],
    },
    {
        "name": "masscan",
        "category": "optional-network",
        "availability": ["masscan"],
        "local_paths": ["masscan/bin/masscan", "masscan/masscan"],
        "status": "optional",
        "notes": "Internet-scale scanner. Keep for high-speed surveys only.",
        "overlap": ["naabu", "rustscan", "nmap"],
    },
    {
        "name": "rustscan",
        "category": "optional-network",
        "availability": ["rustscan"],
        "local_paths": ["rustscan/rustscan"],
        "status": "optional",
        "notes": "Fast local pre-scan wrapper around Nmap.",
        "overlap": ["naabu", "masscan", "nmap"],
    },
    {
        "name": "sqlmap",
        "category": "core-attack",
        "availability": ["sqlmap"],
        "local_paths": ["sqlmap/sqlmap.py"],
        "status": "core",
        "notes": "Core SQL injection automation tool.",
        "overlap": [],
    },
    {
        "name": "zap",
        "category": "core-web",
        "availability": ["zap.sh", "zap"],
        "local_paths": [
            "/Applications/ZAP.app/Contents/MacOS/zap.sh",
            "/Applications/OWASP ZAP.app/Contents/MacOS/zap.sh",
            "/opt/homebrew/Caskroom/zap/*/ZAP.app/Contents/MacOS/zap.sh",
        ],
        "status": "core",
        "notes": "DAST and automation framework for web applications.",
        "overlap": ["nikto", "nuclei"],
    },
    {
        "name": "hashcat",
        "category": "core-password",
        "availability": ["hashcat"],
        "local_paths": ["hashcat/hashcat"],
        "status": "core",
        "notes": "Preferred password cracking engine.",
        "overlap": ["john"],
    },
    {
        "name": "john",
        "category": "optional-password",
        "availability": ["john"],
        "local_paths": ["john/run/john"],
        "status": "optional",
        "notes": "Keep for format compatibility and niche workflows.",
        "overlap": ["hashcat"],
    },
    {
        "name": "wifite",
        "category": "optional-wireless",
        "availability": ["wifite"],
        "local_paths": ["wifite2/Wifite.py"],
        "status": "optional",
        "notes": "Wireless automation helper, requires Linux/monitor mode.",
        "overlap": [],
    },
]


def resolve_tool(tool):
    for candidate in tool["availability"]:
        path = shutil.which(candidate)
        if path:
            return {"available": True, "source": "PATH", "path": path}

    for rel in tool["local_paths"]:
        if os.path.isabs(rel) or "*" in rel or "?" in rel or "[" in rel:
            matches = sorted(glob.glob(rel))
            if matches:
                return {"available": True, "source": "local", "path": matches[0]}
            if os.path.isabs(rel) and os.path.exists(rel):
                return {"available": True, "source": "local", "path": rel}
            continue

        local_path = os.path.abspath(os.path.join("tools", rel))
        if os.path.exists(local_path):
            return {"available": True, "source": "local", "path": local_path}

    return {"available": False, "source": None, "path": None}


def build_report():
    report = []
    for tool in TOOLS:
        resolved = resolve_tool(tool)
        report.append({**tool, **resolved})
    return report


def print_human(report):
    grouped = {}
    for item in report:
        grouped.setdefault(item["status"], []).append(item)

    order = ["core", "optional", "keep-optional", "legacy", "recommended"]
    for status in order:
        items = grouped.get(status, [])
        if not items:
            continue
        print(f"\n[{status.upper()}]")
        for item in items:
            state = "OK" if item["available"] else "MISSING"
            path = item["path"] or "-"
            print(f" - {item['name']}: {state} ({item['source'] or 'unresolved'})")
            print(f"   path: {path}")
            print(f"   notes: {item['notes']}")
            if item["overlap"]:
                print(f"   overlap: {', '.join(item['overlap'])}")

    missing_core = [item["name"] for item in report if item["status"] == "core" and not item["available"]]
    if missing_core:
        print("\n[SUMMARY] Missing core tools:")
        for name in missing_core:
            print(f" - {name}")
    else:
        print("\n[SUMMARY] All core tools are available.")


def main():
    parser = argparse.ArgumentParser(description="Audit Zurvan external tool availability.")
    parser.add_argument("--json", action="store_true", help="Emit JSON instead of human-readable output.")
    args = parser.parse_args()

    report = build_report()
    if args.json:
        print(json.dumps(report, indent=2))
    else:
        print_human(report)

    missing_core = any(item["status"] == "core" and not item["available"] for item in report)
    sys.exit(1 if missing_core else 0)


if __name__ == "__main__":
    main()
