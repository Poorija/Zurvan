# Zurvan Tool Stack Audit

This document captures the cleaned-up tool strategy for Zurvan after auditing the codebase, local availability, and upstream tool status.

## Core Tools

- Network discovery: `nmap`
- Passive subdomain discovery: `subfinder`
- HTTP probing: `httpx`
- Fast port discovery: `naabu` (recommended addition)
- Web content discovery: `ffuf`, `dirsearch`, `gobuster`
- Vulnerability scanning: `nuclei`, `OWASP ZAP`
- Secrets scanning: `trufflehog`
- SQL injection: `sqlmap`
- Password cracking: `hashcat`
- OSINT automation: `spiderfoot`, `theHarvester`, `maigret`

## Keep But De-Emphasize

- `sublist3r`: still usable, but `subfinder` should be the default passive subdomain workflow.
- `sherlock`: keep as optional; `maigret` is the stronger default username tool.
- `whatweb`: useful for quick fingerprints, but `httpx` overlaps with part of its value.
- `rustscan`: optional fast pre-scan, but overlaps with `naabu`, `masscan`, and `nmap`.
- `john`: keep for compatibility, but `hashcat` remains the default.

## Legacy / Not Core

- `phoneinfoga`: upstream explicitly says the project is stable but unmaintained.
- `photon`: legacy crawler; prefer `katana` as the modern crawler.
- `nikto`: useful for legacy checks, but `nuclei` and `OWASP ZAP` should be the main web scanning defaults.

## Recommended Additions

- `naabu`: modern port scan stage before deeper `nmap` service/version enumeration.
- `katana`: modern web crawler/spider for endpoint discovery.
- `OWASP Amass`: deeper external attack-surface mapping for domains and organizations.
- `Feroxbuster`: strong recursive content discovery option for larger web targets.

## Overlap Notes

- Subdomain discovery overlap: `subfinder`, `sublist3r`, `fierce`, `amass`
- Username OSINT overlap: `maigret`, `sherlock`, `social-analyzer`
- Web content discovery overlap: `ffuf`, `dirsearch`, `gobuster`, `katana`
- Port scanning overlap: `nmap`, `naabu`, `rustscan`, `masscan`
- Web vulnerability scanning overlap: `nikto`, `nuclei`, `OWASP ZAP`
- Password cracking overlap: `hashcat`, `john`

## UI Cleanup Applied

- Removed duplicate `RustScan`, `enum4linux-ng`, `Nuclei`, and `TruffleHog` entries from the Advanced Tools tab.
- Added modern maintained tools to the in-app community recommendations list.
