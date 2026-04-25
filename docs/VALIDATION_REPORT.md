# Zurvan Validation Report

Generated on `2026-04-18`.

## Capability Cleanup

- Removed duplicate entries from the Advanced Tools tab: `RustScan`, `enum4linux-ng`, `Nuclei`, `TruffleHog`.
- Kept the practical core stack centered on:
  - `nmap`, `subfinder`, `httpx`, `naabu`
  - `ffuf`, `dirsearch`, `gobuster`, `katana`
  - `nuclei`, `OWASP ZAP`, `nikto`, `whatweb`
  - `spiderfoot`, `theHarvester`, `maigret`, `sherlock`
  - `sqlmap`, `trufflehog`, `hashcat`

## Fixes Applied

- Added missing Qt dependency: `PyQt6-WebEngine`.
- Added missing SVG icon assets required by the UI.
- Fixed duplicate `QApplication` creation in the app bootstrap path.
- Hardened speed test parsing for both modern and legacy CLI JSON formats.
- Added proper local tool fallbacks and wrapper launchers for:
  - `theHarvester`
  - `Nikto`
  - `WhatWeb`
- Updated ZAP discovery to support common macOS app/cask locations.
- Installed and validated current practical toolchain for this checkout.

## Verified Commands

- `python -m py_compile zurvan.py check_binaries.py speed_test_tab.py smoke_test.py`
- `python smoke_test.py`
- `python check_binaries.py`
- `tools/WhatWeb/bin/whatweb --version`
- `tools/nikto/bin/nikto -Version`
- `python tools/spiderfoot/sf.py -h`
- `tools/theHarvester/bin/theHarvester --help`
- `maigret --help`
- `zap.sh -version` via installed macOS ZAP app bundle

## Current Result

- All core tools in the curated audit are available on this machine.
- Main smoke checks passed for:
  - database initialization
  - default admin credential validation
  - login dialog construction
  - main window construction

## Remaining Non-Core Gaps

- `metagoofil`
- `john`
- `wifite`
- `social-analyzer`
- `phoneinfoga` intentionally left disabled as a legacy/unmaintained tool
- `photon` intentionally left de-emphasized in favor of `katana`

## Known Minor Note

- Qt still emits a non-fatal font warning about missing `"Sans Serif"` aliasing during offscreen smoke startup on this machine.
