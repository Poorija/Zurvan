# Zurvan + AI - The Modern Scapy Interface with AI

**Version 3.0**

Zurvan + AI is a modern, feature-rich graphical user interface for the powerful Scapy packet manipulation library, now supercharged with AI analysis capabilities. Built with Python and PyQt6, it provides a user-friendly environment for network sniffing, packet crafting, and running various network tools for security testing and analysis.

### What's New in Version 3.0
- **User Accounts & Profiles:** The application now supports multiple user accounts with password protection and user avatars.
- **Admin Panel:** A dedicated panel for administrators to manage users, including changing emails and usernames.
- **Threat Intelligence:** A new tab to view the latest CVEs and search for exploits.
- **Advanced Reporting:** The reporting tab has been overhauled with a comprehensive ROE template, an offline CVE database, and AI-powered report generation features.
- **History & Auditing:** A new history tab tracks all actions performed by users, providing a complete audit trail (admin-only).

## Features

Zurvan is organized into a series of tabs, each dedicated to a specific function:

### 1. User Accounts & Profiles
- **Secure Login:** Support for multiple users with password-protected logins.
- **User Profiles:** Users can manage their own profile, including changing their email, password, and uploading a custom avatar.
- **Admin Panel:** A dedicated panel for administrators to manage all user accounts.

### 2. AI Assistant (New!)
- **Conversational Interface:** A redesigned, modern chat interface for interacting with local or online Large Language Models (LLMs).
- **Security Analysis:** Paste scan results, code, or configurations and ask the AI to analyze them for vulnerabilities, misconfigurations, or interesting patterns.
- **Guided Prompts:** A huge, built-in library of over 80 prompts for penetration testing, vulnerability analysis, reporting, and more.
- **Flexible Configuration:** Easily switch between local AI services (like Ollama or LMStudio) and online providers (like OpenAI) to fit your privacy and power needs.
- **Context-Aware Actions:** "Send to AI" buttons in various tools automatically format and load results into the assistant for quick analysis.

### 2. Packet Sniffer
- **Live Capture:** Start and stop sniffing packets on any selected network interface.
- **BPF Filtering:** Apply Berkeley Packet Filter (BPF) syntax (e.g., `tcp port 80`) to capture only the traffic you need.
- **Detailed View:** A powerful, Wireshark-like split view shows a packet summary list, a detailed, expandable tree of packet layers and fields, and a raw hex dump.
- **File I/O:** Save captured packets to a `.pcap` file for later analysis in other tools like Wireshark, or load existing pcap files into the sniffer.

### 3. Packet Crafter
- **Layer-by-Layer Construction:** Easily build custom packets by adding protocols from a dropdown list.
- **Dynamic Field Editor:** Select any layer in your packet stack to see and edit all of its fields.
- **Fuzzing:** Wrap any layer in a `fuzz()` call to randomize its fields for testing.
- **Packet Templates:** Quickly load pre-built packets for common tasks like ICMP pings and DNS queries.
- **Send & Receive:** Send your crafted packet(s) and view any responses received.

### 4. Network Tools
- **Nmap Scanner:** A comprehensive frontend for the Nmap network scanner.
    - **Live Output:** View Nmap's output in real-time as the scan progresses.
    - **Detailed Options:** Control scan types (SYN, TCP, UDP, etc.), timing, OS/service detection, and script scanning.
    - **Scan Presets:** Includes "All Ports" and "Super Complete Scan" buttons to quickly configure common, comprehensive scans.
    - **Post-Scan Summary:** An automatic pop-up dialog shows a clean summary of up hosts and open ports after each scan.
    - **HTML Reporting:** Generate a beautiful, interactive HTML report from your scan results with a single click (requires `lxml`).
- **Nikto Scanner:** A comprehensive frontend for the Nikto web server scanner, with detailed options for tuning, evasion, and output formats.
- **Gobuster:** A powerful tool for brute-forcing URIs (directories and files), DNS subdomains, and virtual host names. The UI supports detailed configuration for wordlists, extensions, status codes, and more.
- **WhatWeb:** Quickly identify technologies used on websites, including CMS, analytics packages, and server software, with configurable aggression levels.
- **Masscan:** An extremely fast TCP port scanner for large-scale network surveys. The UI allows for easy configuration of target ranges, ports, and scan rates.
- **Traceroute:** A graphical traceroute tool to map the path to a destination host.
- **Advanced Port Scanner:** A powerful, Scapy-based port scanner with multiple scan types (TCP SYN, FIN, Xmas, etc.) and an option for packet fragmentation.
- **ARP Scan:** Discover all active hosts on your local network segment.
- **Ping Sweep:** Quickly discover live hosts on a network using various probe types (ICMP, TCP, UDP).

### 5. Advanced Tools
- **SQLMap:** A full-featured UI for the powerful SQLMap tool to automatically detect and exploit SQL injection flaws. Includes extensive options for target/request configuration, injection techniques, and enumeration.
- **Hashcat:** A powerful frontend for the Hashcat password cracking tool. The UI supports multiple attack modes (dictionary, mask, hybrid), hash types, and wordlist/mask management.
- **Packet Flooder:** A network stress-testing tool to send a high volume of custom or templated packets (e.g., SYN, UDP, ICMP floods). Includes an ethical use warning.
- **Firewall Tester:** Probe a target with predefined sets of packets to test firewall rules and discover its ACLs.
- **ARP Spoofer:** A tool to perform ARP cache poisoning for Man-in-the-Middle (MITM) testing. Includes an ethical use warning.

### 6. Wireless Tools (802.11)
- **Wifite Auditor:** An interface for the Wifite tool to automate wireless network auditing (WPS, PMKID, WPA).
- **Wi-Fi Scanner:** Discover nearby Wi-Fi networks by sniffing for beacon frames. Features automatic channel hopping for better discovery (Linux only).
- **Deauthentication Tool:** A tool to send deauthentication packets for network security testing. Includes an ethical use warning.
- **Beacon Flood:** Create fake wireless networks by flooding the air with beacon frames.
- **WPA Handshake & Cracker:** A comprehensive tool to capture WPA/WPA2 handshakes and then crack the password using `aircrack-ng` with a provided wordlist. Includes a helper to generate wordlists with `crunch`.
- **KRACK Scanner:** Passively sniff for retransmitted EAPOL messages to detect networks vulnerable to Key Reinstallation Attacks (KRACK).

### 7. System & Community
- **System Info:** View detailed information about your system, including OS, CPU, memory, disk, and network interfaces in a modern card-style layout.
- **Community Tools:** A curated list of other popular open-source network security tools.

## Installation

1.  **Prerequisites:**
    - Python 3.x
    - **Local AI (Recommended):** For the AI Assistant, you need a running local LLM service. We recommend [Ollama](https://ollama.com/) or [LMStudio](https://lmstudio.ai/). See the in-app AI Guide for setup instructions.
    - **External Tools:** For full functionality, the following command-line tools must be installed and in your system's PATH: `nmap`, `nikto`, `gobuster`, `whatweb`, `sqlmap`, `hashcat`, `masscan`, `wifite`, `aircrack-ng`, and `crunch`.
    - For **Windows users**, you must have [Npcap](https://npcap.com/) installed for Scapy to function correctly.

2.  **Clone the repository (or download the files).**

3.  **Set up a virtual environment (recommended):**
    ```bash
    python -m venv venv
    source venv/bin/activate  # On Windows: venv\Scripts\activate
    ```

4.  **Install dependencies:**
    The required Python libraries are listed in `requirements.txt`. For full functionality, including AI features and HTML reporting, ensure all are installed.
    ```bash
    pip install -r requirements.txt
    ```

## Usage

Because GScapy uses raw sockets for most of its operations, it requires administrator/root privileges to run correctly.

**On Linux/macOS:**
```bash
sudo python zurvan.py
```

**On Windows:**
Right-click on your terminal (Command Prompt or PowerShell) and select "Run as administrator", then run the script:
```bash
python zurvan.py
```
