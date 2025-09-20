# GScapy + AI - Comprehensive User Guide

Welcome to the official user guide for GScapy + AI. This document provides a detailed overview of the application's features, tools, and functionalities.

## Table of Contents
1.  [Introduction](#introduction)
2.  [User Accounts & Profiles](#user-accounts--profiles)
3.  [Admin Panel](#admin-panel)
4.  [Main Window Overview](#main-window-overview)
    -   [Resource Bar](#resource-bar)
    -   [Header Bar (Interface & Theme)](#header-bar)
    -   [Live Log](#live-log)
5.  [Packet Sniffer](#packet-sniffer)
6.  [Packet Crafter](#packet-crafter)
7.  [Network Tools](#network-tools)
    -   [Nmap Scan](#nmap-scan)
    -   [Subdomain Scanner](#subdomain-scanner)
    -   [Nikto Scan](#nikto-scan)
    -   [Gobuster](#gobuster)
    -   [WhatWeb](#whatweb)
    -   [Masscan](#masscan)
    -   [Port Scanner (Scapy)](#port-scanner-scapy)
    -   [ARP Scan](#arp-scan)
    -   [Ping Sweep](#ping-sweep)
    -   [Traceroute](#traceroute)
8.  [Advanced Tools](#advanced-tools)
    -   [Packet Flooder](#packet-flooder)
    -   [Firewall Tester](#firewall-tester)
    -   [ARP Spoofer](#arp-spoofer)
    -   [SQLMap](#sqlmap)
    -   [Hashcat](#hashcat)
9.  [Wireless Tools](#wireless-tools)
    -   [Wi-Fi Scanner](#wi-fi-scanner)
    -   [Deauthentication Tool](#deauthentication-tool)
    -   [Beacon Flood](#beacon-flood)
    -   [WPA Handshake Tool](#wpa-handshake-tool)
    -   [KRACK Scanner](#krack-scanner)
    -   [Wifite Auditor](#wifite-auditor)
10. [Threat Intelligence](#threat-intelligence)
11. [Reporting](#reporting)
12. [History](#history)
13. [AI Assistant](#ai-assistant)
14. [System Info](#system-info)
15. [Community Tools](#community-tools)
16. [Exporting Results](#exporting-results)

---

## Introduction

GScapy + AI is a graphical interface for the powerful Scapy packet manipulation program. It extends Scapy's capabilities by integrating a suite of popular open-source security tools, an AI-powered analysis assistant, and a modern, user-friendly interface. This application is designed for network administrators, security professionals, and students to learn, test, and analyze network interactions.

**Disclaimer:** Many tools included in this application can be used for malicious purposes. This software is intended for educational and authorized security testing purposes only. The user is solely responsible for their actions and must have explicit, written permission to test any network or system they do not own.

## Main Window Overview

### Resource Bar
The top-most bar provides a real-time overview of your system's performance.
-   **CPU, RAM, GPU Graphs:** Live-scrolling graphs showing the current utilization of your system's core components.
-   **Disk & Network I/O:** Shows current disk read/write speeds and network sent/receive speeds.
-   **Clock:** Displays the current system date, time, and timezone.
-   **Refresh Interval:** Allows you to change the update frequency of the resource monitors (1s, 2s, 5s) or turn them off to save resources.

### Header Bar
-   **Network Interface:** A crucial dropdown menu where you select the network interface for tools to use. For many tools (especially wireless ones), you must select the correct interface. "Automatic" will let Scapy decide, which is suitable for basic wired connections.
-   **Theme:** Customize the application's look and feel by choosing from a list of themes.

### Live Log
The panel at the bottom of the window shows a live log of the application's actions, including tool commands, errors, and status updates. It is invaluable for debugging and understanding what the application is doing in the background.

---

## Packet Sniffer

The Packet Sniffer is the core of the application, allowing you to capture and inspect live network traffic.

-   **Purpose:** To capture, display, and analyze network packets in real-time.
-   **UI Layout:**
    -   **Controls:** Buttons to Start/Stop sniffing, clear the display, and export results.
    -   **BPF Filter:** A powerful input field where you can specify a [Berkeley Packet Filter](https://biot.com/capstats/bpf.html) to capture only the traffic you're interested in (e.g., `tcp and port 443`, `host 192.168.1.50`).
    -   **Packet List:** The main table displaying captured packets with key information.
    -   **Packet Details:** A tree view showing a detailed, field-by-field breakdown of the selected packet's layers.
    -   **Hex View:** A hexadecimal and ASCII representation of the raw packet data.
-   **Example Use Case:** You want to inspect HTTP traffic from your machine to a specific website.
    1.  Select the correct network interface in the Header Bar.
    2.  In the BPF Filter input, type `tcp and port 80`.
    3.  Click "Start Sniffing".
    4.  Browse to a non-HTTPS website.
    5.  Observe the captured packets in the list. Click on any packet to see its full details.

## Packet Crafter

The Packet Crafter gives you the power to build custom packets from scratch, layer by layer.

-   **Purpose:** To create any type of network packet for testing, analysis, or specialized attacks.
-   **UI Layout:**
    -   **Layer Controls:** Add or remove protocol layers (e.g., Ether, IP, TCP, DNS).
    -   **Layer List:** Shows the stack of protocol layers for the current packet.
    -   **Layer Fields:** Displays the editable fields for the currently selected layer.
    -   **Packet Summary:** A live summary of the packet you are building.
    -   **Sending Controls:** Specify the number of packets to send and the interval between them.
-   **Example Use Case:** You want to craft a DNS query for `example.com`.
    1.  Click "Add" to add an `IP` layer.
    2.  Add a `UDP` layer.
    3.  Add a `DNS` layer.
    4.  Select the `IP` layer and set the `dst` field to a DNS server (e.g., `8.8.8.8`).
    5.  Select the `DNS` layer and set the `qd` (Query Domain) field's `qname` to `example.com`.
    6.  Set the send count to `1` and click "Send Packet(s)". The response will appear in the results panel.

---

## Network Tools

This tab aggregates a collection of powerful, well-known command-line network tools into a graphical interface.

### Nmap Scan
-   **Purpose:** A versatile network scanner for host discovery, port scanning, service and version detection, and vulnerability analysis.
-   **UI Layout:** A comprehensive set of tabs and checkboxes that map directly to Nmap's command-line flags.
    -   **Target/Ports:** Define what to scan.
    -   **Scan Type/Timing:** Control how the scan is performed.
    -   **Detection/Misc:** Options for OS/service detection and verbosity.
    -   **NSE:** Configure the Nmap Scripting Engine for advanced tasks and vulnerability checks.
-   **Example Use Case:** You want to find open web servers on your local network and identify what software they are running.
    1.  Enter your local network range in the "Target(s)" field (e.g., `192.168.1.0/24`).
    2.  Enter `80,443,8080` in the "Ports" field.
    3.  Select the "SYN Stealth Scan (-sS)" scan type.
    4.  Check the "Service/Version (-sV)" box to identify the web server software.
    5.  Click "Start Scan". Results will appear in the output console and a summary window.

### Subdomain Scanner
-   **Purpose:** To discover subdomains for a given domain using the Sublist3r tool.
-   **UI Layout:** A simple interface with a field for the target domain and a start button.
-   **Example Use Case:** You are performing reconnaissance on `example.com`.
    1.  Enter `example.com` into the "Domain" field.
    2.  Click "Start Scan".
    3.  A dialog will appear with a list of found subdomains.

### Nikto Scan
-   **Purpose:** A web server scanner that checks for thousands of potentially dangerous files/CGIs, outdated server versions, and other security issues.
-   **UI Layout:** A multi-tabbed interface to configure all aspects of the Nikto scan.
    -   **Target:** Define the host, port, and whether to use SSL.
    -   **Scan, Evasion, Config, Output:** Fine-tune the scan with tuning, evasion, timing, and output options.
-   **Example Use Case:** You want to run a basic security scan against a web server at `192.168.1.100`.
    1.  In the "Target" tab, enter `192.168.1.100` in the "Target Host" field.
    2.  Click "Start Nikto Scan".

### Gobuster
-   **Purpose:** A tool for brute-forcing URIs (directories and files), DNS subdomains, and virtual host names on web servers. This GUI focuses on the directory/file brute-forcing mode.
-   **UI Layout:** Tabs for configuring the scan, request details (like user-agent), and output options.
-   **Example Use Case:** You want to find hidden directories on `http://example.com`.
    1.  Set the "Target URL" to `http://example.com`.
    2.  Click "Browse..." to select a wordlist file (e.g., `/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt`).
    3.  Click "Start Gobuster Scan".

### WhatWeb
-   **Purpose:** To identify technologies used on websites, including CMS, analytics packages, JavaScript libraries, and web servers.
-   **UI Layout:** A simple interface to specify the target(s) and aggression level.
-   **Example Use Case:** You want to know what technology a website is built with.
    1.  Enter the URL `http://example.com` in the "Target(s)" field.
    2.  Set the aggression level to "1 - Stealthy".
    3.  Click "Start WhatWeb Scan".

### Masscan
-   **Purpose:** An extremely fast Internet-scale port scanner.
-   **UI Layout:** Fields for target ranges, ports, and the transmission rate.
-   **WARNING:** Scanning at high rates is very noisy and can disrupt networks. Use with extreme caution and only on networks you have permission to test.
-   **Example Use Case:** You want to quickly find all hosts with port 80 open on a large network segment.
    1.  Enter the network range (e.g., `10.0.0.0/8`) in the "Target(s)" field.
    2.  Enter `80` in the "Ports" field.
    3.  Set a responsible "Rate" (e.g., `1000`).
    4.  Click "Start Masscan".

### Port Scanner (Scapy)
-   **Purpose:** A port scanner built directly with Scapy, offering fine-grained control over the scan type.
-   **UI Layout:** Options to set the target, ports, and protocol (TCP/UDP). For TCP, you can select the specific flags to use in the probe packet (SYN, FIN, Xmas, etc.).
-   **Example Use Case:** You want to check if a firewall is blocking certain ports by sending a FIN scan, which is often less likely to be logged than a standard SYN scan.
    1.  Enter the target IP and port(s).
    2.  Select the "TCP" protocol.
    3.  Choose "FIN Scan" from the "TCP Scan Mode" dropdown.
    4.  Click "Scan".

### ARP Scan
-   **Purpose:** To discover active hosts on the local network by sending ARP requests.
-   **UI Layout:** A single field for the target network in CIDR notation.
-   **Example Use Case:** You want to quickly map out all devices on your current subnet.
    1.  The tool auto-populates the target network based on your selected interface. You can adjust it if needed.
    2.  Click "Scan". A summary popup will show all discovered hosts and their MAC address vendors.

### Ping Sweep
-   **Purpose:** To discover which hosts in a range are online by sending various types of "ping" probes.
-   **UI Layout:** Allows configuration of the target network, probe type (ICMP, TCP, UDP), ports for TCP/UDP probes, timeout, and number of threads.
-   **Example Use Case:** Standard ICMP pings are blocked on a network. You want to find live hosts by checking if they respond on port 443.
    1.  Enter the target network (e.g., `192.168.1.0/24`).
    2.  Select "TCP SYN" as the probe type.
    3.  Enter `443` in the "Target Port(s)" field.
    4.  Click "Start Sweep".

### Traceroute
-   **Purpose:** To map the network path (hops) from your computer to a target host.
-   **UI Layout:** A field for the target and a tree view to display the results.
-   **Example Use Case:** You are experiencing slow connectivity to `example.com` and want to see where the latency might be.
    1.  Enter `example.com` in the "Target" field.
    2.  Click "Trace". The tool will list each router/hop, its IP address, and the round-trip time.

---

## Advanced Tools

This section contains tools that are more specialized or carry a higher risk of network disruption.

### Packet Flooder
-   **Purpose:** To send a high volume of packets to a target for stress testing or denial-of-service testing.
-   **UI Layout:** Allows you to select a flood template (TCP SYN, UDP, ICMP) or load a custom packet from the Packet Crafter. You can configure the packet count, interval, and number of threads.
-   **WARNING:** This tool can easily overwhelm a network or host. Use with extreme caution.
-   **Example Use Case:** You want to stress-test a server's ability to handle a large number of incoming TCP connections.
    1.  Select the "TCP SYN Flood" template.
    2.  Enter the "Target IP" and "Target Port".
    3.  Check "Randomize Source IP" to make the flood harder to block.
    4.  Set the parameters (e.g., Count: 10000, Interval: 0.01, Threads: 10).
    5.  Click "Start Flood" after acknowledging the warning.

### Firewall Tester
-   **Purpose:** To check firewall rules by sending a variety of specially crafted packets to see which ones are blocked and which ones receive a response.
-   **UI Layout:** Select a target and a pre-defined set of probes.
-   **Example Use Case:** You want to test if a firewall is performing basic stateful inspection.
    1.  Enter the target IP.
    2.  Select the "ACK Scan (Firewall Detection)" probe set.
    3.  Click "Start Test". If you receive RST packets back, it suggests the firewall is stateful and allowed the ACK packets through.

### ARP Spoofer
-   **Purpose:** To perform an ARP spoofing (or ARP cache poisoning) attack, enabling a Man-in-the-Middle (MitM) position.
-   **UI Layout:** Requires a "Victim IP" and a "Target IP" (the host you wish to impersonate, usually the gateway).
-   **WARNING:** This is an active attack tool. Using it on a network without permission is illegal. It will disrupt traffic.
-   **Example Use Case (Educational):** You want to understand how ARP spoofing works on your own isolated test network.
    1.  Enter the IP of a victim machine (e.g., a VM).
    2.  Enter the IP of the gateway.
    3.  Click "Start Spoofing". The tool will send ARP packets to poison the caches of both hosts. All traffic between them will now pass through your machine.
    4.  Click "Stop Spoofing" to send corrective packets and restore the network.

### SQLMap
-   **Purpose:** An automatic SQL injection and database takeover tool.
-   **UI Layout:** An extensive multi-tabbed interface that exposes many of SQLMap's powerful features for targeting, request modification, injection techniques, and data enumeration.
-   **WARNING:** This is a powerful attack tool. You MUST have explicit permission to test the target.
-   **Example Use Case:** You've found a URL like `http://test.com/product.php?id=5` and suspect it's vulnerable to SQL injection.
    1.  In the "Target" tab, enter the full URL in the "Target URL" field.
    2.  Go to the "Enumeration" tab and check "Current User" and "Current DB".
    3.  Go to the "General" tab and check "Batch Mode" to accept default answers.
    4.  Click "Start SQLMap Scan".

### Hashcat
-   **Purpose:** The world's fastest and most advanced password recovery utility.
-   **UI Layout:** A GUI for configuring Hashcat attacks, including setting the hash file, hash mode, attack mode, wordlists, and masks.
-   **Example Use Case:** You have a file (`hashes.txt`) containing NTLM password hashes and want to crack them with a wordlist (`rockyou.txt`).
    1.  In the "Configuration" tab, browse to your `hashes.txt` file.
    2.  Set the "Hash Mode" to `1000` (for NTLM).
    3.  Set the "Attack Mode" to "0 - Straight (Dictionary)".
    4.  Go to the "Wordlists" tab and add your `rockyou.txt` file.
    5.  Click "Start Hashcat".

---

## Wireless Tools

This tab contains tools specifically for 802.11 Wi-Fi network analysis and testing.

**IMPORTANT:** All tools in this section require your wireless card to be in **Monitor Mode**. GScapy cannot do this for you. You must enable it manually using tools like `airmon-ng` on Linux.

### Wi-Fi Scanner
-   **Purpose:** To discover nearby wireless networks and connected clients.
-   **UI Layout:** A simple start/stop interface. Results populate the tree view.
-   **Example Use Case:** You need to get the BSSID (MAC address) and channel of a network for use in other tools.
    1.  Put your Wi-Fi card in monitor mode and select the monitor interface (e.g., `wlan0mon`) at the top of the GScapy window.
    2.  Click "Scan for Wi-Fi Networks".
    3.  The list will populate with nearby APs.

### Deauthentication Tool
-   **Purpose:** To send deauthentication frames to a client, forcing it to disconnect from an Access Point.
-   **UI Layout:** Fields for the target AP's BSSID, the client's MAC, and the number of packets to send.
-   **Example Use Case:** To force a client to re-authenticate so you can capture a WPA handshake.
    1.  Enter the AP's BSSID and the client's MAC (or `ff:ff:ff:ff:ff:ff` for all clients).
    2.  Set the count to `5`.
    3.  Click "Send Deauth Packets".

### Beacon Flood
-   **Purpose:** To create fake Wi-Fi networks by flooding the air with beacon frames.
-   **UI Layout:** Options to configure the SSID(s), BSSID, encryption type, and channel of the fake networks.
-   **Example Use Case:** For testing how client devices react to a large number of networks or for social engineering assessments.
    1.  Enter an SSID like "Free Public WiFi".
    2.  Set the "Count" to `0` for an infinite flood.
    3.  Click "Start Beacon Flood".

### WPA Handshake Tool
-   **Purpose:** A two-part tool to first capture a WPA/WPA2 4-way handshake and then crack the password using a dictionary attack.
-   **UI Layout:**
    -   **Capture Section:** Select a target network and start sniffing. A deauth button is provided to speed up the process.
    -   **Cracker Section:** Load the captured handshake file (`.pcap`), provide a wordlist, and start `aircrack-ng`.
-   **Example Use Case:**
    1.  In the Wi-Fi Scanner, find your target network.
    2.  In the WPA Handshake Tool, refresh the target list and select your network.
    3.  Click "Start Handshake Capture".
    4.  Click "Deauth Client to Speed Up" to force a reconnect.
    5.  Once a handshake is captured and saved, the file path will appear in the cracker section.
    6.  Browse for a wordlist file.
    7.  Click "Start Cracking".

### KRACK Scanner
-   **Purpose:** To passively detect networks vulnerable to Key Reinstallation Attacks (KRACK) by listening for retransmitted handshake messages.
-   **UI Layout:** A simple start/stop interface.
-   **Example Use Case:**
    1.  Start the scanner.
    2.  Force a client on a nearby network to reconnect (e.g., using the Deauth Tool).
    3.  If the network is vulnerable, it will appear in the results list.

### Wifite Auditor
-   **Purpose:** An automated wireless auditing tool that can attack WPA/WPS encrypted networks.
-   **UI Layout:** A simple GUI wrapper around the `wifite` command.
-   **Example Use Case:** You want to run a general audit on a specific network named "MyHomeWiFi".
    1.  Enter "MyHomeWiFi" in the "Target ESSID" field.
    2.  Check the "--kill" option to handle conflicting processes.
    3.  Click "Start Wifite Scan". Wifite will run through its attack stages automatically.

---

## AI Assistant

The AI Assistant integrates with large language models (LLMs) to provide analysis and guidance.

-   **Purpose:** To help interpret tool output, explain concepts, generate commands, and analyze security findings.
-   **UI Layout:** A chat interface with a settings button to configure your AI provider (e.g., a local Ollama instance or an online API).
-   **Example Use Case:** After running an Nmap scan, you see an open port you don't recognize.
    1.  Go to the Nmap tool and click the "Send to AI Analyst" button.
    2.  The Nmap XML output is sent to the AI Assistant tab.
    3.  In the chat input, ask "What is port 5432 (postgresql) and what are the common security risks associated with it?"
    4.  The AI will provide a detailed explanation.

---

## System Info, Community Tools, and Exporting

-   **System Info:** Displays detailed information about your operating system, hardware (CPU, memory, GPU), network interfaces, and key library versions.
-   **Community Tools:** Provides a curated list of other popular open-source tools in the Scapy and network security ecosystem, with links to their websites.
-   **Exporting Results:** Most tools that produce results in a table have an "Export Results" button. This allows you to save the data in various formats for reporting and analysis:
    -   **CSV:** Comma-Separated Values, for use in spreadsheets.
    -   **HTML:** A web page for easy viewing.
    -   **PDF:** A portable document format for reports.
    -   **DOCX:** A Microsoft Word document.

---

## User Accounts & Profiles
GScapy now supports a full user account system to provide a personalized and secure experience.

-   **Login:** On startup, you will be prompted to log in or create a new account.
-   **User Profile:** Access your profile by clicking the user icon in the top-right corner of the Resource Bar and selecting "Profile...".
-   **Customization:** In your profile, you can:
    -   Change your email address.
    -   Update your password (you must enter it twice for confirmation).
    -   Upload a custom avatar image.

## Admin Panel
Users marked as administrators have access to a special Admin Panel.

-   **Access:** The Admin Panel is available from the "Admin" menu in the main menu bar.
-   **User Management:** Administrators can:
    -   View all registered users.
    -   Activate or deactivate user accounts.
    -   Change any user's email address.
    -   Change any user's username.
    -   Set a new password for any user.
    -   Promote or demote other users to/from administrator status.

## Threat Intelligence
This tab provides tools to stay up-to-date with the latest security threats.

-   **Recent Threats:** This sub-tab automatically fetches and displays the latest 30 CVEs from the `cve.circl.lu` API. It includes pagination controls to navigate through the list. Click on any CVE to see a detailed summary and links to references.
-   **Exploit-DB Search:** This sub-tab allows you to search for exploits using the `getsploit` command-line tool, which queries the Vulners database. An API key from `vulners.com` is required.

## Reporting
The Reporting tab has been significantly enhanced to streamline the report creation process.

-   **Rules of Engagement (ROE):** The ROE section is now pre-populated with a detailed template based on industry best practices. Simply fill in the client name, dates, and customize the scope and objectives.
-   **Offline CVE Database:** The "Aggregated Findings" section now includes an option to "Use offline CVE_DB".
    -   **Update Offline DB:** Click this button to download all CVE data from the NVD for the years 2002 to the present, plus the latest modifications. This data is stored in a local `cve.db` SQLite file. This process may take a long time on the first run.
    -   When the "Use offline CVE_DB" checkbox is ticked, the "Aggregate & Enrich Results" button will use this local database instead of live APIs, allowing for offline work.
-   **AI-Powered Generation:**
    -   **AI Persona:** Select a persona (e.g., "Technical Manager", "C-Suite Executive") to guide the AI's tone and focus when generating content.
    -   **AI Instructions:** Provide specific, custom instructions to the AI (e.g., "Focus on the financial impact of the SQL injection vulnerability").
    -   **Generate with AI:** This button will use the AI to generate report sections based on the aggregated findings, the selected persona, and your custom instructions.
-   **Final Export:**
    -   **Generate Final HTML Report:** Creates a report based on the selected HTML template.
    -   **Generate Report as Doc:** This button will provide options to export the final report in various document formats, such as DOCX, PDF, and CSV.

## History
*(This feature is under development)*

The History tab will provide a complete audit trail of actions performed within the application.
-   **User View:** Each user will be able to see a history of their own activities.
-   **Admin View:** Administrators will be able to view a comprehensive history of all actions performed by all users, with options to filter by user.
-   **Data Integrity:** Users will not be able to clear their own history, but administrators will have the ability to manage the history logs.
