#!/bin/bash

# Zurvan Installation Script for Linux (Debian/Ubuntu/Kali)

echo "[*] Starting Zurvan Setup..."

# 1. Update and Upgrade System
echo "[*] Updating package lists..."
sudo apt-get update

# 2. Install System Dependencies
echo "[*] Installing system dependencies..."
sudo apt-get install -y \
    python3-pip \
    python3-dev \
    git \
    build-essential \
    libpcap-dev \
    libdnet-dev \
    libdumbnet-dev \
    libnetfilter-queue-dev \
    libusb-1.0-0-dev \
    libssl-dev \
    libffi-dev \
    libxml2-dev \
    libxslt1-dev \
    zlib1g-dev \
    libjpeg-dev \
    libgtk2.0-dev \
    pkg-config \
    libcairo2-dev \
    libgirepository1.0-dev \
    libxcb-xinerama0 \
    libxcb-icccm4 \
    libxcb-image0 \
    libxcb-keysyms1 \
    libxcb-render-util0 \
    libxcb-xkb1 \
    libxkbcommon-x11-0 \
    libxcb-cursor0 \
    xvfb \
    proxychains4 \
    tor \
    wget \
    curl \
    unzip \
    nmap \
    masscan \
    hydra \
    aircrack-ng \
    dnsrecon \
    sherlock \
    libevent-dev \
    golang

# 3. Install Python Requirements
echo "[*] Installing Core Python dependencies..."
# Use --break-system-packages if on newer Debian/Kali/Ubuntu versions that enforce PEP 668
sudo python3 -m pip install -r requirements.txt --break-system-packages || sudo python3 -m pip install -r requirements.txt

# 4. Clone & Setup External Tools in tools/
echo "[*] Setting up external tools in 'tools/' directory..."
mkdir -p tools

# Helper function to clone and install requirements
setup_tool() {
    REPO_URL=$1
    DIR_NAME=$2
    echo "[*] Setting up $DIR_NAME..."
    if [ ! -d "tools/$DIR_NAME" ]; then
        git clone "$REPO_URL" "tools/$DIR_NAME"
    else
        echo "[-] tools/$DIR_NAME already exists. Skipping clone."
    fi

    if [ -f "tools/$DIR_NAME/requirements.txt" ]; then
        echo "    Installing requirements for $DIR_NAME..."
        sudo python3 -m pip install -r "tools/$DIR_NAME/requirements.txt" --break-system-packages || sudo python3 -m pip install -r "tools/$DIR_NAME/requirements.txt"
    fi
}

setup_tool "https://github.com/maurosoria/dirsearch.git" "dirsearch"
setup_tool "https://github.com/sqlmapproject/sqlmap.git" "sqlmap"
setup_tool "https://github.com/derv82/wifite2.git" "wifite2"
setup_tool "https://github.com/sullo/nikto.git" "nikto"
setup_tool "https://github.com/urbanadventurer/WhatWeb.git" "WhatWeb"
setup_tool "https://github.com/m4ll0k/Infoga.git" "Infoga"
setup_tool "https://github.com/Muhammad-Badawy/social-analyzer.git" "social-analyzer"
setup_tool "https://github.com/opsdisk/metagoofil.git" "metagoofil"
setup_tool "https://github.com/s0md3v/Photon.git" "Photon"
setup_tool "https://github.com/lanmaster53/recon-ng.git" "recon-ng"
setup_tool "https://github.com/OJ/gobuster.git" "gobuster"
setup_tool "https://github.com/rapid7/metasploit-framework.git" "metasploit-framework"
setup_tool "https://github.com/hashcat/hashcat.git" "hashcat"
setup_tool "https://github.com/openwall/john.git" "john"
setup_tool "https://github.com/trufflesecurity/trufflehog.git" "trufflehog"
setup_tool "https://github.com/carlospolop/PEASS-ng.git" "PEASS-ng"
setup_tool "https://github.com/Lazza/Magma-Osint.git" "Magma-Osint"
setup_tool "https://github.com/megadose/holehe.git" "holehe"
setup_tool "https://github.com/soxoj/maigret.git" "maigret"
setup_tool "https://github.com/projectdiscovery/httpx.git" "httpx"
setup_tool "https://github.com/projectdiscovery/subfinder.git" "subfinder"
setup_tool "https://github.com/projectdiscovery/nuclei.git" "nuclei"
setup_tool "https://github.com/aboul3la/Sublist3r.git" "sublist3r"
setup_tool "https://github.com/smicallef/spiderfoot.git" "spiderfoot"
setup_tool "https://github.com/royhills/arp-scan.git" "arp-scan"

# PhoneInfoga (Go build)
echo "[*] Setting up PhoneInfoga..."
if [ ! -d "tools/PhoneInfoga" ]; then
    git clone "https://github.com/sundowndev/phoneinfoga.git" "tools/PhoneInfoga"
    cd tools/PhoneInfoga
    echo "    Building PhoneInfoga..."
    go build
    cd ../..
else
    echo "[-] tools/PhoneInfoga already exists."
    if [ ! -f "tools/PhoneInfoga/phoneinfoga" ]; then
        echo "    Building PhoneInfoga binary..."
        cd tools/PhoneInfoga
        go build
        cd ../..
    fi
fi

# 5. Compile Fragrouter
echo "[*] Setting up Fragrouter..."
if [ -d "tools/fragrouter" ]; then
    cd tools/fragrouter
    # fragrouter is old and might need some autoconf love
    # It often requires libdnet and libpcap

    # We try to configure and make. If it fails, we warn.
    if [ ! -f "Makefile" ]; then
        ./configure
    fi
    make

    if [ -f "fragrouter" ]; then
        echo "[+] Fragrouter compiled successfully."
    else
        echo "[-] Fragrouter compilation failed. You might need to check 'tools/fragrouter' manually."
    fi
    cd ../..
else
    echo "[-] tools/fragrouter directory not found."
fi

# 6. Install Missing System Tools (Best Effort)
echo "[*] Attempting to install other requested tools via Package Managers..."

# rustscan
if ! command -v rustscan &> /dev/null; then
    echo "[*] Installing RustScan (via cargo)..."
    if ! command -v cargo &> /dev/null; then sudo apt-get install -y cargo; fi
    cargo install rustscan || echo "[-] Failed to install rustscan via cargo."
fi

# ffuf
if ! command -v ffuf &> /dev/null; then
    echo "[*] Installing ffuf (via go)..."
    go install github.com/ffuf/ffuf@latest || echo "[-] Failed to install ffuf via go."
fi

# nuclei
if ! command -v nuclei &> /dev/null; then
    echo "[*] Installing nuclei (via go)..."
    go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest || echo "[-] Failed to install nuclei via go."
fi

# ghunt
if ! command -v ghunt &> /dev/null; then
    echo "[*] Installing GHunt..."
    sudo python3 -m pip install ghunt --break-system-packages || sudo python3 -m pip install ghunt
fi

# enum4linux-ng
if ! command -v enum4linux-ng &> /dev/null; then
    echo "[*] Installing enum4linux-ng..."
    sudo python3 -m pip install enum4linux-ng --break-system-packages || sudo python3 -m pip install enum4linux-ng
fi

# 7. Set Permissions
echo "[*] Setting execution permissions..."
chmod +x zurvan.py
find tools -type f -name "*.py" -exec chmod +x {} \;
find tools -type f -name "*.sh" -exec chmod +x {} \;
# Set +x on binaries if they exist
[ -f tools/xray/xray ] && chmod +x tools/xray/xray
[ -f tools/holehe/holehe ] && chmod +x tools/holehe/holehe

echo "[+] Installation complete. You can run the app with: sudo python3 zurvan.py"
