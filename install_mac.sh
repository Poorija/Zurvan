#!/bin/bash

# Zurvan Installation Script for MacOS

echo "[*] Starting Zurvan Setup for MacOS..."

if ! command -v brew &> /dev/null; then
    echo "[-] Homebrew is not installed. Please install it first: https://brew.sh/"
    exit 1
fi

# 1. Install System Dependencies
echo "[*] Installing system dependencies via Homebrew..."
brew install python3 \
    libpcap \
    libdnet \
    libusb \
    nmap \
    masscan \
    hydra \
    aircrack-ng \
    tor \
    proxychains-ng \
    rust \
    go \
    qt@6

# 2. Install Tools
echo "[*] Installing additional tools..."
brew install rustscan
brew install ffuf
brew install nuclei
brew install sherlock
# dirsearch, enum4linux-ng might need pip or manual install

# 3. Install Python Requirements
echo "[*] Installing Python dependencies..."
pip3 install -r requirements.txt

# 4. Fragrouter
echo "[*] Note regarding Fragrouter: MacOS compilation might require specific adjustments."
if [ -d "tools/fragrouter" ]; then
    cd tools/fragrouter
    ./configure
    make
    cd ../..
fi

# 5. Permissions
echo "[*] Setting execution permissions..."
chmod +x zurvan.py
find tools -type f -name "*.py" -exec chmod +x {} \;
find tools -type f -name "*.sh" -exec chmod +x {} \;
[ -f tools/xray/xray ] && chmod +x tools/xray/xray

echo "[+] Installation complete. Run with: sudo python3 zurvan.py"
