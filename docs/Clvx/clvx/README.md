# CLVX

> Cloud & Firewall Evasion Framework — WAF/CDN fingerprinting, Cloudflare & Azure cloud recon, and evasive port scanning.

![Python](https://img.shields.io/badge/Python-3.8%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20macOS%20%7C%20Windows-557C94?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

CLVX covers the recon-and-evasion side of a penetration test: identify the WAF/CDN sitting in front of a target, find the real origin IP hiding behind Cloudflare, enumerate exposed Azure storage and tenant data, and scan firewalled hosts using timing-based evasion techniques. Built as a single interactive Python console, standard library only, no Metasploit dependency.

---

## Modules

| Module | Description |
|---|---|
| `evade/detect` | Fingerprints 20+ WAF/CDN providers (Cloudflare, AWS WAF, Akamai, Sucuri, Imperva, F5, Azure Front Door, Fastly, ModSecurity...) and probes WAF behavior with test payloads and known scanner User-Agents |
| `cloud/cloudflare` | Discovers the real origin IP behind Cloudflare via DNS history, Certificate Transparency logs (crt.sh), DNS record leaks (MX/TXT/NS), common bypass subdomains, and optional Shodan lookup |
| `cloud/azure` | Enumerates public Azure Blob Storage containers, discovers tenant ID via public Microsoft endpoints, maps Azure-specific subdomains, and flags subdomain takeover candidates |
| `firewall/portscan` | Evasive TCP connect scanner with Nmap-style timing profiles (paranoid → aggressive), source port manipulation, scan-order randomization, banner grabbing, and an ACK probe to fingerprint stateful vs. stateless firewalls |

---

## Features

- **Console-based workflow** — `use` / `set` / `show options` / `run`, inspired by Metasploit-style module design, with zero Metasploit dependency
- **Standard library only** — no external Python packages required to run the core toolkit
- **Findings aggregation** — every module reports structured findings (`severity`, `check`, `target`, `detail`) collected into a single session
- **JSON report export** — `save report <file>` dumps all session findings for evidence/portfolio use
- **Timing-based evasion** — jitter, randomized port order, configurable delay profiles (paranoid/sneaky/polite/normal/aggressive)
- **Built around certification-relevant techniques** — WAF fingerprinting, CDN bypass, cloud misconfiguration recon, and firewall behavior probing (OSCP/DCPT-style content)

---

## Requirements

| Tool | Purpose | Install |
|---|---|---|
| Python 3.8+ | Runtime — stdlib only (`urllib`, `socket`, `ssl`) | pre-installed on most distros |
| `dig` *(optional)* | DNS leak checks in `cloud/cloudflare` | `apt install dnsutils` / `brew install bind` |
| root / `CAP_NET_RAW` *(optional)* | Raw-socket ACK probe in `firewall/portscan` | not required for the rest of the toolkit |

```bash
# Optional extras (Debian/Kali)
sudo apt install dnsutils
```

No external pip packages are required — everything runs on the Python standard library.

---

## Installation

```bash
git clone https://github.com/<you>/CLVX.git
cd CLVX
python3 clvx.py
```

---

## Usage

```
clvx > show modules
clvx > use <module>
clvx > set <OPTION> <value>
clvx > run
```

### Core commands

```
use <module>            Load a module
set <OPTION> <value>    Set an option
show options            Show current module options
show modules            List available modules
run                     Execute the loaded module
show findings           Show findings collected this session
save report <file>      Export session findings to JSON
back                    Unload the current module
help                    Show command help
exit / quit             Exit the console
```

---

## Examples

**Fingerprint a WAF/CDN:**
```
clvx > use evade/detect
clvx (evade/detect) > set TARGET https://target.com
clvx (evade/detect) > run
```

**Find the real IP behind Cloudflare:**
```
clvx > use cloud/cloudflare
clvx (cloud/cloudflare) > set TARGET target.com
clvx (cloud/cloudflare) > set SHODAN_KEY <optional-api-key>
clvx (cloud/cloudflare) > run
```

**Enumerate exposed Azure storage:**
```
clvx > use cloud/azure
clvx (cloud/azure) > set TARGET contoso.com
clvx (cloud/azure) > run
```

**Evasive port scan with slow timing:**
```
clvx > use firewall/portscan
clvx (firewall/portscan) > set TARGET target.com
clvx (firewall/portscan) > set TIMING sneaky
clvx (firewall/portscan) > set RANDOMIZE true
clvx (firewall/portscan) > run
```

---

## Output

```
clvx (evade/detect) > run

[*] Sending baseline request...
[*] HTTP 403  Server: cloudflare
[*] Fingerprinting from response headers and body...
  [CDN/WAF] Cloudflare detected
[*] Probing WAF behaviour with attack payloads...
  [BLOCK]  SQLi probe → HTTP 403 (WAF active)
  [PASS]   Path traversal → HTTP 403 (not blocked)
[+] Detection complete. Found: Cloudflare
```

---

## Repository Structure

```
CLVX/
├── clvx.py                   # Interactive console
├── modules/
│   ├── base.py                # BaseModule class (options, validation, findings)
│   ├── evade_detect.py
│   ├── cloud_cloudflare.py
│   ├── cloud_azure.py
│   └── firewall_portscan.py
├── utils/
│   ├── colors.py
│   └── http_client.py
└── reports/                   # Exported JSON findings (created on demand)
```

---

## Roadmap

- [ ] `evade/bypass` — dedicated WAF bypass test suite (encoding, case variation, HTTP verb tampering, chunked transfer)
- [ ] `firewall/acl` — multi-protocol ACL testing
- [ ] `cloud/aws` — port the existing S3 bucket enumeration module to the `BaseModule` pattern
- [ ] Real TCP checksum calculation for the ACK probe (RFC 793)

---

## Legal

For use only on systems and networks you own or have explicit written authorization to test. Unauthorized use against third-party infrastructure is illegal in most jurisdictions. Built for educational purposes and certification preparation.
