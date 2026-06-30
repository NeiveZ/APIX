# APIX 

> API Security Tester — modular API security testing with endpoint discovery, auth bypass, IDOR and rate limit checks.

![Python](https://img.shields.io/badge/Python-3.10%2B-3776AB?style=flat-square&logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/Platform-Linux%20%7C%20Kali-557C94?style=flat-square)
![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Status](https://img.shields.io/badge/Status-Active-brightgreen?style=flat-square)

---

## Overview

APIX covers the OWASP API Security Top 10 in a modular, interactive framework. From discovering hidden endpoints to testing JWT vulnerabilities, IDOR and rate limiting — all in one tool.

---

## Modules

| Module | Description |
|---|---|
| `api/fuzz` | Endpoint discovery — tests 100+ common API paths across multiple HTTP methods |
| `api/auth` | Auth testing — missing auth, JWT alg:none bypass, weak tokens, header bypass |
| `api/idor` | IDOR testing — iterates object IDs looking for unauthorized data access |
| `api/ratelimit` | Rate limit testing — burst requests to detect missing or insufficient limits |

---

## Features

- **Endpoint fuzzer** — 100+ built-in API paths, custom wordlist support, multi-method testing
- **JWT analysis** — decodes header/payload, checks alg:none, tests bypass, warns on weak algorithms
- **Auth header bypass** — tests X-Forwarded-For, X-Real-IP, X-Original-URL and others
- **IDOR detection** — iterates ID ranges and flags accessible resources that shouldn't be
- **Rate limit detection** — measures burst response distribution (200 vs 429 vs 503)
- **Bearer/Basic auth** — pass tokens via AUTH option for authenticated testing
- **Custom headers** — inject any headers for session cookies, API keys, etc.

---

## Requirements

```bash
# No external dependencies
python3 --version  # 3.10+
```

---

## Installation

```bash
git clone https://github.com/NeiveZ/APIX.git
cd APIX
chmod +x apix.sh
./apix.sh
```

---

## Usage

```
apix > use <module>
apix > set TARGET <url>
apix > run
```

---

## Examples

**Discover API endpoints:**
```
apix > use api/fuzz
apix (api/fuzz) > set TARGET https://api.example.com
apix (api/fuzz) > set METHODS GET,POST,PUT,DELETE
apix (api/fuzz) > run
```

**Fuzz with auth token:**
```
apix (api/fuzz) > set AUTH eyJhbGciOiJIUzI1NiJ9...
apix (api/fuzz) > run
```

**Test authentication security:**
```
apix > use api/auth
apix (api/auth) > set TARGET https://api.example.com/users/me
apix (api/auth) > set TOKEN eyJhbGciOiJIUzI1NiJ9...
apix (api/auth) > run
```

**Test for IDOR:**
```
apix > use api/idor
apix (api/idor) > set TARGET https://api.example.com/users/{id}
apix (api/idor) > set AUTH eyJhbGciOiJIUzI1NiJ9...
apix (api/idor) > set OWN_ID 42
apix (api/idor) > set START 1
apix (api/idor) > set END 100
apix (api/idor) > run
```

**Rate limit test:**
```
apix > use api/ratelimit
apix (api/ratelimit) > set TARGET https://api.example.com/auth/login
apix (api/ratelimit) > set REQUESTS 100
apix (api/ratelimit) > set THREADS 20
apix (api/ratelimit) > run
```

---

## OWASP API Security Top 10 Coverage

| OWASP ID | Name | Module |
|---|---|---|
| API1 | Broken Object Level Authorization | `api/idor` |
| API2 | Broken Authentication | `api/auth` |
| API4 | Unrestricted Resource Consumption | `api/ratelimit` |
| API9 | Improper Inventory Management | `api/fuzz` |

---

## Repository Structure

```
APIX/
├── apix.py               # Interactive shell
├── apix.sh               # Launcher
├── modules/
│   ├── endpoint_fuzz.py  # API endpoint discovery
│   ├── auth_test.py      # Auth and JWT testing
│   ├── idor_test.py      # IDOR and rate limit testing
│   └── report_gen.py     # Report generator
└── utils/
    ├── colors.py
    └── session.py
```

---

## Legal

For use only on systems you own or have explicit written authorization to test.
