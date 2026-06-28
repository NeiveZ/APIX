#!/usr/bin/env python3
# modules/endpoint_fuzz.py — API endpoint discovery for APIX

import urllib.request
import urllib.error
import urllib.parse
import ssl
import concurrent.futures
import random
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section

USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0",
    "curl/7.88.1",
    "python-requests/2.31.0",
    "APIX/1.0 (Security Assessment)",
]

DEFAULT_ENDPOINTS = [
    # Auth
    "api/auth", "api/login", "api/logout", "api/register", "api/token",
    "api/refresh", "api/password", "api/reset",
    # Users
    "api/users", "api/user", "api/me", "api/profile", "api/account",
    "api/admin", "api/accounts",
    # Resources
    "api/data", "api/items", "api/products", "api/orders", "api/files",
    "api/upload", "api/download", "api/search", "api/config",
    # Versioned
    "api/v1", "api/v2", "api/v3", "v1", "v2", "v3",
    "api/v1/users", "api/v1/auth", "api/v1/token", "api/v2/users",
    # Common patterns
    "api", "rest", "graphql", "swagger", "swagger.json", "swagger.yaml",
    "openapi.json", "openapi.yaml", "docs", "api-docs", "redoc",
    "health", "ping", "status", "metrics", "info", "version",
    # Admin
    "admin", "admin/api", "management", "internal", "private",
    # Debug
    "debug", "test", "dev", "staging",
]

HTTP_METHODS = ["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS", "HEAD"]


class EndpointFuzzer(BaseModule):

    NAME        = "api/fuzz"
    DESCRIPTION = "API endpoint discovery — finds hidden endpoints, methods, and parameters"
    REFERENCES  = [
        "https://owasp.org/www-project-api-security/",
        "https://github.com/danielmiessler/SecLists/tree/master/Discovery/Web-Content/api",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",      True,  "Base URL (e.g. https://api.target.com)")
        self._add_option("WORDLIST", "",      False, "Custom endpoint wordlist (default: built-in)")
        self._add_option("METHODS",  "GET",   False, "HTTP methods to test: GET | ALL | GET,POST,PUT")
        self._add_option("CODES",    "200,201,204,301,302,400,401,403,405,500", False, "Status codes to report")
        self._add_option("THREADS",  "20",    False, "Parallel requests")
        self._add_option("TIMEOUT",  "8",     False, "Request timeout in seconds")
        self._add_option("HEADERS",  "",      False, "Extra headers: Key:Val,Key2:Val2")
        self._add_option("AUTH",     "",      False, "Bearer token or Basic base64 for Authorization header")
        self._add_option("DELAY",    "0",     False, "Delay between requests in ms")

    def run(self) -> list:
        if not self._validate():
            return []

        target   = self.get_option("TARGET").rstrip("/")
        timeout  = int(self.get_option("TIMEOUT") or 8)
        threads  = int(self.get_option("THREADS") or 20)
        delay    = int(self.get_option("DELAY") or 0)
        auth     = self.get_option("AUTH") or ""
        codes    = set(int(c) for c in (self.get_option("CODES") or "200").split(","))
        methods  = self._parse_methods(self.get_option("METHODS") or "GET")
        endpoints = self._load_endpoints()
        headers  = self._parse_headers(self.get_option("HEADERS") or "")

        if auth:
            if auth.startswith("Bearer ") or " " not in auth:
                headers["Authorization"] = f"Bearer {auth.lstrip('Bearer ')}"
            else:
                headers["Authorization"] = f"Basic {auth}"

        print_section(f"API Endpoint Fuzzer — {target}")
        print_status(f"Endpoints : {Colors.WHITE}{len(endpoints)}{Colors.RESET}", "info")
        print_status(f"Methods   : {Colors.WHITE}{', '.join(methods)}{Colors.RESET}", "info")
        print_status(f"Threads   : {Colors.WHITE}{threads}{Colors.RESET}", "info")
        print()

        findings = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        combos = [(ep, m) for ep in endpoints for m in methods]
        total  = len(combos)
        count  = 0
        lock   = __import__("threading").Lock()

        def probe(combo):
            nonlocal count
            endpoint, method = combo
            url = f"{target}/{endpoint}"
            ua  = random.choice(USER_AGENTS)

            if delay > 0:
                __import__("time").sleep(delay / 1000)

            try:
                req = urllib.request.Request(url, method=method,
                                             headers={"User-Agent": ua, **headers})
                handler = urllib.request.HTTPSHandler(context=ctx)
                opener  = urllib.request.build_opener(handler, NoRedirectHandler())
                with opener.open(req, timeout=timeout) as resp:
                    code    = resp.status
                    ctype   = resp.headers.get("Content-Type", "")
                    length  = resp.headers.get("Content-Length", "?")
            except urllib.error.HTTPError as e:
                code   = e.code
                ctype  = e.headers.get("Content-Type", "") if e.headers else ""
                length = "?"
            except Exception:
                with lock:
                    count += 1
                return None

            with lock:
                count += 1
                print(f"  {Colors.DARK_GRAY}[{count:>5}/{total}]{Colors.RESET} "
                      f"{Colors.CYAN}{method:<7}{Colors.RESET} "
                      f"{Colors.WHITE}{endpoint:<40}{Colors.RESET} "
                      f"{_code_color(code)}{code}{Colors.RESET}",
                      end="\r")

            if code in codes:
                is_api = "json" in ctype.lower() or "xml" in ctype.lower()
                sev    = _severity_from_code(code, is_api)
                with lock:
                    print(" " * 80 + "\r", end="")
                    print(f"  {Colors.BOLD}{_code_color(code)}[{code}]{Colors.RESET} "
                          f"{Colors.CYAN}{method:<7}{Colors.RESET} "
                          f"{Colors.WHITE}{url}{Colors.RESET} "
                          f"{Colors.DARK_GRAY}({ctype[:30]}){Colors.RESET}")
                return {"severity": sev, "check": "Endpoint Found", "endpoint": f"{method} {url}",
                        "detail": f"HTTP {code} | Content-Type: {ctype} | Length: {length}"}
            return None

        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            for result in ex.map(probe, combos):
                if result:
                    findings.append(result)

        print(" " * 80)
        print()
        print_status(f"Found {Colors.GREEN}{len(findings)}{Colors.RESET} endpoint(s) out of {total} tested.", "ok")
        return findings

    def _parse_methods(self, spec: str) -> list:
        if spec.upper() == "ALL":
            return HTTP_METHODS
        return [m.strip().upper() for m in spec.split(",")]

    def _parse_headers(self, spec: str) -> dict:
        headers = {}
        if not spec:
            return headers
        for pair in spec.split(","):
            if ":" in pair:
                k, v = pair.split(":", 1)
                headers[k.strip()] = v.strip()
        return headers

    def _load_endpoints(self) -> list:
        wl = self.get_option("WORDLIST")
        if wl and __import__("os").path.isfile(wl):
            try:
                with open(wl) as f:
                    return [l.strip() for l in f if l.strip() and not l.startswith("#")]
            except Exception:
                pass
        return DEFAULT_ENDPOINTS


def _code_color(code: int) -> str:
    if code < 300:   return Colors.GREEN
    if code < 400:   return Colors.BLUE if hasattr(Colors, "BLUE") else Colors.CYAN
    if code == 401:  return Colors.YELLOW
    if code == 403:  return Colors.YELLOW
    if code >= 500:  return Colors.RED
    return Colors.DARK_GRAY


def _severity_from_code(code: int, is_api: bool) -> str:
    if code in (200, 201, 204) and is_api: return "HIGH"
    if code in (200, 201, 204):            return "MEDIUM"
    if code in (401, 403):                 return "LOW"
    if code >= 500:                        return "MEDIUM"
    return "INFO"


class NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **kw): return None
