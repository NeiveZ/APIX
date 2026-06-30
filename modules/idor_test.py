#!/usr/bin/env python3
# modules/idor_test.py — IDOR and rate limit tester for APIX

import urllib.request
import urllib.error
import ssl
import time
import threading
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


class IDORTester(BaseModule):

    NAME        = "api/idor"
    DESCRIPTION = "IDOR testing — iterates object IDs looking for unauthorized access to other users data"
    REFERENCES  = [
        "https://owasp.org/www-project-api-security/",
        "https://portswigger.net/web-security/access-control/idor",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",     True,  "Endpoint with ID placeholder: https://api.com/users/{id}")
        self._add_option("AUTH",     "",     False, "Your valid Bearer token")
        self._add_option("START",    "1",    False, "ID range start")
        self._add_option("END",      "20",   False, "ID range end")
        self._add_option("METHOD",   "GET",  False, "HTTP method")
        self._add_option("OWN_ID",   "",     False, "Your own user ID (to skip)")
        self._add_option("TIMEOUT",  "8",    False, "Request timeout")

    def run(self) -> list:
        if not self._validate():
            return []

        template = self.get_option("TARGET").strip()
        auth     = self.get_option("AUTH") or ""
        start    = int(self.get_option("START") or 1)
        end      = int(self.get_option("END") or 20)
        method   = self.get_option("METHOD").upper()
        own_id   = self.get_option("OWN_ID") or ""
        timeout  = int(self.get_option("TIMEOUT") or 8)

        if "{id}" not in template:
            print_status("TARGET must contain {id} placeholder. Example: https://api.com/users/{id}", "error")
            return []

        print_section(f"IDOR Test — {template}")
        print_status(f"Range  : {Colors.WHITE}{start} → {end}{Colors.RESET}", "info")
        print_status(f"Own ID : {Colors.WHITE}{own_id or 'not set'}{Colors.RESET}", "info")
        print()

        findings = []
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        headers = {"User-Agent": "APIX/1.0"}
        if auth:
            # See endpoint_fuzz.py for why .lstrip("Bearer ") is wrong here.
            headers["Authorization"] = auth if auth.startswith("Bearer ") else f"Bearer {auth}"

        for id_ in range(start, end + 1):
            url = template.replace("{id}", str(id_))
            if str(id_) == own_id:
                print(f"  {Colors.DARK_GRAY}[SKIP]{Colors.RESET}  ID {id_} (own ID)")
                continue

            try:
                req     = urllib.request.Request(url, method=method, headers=headers)
                handler = urllib.request.HTTPSHandler(context=ctx)
                opener  = urllib.request.build_opener(handler)
                with opener.open(req, timeout=timeout) as resp:
                    code = resp.status
                    body = resp.read(512).decode("utf-8", errors="replace")
            except urllib.error.HTTPError as e:
                code = e.code
                body = ""
            except Exception:
                continue

            color = Colors.RED if code in (200, 201) else Colors.DARK_GRAY
            label = "ACCESSIBLE" if code in (200, 201) else str(code)

            print(f"  {color}[{label}]{Colors.RESET}  ID {id_:>5}  {url}")

            if code in (200, 201):
                findings.append(self._finding(
                    "HIGH", "IDOR — Unauthorized Object Access",
                    url, f"HTTP {code} for ID {id_} — possible unauthorized data access"
                ))

        print()
        if findings:
            print_status(f"{Colors.RED}{len(findings)}{Colors.RESET} potential IDOR finding(s).", "ok")
        else:
            print_status("No IDOR vulnerabilities detected.", "info")
        return findings


# ─────────────────────────────────────────────────────────────────
#  Rate Limit Tester
# ─────────────────────────────────────────────────────────────────

class RateLimitTester(BaseModule):

    NAME        = "api/ratelimit"
    DESCRIPTION = "Rate limiting test — sends burst requests to check if API enforces limits"
    REFERENCES  = [
        "https://owasp.org/www-project-api-security/",
    ]

    def _define_options(self):
        self._add_option("TARGET",   "",     True,  "Endpoint URL to test")
        self._add_option("REQUESTS", "50",   False, "Number of requests to send")
        self._add_option("THREADS",  "10",   False, "Parallel threads")
        self._add_option("METHOD",   "GET",  False, "HTTP method")
        self._add_option("BODY",     "",     False, "Request body (POST/PUT)")
        self._add_option("AUTH",     "",     False, "Bearer token")
        self._add_option("TIMEOUT",  "5",    False, "Request timeout")

    def run(self) -> list:
        if not self._validate():
            return []

        url      = self.get_option("TARGET").strip()
        total    = int(self.get_option("REQUESTS") or 50)
        threads  = int(self.get_option("THREADS") or 10)
        method   = self.get_option("METHOD").upper()
        body     = self.get_option("BODY") or None
        auth     = self.get_option("AUTH") or ""
        timeout  = int(self.get_option("TIMEOUT") or 5)

        print_section(f"Rate Limit Test — {url}")
        print_status(f"Requests : {Colors.WHITE}{total}{Colors.RESET}", "info")
        print_status(f"Threads  : {Colors.WHITE}{threads}{Colors.RESET}", "info")
        print()

        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode    = ssl.CERT_NONE

        headers = {"User-Agent": "APIX/1.0"}
        if auth:
            # See endpoint_fuzz.py for why .lstrip("Bearer ") is wrong here.
            headers["Authorization"] = auth if auth.startswith("Bearer ") else f"Bearer {auth}"

        results = {"200": 0, "429": 0, "503": 0, "other": 0, "error": 0}
        lock    = threading.Lock()
        start   = time.time()

        def send(_):
            try:
                data = body.encode() if body else None
                req  = urllib.request.Request(url, method=method, headers=headers, data=data)
                h    = urllib.request.HTTPSHandler(context=ctx)
                op   = urllib.request.build_opener(h)
                with op.open(req, timeout=timeout) as resp:
                    code = str(resp.status)
            except urllib.error.HTTPError as e:
                code = str(e.code)
            except Exception:
                code = "error"

            with lock:
                key = code if code in results else "other"
                results[key] += 1
                done = sum(results.values())
                print(f"  {Colors.DARK_GRAY}[{done:>4}/{total}]{Colors.RESET} "
                      f"200:{Colors.GREEN}{results['200']}{Colors.RESET} "
                      f"429:{Colors.YELLOW}{results['429']}{Colors.RESET} "
                      f"err:{Colors.RED}{results['error']}{Colors.RESET}",
                      end="\r")

        import concurrent.futures
        with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as ex:
            list(ex.map(send, range(total)))

        elapsed = time.time() - start
        rps     = total / elapsed

        print(" " * 80)
        print()
        print_status(f"Completed {total} requests in {elapsed:.1f}s ({rps:.1f} req/s)", "info")
        print(f"  {Colors.GREEN}200/OK    {Colors.RESET}: {results['200']}")
        print(f"  {Colors.YELLOW}429 Limit {Colors.RESET}: {results['429']}")
        print(f"  {Colors.RED}503/Err   {Colors.RESET}: {results['503'] + results['error']}")
        print(f"  {Colors.DARK_GRAY}Other     {Colors.RESET}: {results['other']}")

        findings = []
        if results["429"] == 0 and results["200"] > total * 0.8:
            print(f"\n  {Colors.RED}[HIGH]{Colors.RESET}   No rate limiting detected — {total} requests all succeeded")
            findings.append(self._finding(
                "HIGH", "Missing Rate Limiting", url,
                f"{total} requests completed with {results['200']} successful responses"
            ))
        elif results["429"] > 0:
            print(f"\n  {Colors.GREEN}[OK]{Colors.RESET}     Rate limiting active — {results['429']} requests throttled (HTTP 429)")
            findings.append(self._finding(
                "OK", "Rate Limiting Active", url,
                f"{results['429']}/{total} requests returned HTTP 429"
            ))
        else:
            print(f"\n  {Colors.YELLOW}[MEDIUM]{Colors.RESET} Inconclusive — review response codes above")
            findings.append(self._finding("MEDIUM", "Rate Limiting Inconclusive", url,
                                          str(results)))

        print()
        return findings
