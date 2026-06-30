#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
APIX - API Security Tester
Author: NeiveZ | github.com/NeiveZ/APIX
"""
from core.base_shell import PentestShell, main_entrypoint
from utils.colors import Colors
from modules.endpoint_fuzz import EndpointFuzzer
from modules.auth_test import AuthTester
from modules.idor_test import IDORTester, RateLimitTester
from modules.report_gen import ReportGenerator


class APIXShell(PentestShell):
    TOOL_NAME = "apix"
    TAGLINE = "API Security Tester"
    VERSION = "1.0.0"
    RESULT_LABEL = "Findings"
    DEFAULT_REPORT_FORMAT = "html"
    REPORT_GENERATOR = ReportGenerator
    MODULES = {
        "api/fuzz": EndpointFuzzer,
        "api/auth": AuthTester,
        "api/idor": IDORTester,
        "api/ratelimit": RateLimitTester,
    }

    def _print_result_item(self, item):
        if not isinstance(item, dict):
            return
        sev = item.get("severity", "?")
        c = (Colors.RED if sev in ("HIGH", "CRITICAL") else
             Colors.YELLOW if sev == "MEDIUM" else
             Colors.GREEN if sev == "OK" else Colors.DARK_GRAY)
        print(f"   {c}[{sev}]{Colors.RESET} {item.get('check', '')} — "
              f"{Colors.DARK_GRAY}{item.get('endpoint', '')[:60]}{Colors.RESET}")


if __name__ == "__main__":
    main_entrypoint(APIXShell)
