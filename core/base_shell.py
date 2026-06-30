#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
core/base_shell.py — Shared Metasploit-style interactive shell.

This is the common engine behind every NeiveZ pentest tool (APIX, HSHX,
and future ones). A tool only needs to subclass PentestShell, set a
handful of class attributes, and optionally override _print_result_item
for custom result formatting. Everything else (use/set/run/show/report/
session tracking/non-interactive CLI mode) is free and stays in sync
across tools automatically.

NOTE ON THE FIX: the original apix.py/hshx.py called
self.session.add_findings(...) / get_all_findings() (APIX) and
self.session.add_cracks(...) / get_all_cracks() (HSHX), but Session only
ever defined add_results()/get_all_results(). That mismatch meant every
`run` that produced results, every `show findings|results`, and every
`report` call raised an AttributeError at runtime — `report` in particular
crashed the whole shell, since it wasn't wrapped in try/except. This base
class calls the methods that actually exist on Session.
"""
import argparse
import cmd
import json
import os
import shutil
import sys
from datetime import datetime

from utils.colors import Colors, print_status
from utils.session import Session


class PentestShell(cmd.Cmd):
    """Base class for every NeiveZ tool's interactive shell."""

    # Override these in subclasses
    TOOL_NAME: str = "tool"
    TAGLINE: str = ""
    VERSION: str = "1.0.0"
    MODULES: dict = {}
    RESULT_LABEL: str = "Results"          # "Findings" for APIX, "Cracked" for HSHX
    DEFAULT_REPORT_FORMAT: str = "html"
    REPORT_GENERATOR = None                # set to the tool's ReportGenerator class

    intro = ""

    def __init__(self):
        super().__init__()
        self.session = Session()
        self.active_module = None
        self.active_module_name = None
        self._update_prompt()
        self._show_header()

    # ── header / prompt ──────────────────────────────────────────────
    def _show_header(self):
        stats = self.session.get_stats()
        print(f"\n {Colors.BOLD}{Colors.RED}{self.TOOL_NAME}{Colors.RESET} "
              f"{Colors.DARK_GRAY}{self.TAGLINE}{Colors.RESET} "
              f"{Colors.WHITE}v{self.VERSION}{Colors.RESET}")
        print(f" {Colors.DARK_GRAY}Author: NeiveZ | For authorized testing only{Colors.RESET}")
        print(f" {Colors.DARK_GRAY}Scans: {Colors.WHITE}{stats['scans']}"
              f" {Colors.DARK_GRAY}{self.RESULT_LABEL}: {Colors.WHITE}{stats['results']}"
              f" {Colors.DARK_GRAY}Reports: {Colors.WHITE}{stats['reports']}{Colors.RESET}")
        print(f"\n {Colors.DARK_GRAY}Type {Colors.CYAN}help{Colors.DARK_GRAY} to list commands.{Colors.RESET}\n")

    def _update_prompt(self):
        tool = f"{Colors.BOLD}{Colors.RED}{self.TOOL_NAME}{Colors.RESET}"
        if self.active_module_name:
            self.prompt = (f"{tool}{Colors.DARK_GRAY}({Colors.RESET}{Colors.YELLOW}"
                            f"{self.active_module_name}{Colors.RESET}{Colors.DARK_GRAY}){Colors.RESET} "
                            f"{Colors.WHITE}>{Colors.RESET} ")
        else:
            self.prompt = f"{tool} {Colors.WHITE}>{Colors.RESET} "

    def default(self, line):
        print_status(f"Unknown command: '{line}'. Type 'help'.", "error")

    def emptyline(self):
        pass

    # ── module management ────────────────────────────────────────────
    def do_use(self, name):
        """Load a module.\n Usage: use <module>"""
        name = name.strip()
        if not name:
            print_status("Usage: use <module_name>", "warn")
            return
        if name not in self.MODULES:
            print_status(f"Module '{name}' not found. Run 'show modules'.", "error")
            return
        self.active_module_name = name
        self.active_module = self.MODULES[name]()
        self._update_prompt()
        print_status(f"Module loaded: {Colors.YELLOW}{name}{Colors.RESET}", "ok")
        print()
        self.active_module.show_info()

    def do_set(self, args):
        """Set a module option.\n Usage: set <OPTION> <value>"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        parts = args.strip().split(None, 1)
        if len(parts) < 2:
            print_status("Usage: set <OPTION> <value>", "warn")
            return
        opt, val = parts[0].upper(), parts[1]
        if self.active_module.set_option(opt, val):
            print_status(f"{Colors.CYAN}{opt}{Colors.RESET} => {Colors.WHITE}{val}{Colors.RESET}", "ok")
        else:
            print_status(f"Unknown option: {opt}.", "error")

    def do_run(self, _):
        """Execute the loaded module.\n Usage: run"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        print()
        try:
            results = self.active_module.run()
            if results:
                self.session.add_results(self.active_module_name, results)
                self._auto_save(results)
        except KeyboardInterrupt:
            print()
            print_status("Interrupted.", "warn")
        except Exception as e:
            print_status(f"Module error: {e}", "error")

    def do_options(self, _):
        """Show module options.\n Usage: options"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_options()

    def do_info(self, _):
        """Show module info.\n Usage: info"""
        if not self.active_module:
            print_status("No module loaded.", "warn")
            return
        self.active_module.show_info()

    def do_back(self, _):
        """Unload the current module.\n Usage: back"""
        if self.active_module:
            print_status(f"Unloaded: {self.active_module_name}", "info")
            self.active_module = None
            self.active_module_name = None
            self._update_prompt()
        else:
            print_status("No module loaded.", "warn")

    # ── show ──────────────────────────────────────────────────────────
    def do_show(self, args):
        """show modules | results | session"""
        arg = args.strip().lower()
        if arg == "modules":
            self._show_modules()
        elif arg in ("results", "findings", "cracks"):
            self._show_results()
        elif arg == "session":
            self._show_session()
        else:
            print_status("Usage: show [modules|results|session]", "warn")

    def _show_modules(self):
        col_w = shutil.get_terminal_size((80, 20)).columns
        print(f"\n {Colors.BOLD}{Colors.WHITE}Available Modules{Colors.RESET}\n")
        print(f" {'─' * (col_w - 4)}")
        for name, cls in self.MODULES.items():
            # Pulled straight from the module's own DESCRIPTION instead of a
            # second hardcoded copy, so the two can no longer drift apart.
            desc = getattr(cls, "DESCRIPTION", "")
            print(f" {Colors.CYAN}{name:<16}{Colors.RESET}{Colors.WHITE}{desc}{Colors.RESET}")
        print(f" {'─' * (col_w - 4)}\n")

    def _show_results(self):
        all_results = self.session.get_all_results()
        if not all_results:
            print_status("No results yet. Run a module first.", "warn")
            return
        print(f"\n {Colors.BOLD}{Colors.WHITE}{self.RESULT_LABEL}{Colors.RESET}\n")
        for module, items in all_results.items():
            print(f" {Colors.YELLOW}[{module}]{Colors.RESET}")
            for item in (items if isinstance(items, list) else [items]):
                self._print_result_item(item)
        print()

    def _print_result_item(self, item):
        """Default one-line result renderer. Override per tool for nicer output."""
        if isinstance(item, dict):
            print(f"   {Colors.DARK_GRAY}{item}{Colors.RESET}")

    def _show_session(self):
        stats = self.session.get_stats()
        print(f"\n {Colors.BOLD}{Colors.WHITE}Session{Colors.RESET}\n")
        print(f" {Colors.DARK_GRAY}Session ID{Colors.RESET}: {Colors.CYAN}{stats['id']}{Colors.RESET}")
        print(f" {Colors.DARK_GRAY}Started   {Colors.RESET}: {stats['started']}")
        print(f" {Colors.DARK_GRAY}Scans     {Colors.RESET}: {Colors.WHITE}{stats['scans']}{Colors.RESET}")
        print(f" {Colors.DARK_GRAY}{self.RESULT_LABEL:<10}{Colors.RESET}: {Colors.WHITE}{stats['results']}{Colors.RESET}")
        print(f" {Colors.DARK_GRAY}Reports   {Colors.RESET}: {Colors.WHITE}{stats['reports']}{Colors.RESET}\n")

    # ── report ────────────────────────────────────────────────────────
    def do_report(self, args):
        """Generate a report.\n Usage: report [txt|json|html] [filename]"""
        parts = args.strip().split()
        fmt = parts[0].lower() if parts else self.DEFAULT_REPORT_FORMAT
        fname = parts[1] if len(parts) > 1 else None
        all_results = self.session.get_all_results()
        if not all_results:
            print_status("No results to report.", "warn")
            return
        if self.REPORT_GENERATOR is None:
            print_status("No REPORT_GENERATOR configured for this tool.", "error")
            return
        try:
            gen = self.REPORT_GENERATOR(all_results, self.session.get_stats())
            path = gen.generate(fmt=fmt, filename=fname)
        except Exception as e:
            print_status(f"Report error: {e}", "error")
            return
        if path:
            self.session.increment_reports()
            print_status(f"Report saved: {Colors.CYAN}{path}{Colors.RESET}", "ok")

    def _auto_save(self, results):
        os.makedirs("reports", exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        path = f"reports/auto_{self.active_module_name.replace('/', '_')}_{ts}.json"
        try:
            with open(path, "w") as f:
                json.dump({"module": self.active_module_name, "timestamp": ts, "results": results},
                          f, indent=2, default=str)
        except Exception:
            pass

    # ── utility ───────────────────────────────────────────────────────
    def do_clear(self, _):
        """Clear the screen."""
        os.system("cls" if os.name == "nt" else "clear")
        self._show_header()

    def do_exit(self, _):
        """Exit the shell."""
        print(f"\n {Colors.DARK_GRAY}Goodbye. Stay ethical.{Colors.RESET}\n")
        return True

    def do_quit(self, _):
        return self.do_exit(_)

    def do_help(self, arg):
        if arg:
            super().do_help(arg)
            return
        print(f"""
 {Colors.BOLD}{Colors.WHITE}Core Commands{Colors.RESET}
 {'─' * 40}
 {Colors.CYAN}use <module>{Colors.RESET}            Load a module
 {Colors.CYAN}set <OPTION> <value>{Colors.RESET}    Set option
 {Colors.CYAN}run{Colors.RESET}                     Execute module
 {Colors.CYAN}options / info / back{Colors.RESET}   Module management

 {Colors.BOLD}{Colors.WHITE}Show{Colors.RESET}
 {'─' * 40}
 {Colors.CYAN}show modules{Colors.RESET}            List modules
 {Colors.CYAN}show results{Colors.RESET}            {self.RESULT_LABEL}
 {Colors.CYAN}show session{Colors.RESET}            Session info

 {Colors.BOLD}{Colors.WHITE}Output{Colors.RESET}
 {'─' * 40}
 {Colors.CYAN}report [txt|json|html]{Colors.RESET}  Generate report

 {Colors.BOLD}{Colors.WHITE}Utility{Colors.RESET}
 {'─' * 40}
 {Colors.CYAN}clear{Colors.RESET}                   Clear screen
 {Colors.CYAN}exit / quit{Colors.RESET}              Exit shell
""")


# ── non-interactive / scriptable CLI mode ───────────────────────────────

def build_arg_parser(tool_name: str, tagline: str) -> argparse.ArgumentParser:
    """Shared argparse layout so every tool's one-shot CLI mode behaves the same."""
    p = argparse.ArgumentParser(
        prog=tool_name,
        description=f"{tagline} — non-interactive mode. Omit -m to launch the interactive shell instead.",
    )
    p.add_argument("-m", "--module", metavar="MODULE", help="Module to run, e.g. api/fuzz")
    p.add_argument("-s", "--set", action="append", default=[], metavar="OPTION=VALUE",
                    help="Set a module option (repeatable): -s TARGET=https://api.example.com")
    p.add_argument("-f", "--format", choices=["txt", "json", "html"], default=None,
                    help="Report format (defaults to the tool's default format)")
    p.add_argument("-o", "--output", metavar="FILENAME", default=None,
                    help="Report filename (saved under reports/)")
    p.add_argument("--no-report", action="store_true", help="Skip writing a report file")
    p.add_argument("--no-color", action="store_true", help="Disable ANSI colors (useful in CI logs)")
    return p


def run_non_interactive(shell_cls, args: argparse.Namespace) -> int:
    """Load one module, set options, run it once, optionally write a report.

    Returns a process exit code: 0 on success, 1 if the module could not be
    loaded/run, 2 if it ran but produced no results.
    """
    if args.no_color:
        Colors.disable()

    shell = shell_cls()
    shell.do_use(args.module)
    if not shell.active_module:
        return 1

    for kv in args.set:
        if "=" not in kv:
            print_status(f"Ignoring malformed --set value (expected OPTION=VALUE): {kv}", "warn")
            continue
        key, value = kv.split("=", 1)
        shell.do_set(f"{key} {value}")

    shell.do_run("")

    if not shell.session.get_all_results():
        return 2

    if not args.no_report:
        fmt = args.format or shell.DEFAULT_REPORT_FORMAT
        shell.do_report(f"{fmt} {args.output or ''}".strip())

    return 0


def main_entrypoint(shell_cls):
    """Call from each tool's `if __name__ == "__main__":` block."""
    parser = build_arg_parser(shell_cls.TOOL_NAME, shell_cls.TAGLINE)
    args = parser.parse_args()
    try:
        if args.module:
            sys.exit(run_non_interactive(shell_cls, args))
        shell_cls().cmdloop()
    except KeyboardInterrupt:
        print(f"\n\n {Colors.DARK_GRAY}Interrupted.{Colors.RESET}\n")
        sys.exit(0)
