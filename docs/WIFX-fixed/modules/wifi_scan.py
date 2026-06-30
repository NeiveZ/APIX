#!/usr/bin/env python3
# modules/wifi_scan.py — WiFi network scanner for WIFX

import subprocess
import shutil
import re
import os
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


# Security ratings per encryption type
SECURITY_RATING = {
    "WPA3":    ("STRONG",   Colors.GREEN),
    "WPA2":    ("GOOD",     Colors.GREEN),
    "WPA":     ("WEAK",     Colors.YELLOW),
    "WEP":     ("CRITICAL", Colors.RED),
    "OPEN":    ("CRITICAL", Colors.RED),
    "OWE":     ("GOOD",     Colors.GREEN),
    "UNKNOWN": ("?",        Colors.DARK_GRAY),
}


class WiFiScanner(BaseModule):

    NAME        = "wifi/scan"
    DESCRIPTION = "Scan nearby WiFi networks — SSID, BSSID, channel, signal, encryption, WPS"
    REFERENCES  = [
        "https://www.wi-fi.org/discover-wi-fi/wi-fi-certified-wpa3",
        "https://attack.mitre.org/techniques/T1465/",
    ]

    def _define_options(self):
        self._add_option("INTERFACE", "",      True,  "Wireless interface (e.g. wlan0, wlan1)")
        self._add_option("TIMEOUT",   "15",    False, "Scan duration in seconds")
        self._add_option("BAND",      "both",  False, "Frequency band: 2.4 | 5 | both")
        self._add_option("MONITOR",   "false", False, "Enable monitor mode before scan (true/false)")

    def run(self) -> list:
        if not self._validate():
            return []

        iface   = self.get_option("INTERFACE").strip()
        timeout = int(self.get_option("TIMEOUT") or 15)
        monitor = self.get_option("MONITOR").lower() == "true"

        # Check tools
        tool = self._detect_tool()
        if not tool:
            print_status("No WiFi scanning tool found.", "error")
            print_status("Install one: apt install iw wireless-tools aircrack-ng", "info")
            return []

        print_section(f"WiFi Scan — {iface} ({tool})")
        print_status(f"Interface : {Colors.WHITE}{iface}{Colors.RESET}", "info")
        print_status(f"Tool      : {Colors.WHITE}{tool}{Colors.RESET}", "info")
        print_status(f"Timeout   : {Colors.WHITE}{timeout}s{Colors.RESET}", "info")
        print()

        # Enable monitor mode if requested
        if monitor:
            self._set_monitor_mode(iface, True)

        networks = []
        if tool == "iw":
            networks = self._scan_iw(iface, timeout)
        elif tool == "iwlist":
            networks = self._scan_iwlist(iface, timeout)
        elif tool == "nmcli":
            networks = self._scan_nmcli(iface, timeout)
        elif tool == "airodump":
            networks = self._scan_airodump(iface, timeout)

        if not networks:
            print_status("No networks found or scan failed.", "warn")
            print_status("Try running as root or check if interface is up.", "info")
            if monitor:
                self._set_monitor_mode(iface, False)
            return []

        # Display results
        findings = []
        print_status(f"Found {Colors.WHITE}{len(networks)}{Colors.RESET} network(s):\n", "ok")

        # Sort by signal strength
        networks.sort(key=lambda x: x.get("signal", -100), reverse=True)

        for net in networks:
            findings += self._analyze_network(net)

        # Summary by security type
        print()
        print_status("Security Summary:", "info")
        from collections import Counter
        sec_count = Counter(n.get("security", "UNKNOWN").upper() for n in networks)
        for sec, count in sec_count.most_common():
            _, color = SECURITY_RATING.get(sec, ("?", Colors.DARK_GRAY))
            print(f"  {color}{sec:<10}{Colors.RESET}: {count} network(s)")

        if monitor:
            self._set_monitor_mode(iface, False)

        print()
        print_status(f"Scan complete. {Colors.WHITE}{len(findings)}{Colors.RESET} finding(s).", "ok")
        return findings

    # ── Scan backends ─────────────────────────────────────────────

    def _scan_iw(self, iface, timeout) -> list:
        print_status("Triggering scan...", "run")
        try:
            subprocess.run(["iw", "dev", iface, "scan", "trigger"],
                           capture_output=True, timeout=5)
            import time; time.sleep(min(timeout, 10))
            out = subprocess.check_output(
                ["iw", "dev", iface, "scan"],
                stderr=subprocess.DEVNULL, timeout=timeout
            ).decode("utf-8", errors="replace")
        except Exception as e:
            print_status(f"iw scan failed: {e}", "warn")
            return []

        networks = []
        current  = {}
        for line in out.splitlines():
            line = line.strip()
            if line.startswith("BSS "):
                if current:
                    networks.append(current)
                current = {"bssid": line.split()[1].split("(")[0], "ssid": "<hidden>",
                           "signal": -100, "channel": "?", "security": "UNKNOWN", "wps": False}
            elif "SSID:" in line:
                ssid = line.split("SSID:")[1].strip()
                if ssid:
                    current["ssid"] = ssid
            elif "signal:" in line:
                try:
                    current["signal"] = float(re.search(r"signal: ([-\d.]+)", line).group(1))
                except Exception:
                    pass
            elif "DS Parameter set: channel" in line:
                try:
                    current["channel"] = re.search(r"channel (\d+)", line).group(1)
                except Exception:
                    pass
            elif "WPA" in line or "RSN" in line:
                if "WPA3" in line or "SAE" in line:
                    current["security"] = "WPA3"
                elif "WPA2" in line or "RSN" in line:
                    current["security"] = "WPA2"
                elif "WPA" in line:
                    current["security"] = "WPA"
            elif "WPS" in line:
                current["wps"] = True
            elif "capability:" in line and "Privacy" not in line and current.get("security") == "UNKNOWN":
                current["security"] = "OPEN"
            elif "Privacy" in line and current.get("security") == "UNKNOWN":
                current["security"] = "WEP"

        if current:
            networks.append(current)
        return networks

    def _scan_iwlist(self, iface, timeout) -> list:
        try:
            out = subprocess.check_output(
                ["iwlist", iface, "scan"],
                stderr=subprocess.DEVNULL, timeout=timeout
            ).decode("utf-8", errors="replace")
        except Exception as e:
            print_status(f"iwlist scan failed: {e}", "warn")
            return []

        networks = []
        current  = {}
        for line in out.splitlines():
            line = line.strip()
            if "Cell" in line and "Address:" in line:
                if current:
                    networks.append(current)
                bssid = re.search(r"Address: ([\da-fA-F:]+)", line)
                current = {"bssid": bssid.group(1) if bssid else "?",
                           "ssid": "<hidden>", "signal": -100,
                           "channel": "?", "security": "OPEN", "wps": False}
            elif "ESSID:" in line:
                ssid = re.search(r'ESSID:"([^"]*)"', line)
                if ssid:
                    current["ssid"] = ssid.group(1) or "<hidden>"
            elif "Signal level" in line:
                sig = re.search(r"Signal level=([-\d]+)", line)
                if sig:
                    current["signal"] = int(sig.group(1))
            elif "Channel:" in line:
                ch = re.search(r"Channel:(\d+)", line)
                if ch:
                    current["channel"] = ch.group(1)
            elif "WPA2" in line:
                current["security"] = "WPA2"
            elif "WPA" in line:
                current["security"] = "WPA"
            elif "WEP" in line:
                current["security"] = "WEP"
        if current:
            networks.append(current)
        return networks

    def _scan_nmcli(self, iface, timeout) -> list:
        try:
            subprocess.run(["nmcli", "dev", "wifi", "rescan", "ifname", iface],
                           capture_output=True, timeout=10)
            import time; time.sleep(3)
            out = subprocess.check_output(
                ["nmcli", "-t", "-f", "SSID,BSSID,CHAN,SIGNAL,SECURITY,WPS",
                 "dev", "wifi", "list", "ifname", iface],
                stderr=subprocess.DEVNULL, timeout=timeout
            ).decode("utf-8", errors="replace")
        except Exception as e:
            print_status(f"nmcli scan failed: {e}", "warn")
            return []

        networks = []
        for line in out.splitlines():
            parts = line.split(":")
            if len(parts) >= 5:
                networks.append({
                    "ssid":     parts[0] or "<hidden>",
                    "bssid":    ":".join(parts[1:7]) if len(parts) > 6 else parts[1],
                    "channel":  parts[-4] if len(parts) > 4 else "?",
                    "signal":   int(parts[-3]) if len(parts) > 3 and parts[-3].isdigit() else -100,
                    "security": parts[-2] if len(parts) > 2 else "UNKNOWN",
                    "wps":      "WPS" in line,
                })
        return networks

    def _scan_airodump(self, iface, timeout) -> list:
        print_status("Starting airodump-ng scan...", "run")
        out_prefix = "/tmp/wifx_scan"
        try:
            proc = subprocess.Popen(
                ["airodump-ng", "--write", out_prefix, "--output-format", "csv", iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
            import time; time.sleep(min(timeout, 15))
            proc.terminate()
        except Exception as e:
            print_status(f"airodump-ng failed: {e}", "warn")
            return []

        csv_file = f"{out_prefix}-01.csv"
        networks = []
        if os.path.isfile(csv_file):
            try:
                with open(csv_file) as f:
                    lines = f.readlines()
                for line in lines[2:]:
                    parts = [p.strip() for p in line.split(",")]
                    if len(parts) < 14 or not parts[0]:
                        continue
                    privacy = parts[5].upper()
                    sec = "WPA3" if "WPA3" in privacy else \
                          "WPA2" if "WPA2" in privacy else \
                          "WPA"  if "WPA"  in privacy else \
                          "WEP"  if "WEP"  in privacy else "OPEN"
                    networks.append({
                        "bssid":    parts[0],
                        "channel":  parts[3],
                        "signal":   int(parts[8]) if parts[8].lstrip("-").isdigit() else -100,
                        "security": sec,
                        "ssid":     parts[13] if len(parts) > 13 else "<hidden>",
                        "wps":      False,
                    })
                os.remove(csv_file)
            except Exception:
                pass
        return networks

    # ── Network analysis ──────────────────────────────────────────

    def _analyze_network(self, net: dict) -> list:
        ssid     = net.get("ssid", "<hidden>")
        bssid    = net.get("bssid", "?")
        signal   = net.get("signal", -100)
        channel  = net.get("channel", "?")
        security = net.get("security", "UNKNOWN").upper()
        wps      = net.get("wps", False)

        rating, color = SECURITY_RATING.get(security, ("?", Colors.DARK_GRAY))
        sig_bar  = self._signal_bar(signal)
        wps_str  = f" {Colors.YELLOW}[WPS]{Colors.RESET}" if wps else ""

        print(f"  {color}{security:<8}{Colors.RESET} "
              f"{Colors.BOLD}{Colors.WHITE}{ssid:<32}{Colors.RESET} "
              f"{Colors.DARK_GRAY}{bssid}  ch:{channel:<4}{Colors.RESET}"
              f"{sig_bar}{wps_str}")

        findings = []

        if security in ("OPEN", "WEP"):
            findings.append(self._finding(
                "CRITICAL", f"Insecure Network: {security}",
                f"{ssid} ({bssid})",
                f"Network uses {security} — no encryption or broken encryption"
            ))
        elif security == "WPA":
            findings.append(self._finding(
                "HIGH", "Deprecated WPA (TKIP)",
                f"{ssid} ({bssid})",
                "WPA/TKIP is vulnerable to TKIP MIC attack — upgrade to WPA2/WPA3"
            ))

        if wps:
            findings.append(self._finding(
                "MEDIUM", "WPS Enabled",
                f"{ssid} ({bssid})",
                "WPS PIN attack possible (Pixie Dust, Reaver) — disable WPS in router settings"
            ))

        return findings

    def _signal_bar(self, signal: float) -> str:
        pct   = max(0, min(100, int((signal + 100) * 2)))
        bars  = int(pct / 20)
        color = Colors.GREEN if pct > 60 else Colors.YELLOW if pct > 30 else Colors.RED
        return f" {color}{'█' * bars}{'░' * (5 - bars)}{Colors.RESET} {signal}dBm"

    # ── Helpers ───────────────────────────────────────────────────

    def _detect_tool(self) -> str | None:
        for tool, check in [
            ("iw",        ["iw"]),
            ("iwlist",    ["iwlist"]),
            ("nmcli",     ["nmcli"]),
            ("airodump",  ["airodump-ng"]),
        ]:
            if all(shutil.which(c) for c in check):
                return tool
        return None

    def _set_monitor_mode(self, iface: str, enable: bool):
        mode = "monitor" if enable else "managed"
        action = "Enabling monitor mode" if enable else "Restoring managed mode"
        print_status(f"{action} on {iface}...", "run")
        try:
            subprocess.run(["ip", "link", "set", iface, "down"],
                           capture_output=True, timeout=5)
            subprocess.run(["iw", "dev", iface, "set", "type", mode],
                           capture_output=True, timeout=5)
            subprocess.run(["ip", "link", "set", iface, "up"],
                           capture_output=True, timeout=5)
            print_status(f"Interface {iface} set to {mode} mode.", "ok")
        except Exception as e:
            print_status(f"Failed to set {mode} mode: {e}", "warn")
