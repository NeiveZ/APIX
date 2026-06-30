#!/usr/bin/env bash
# wifx.sh — Launcher for WIFX (WiFi Recon & Audit)
# Resolves its own directory so it can be run from anywhere, checks
# the Python version and for root (most wifi/* modules need raw
# socket / monitor-mode access), then hands off to the console.

set -euo pipefail

DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$DIR"

if ! command -v python3 >/dev/null 2>&1; then
    echo "[-] python3 not found. Install Python 3.10+ and try again."
    exit 1
fi

PY_VERSION="$(python3 -c 'import sys; print(f"{sys.version_info.major}.{sys.version_info.minor}")')"
REQUIRED="3.10"
if [ "$(printf '%s\n%s\n' "$REQUIRED" "$PY_VERSION" | sort -V | head -n1)" != "$REQUIRED" ]; then
    echo "[!] Warning: WIFX targets Python $REQUIRED+, found $PY_VERSION. Continuing anyway."
fi

if [ "$(id -u)" -ne 0 ]; then
    echo "[!] Not running as root — monitor mode, deauth and WPS modules need raw socket"
    echo "    access and will likely fail. Re-run with sudo for full functionality."
fi

for dep in iw; do
    if ! command -v "$dep" >/dev/null 2>&1; then
        echo "[!] '$dep' not found — wifi/scan will fall back to iwlist/nmcli if available."
    fi
done

mkdir -p captures reports

exec python3 wifx.py "$@"
