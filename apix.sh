#!/usr/bin/env bash
# apix.sh — launcher for APIX (API Security Tester)
set -euo pipefail
cd "$(dirname "${BASH_SOURCE[0]}")"

PYTHON_BIN="${PYTHON_BIN:-python3}"

if ! command -v "$PYTHON_BIN" >/dev/null 2>&1; then
    echo "[-] $PYTHON_BIN not found. Install Python 3.10+ and try again." >&2
    exit 1
fi

PY_VERSION="$("$PYTHON_BIN" -c 'import sys; print("%d.%d" % sys.version_info[:2])')"
PY_MAJOR="${PY_VERSION%%.*}"
PY_MINOR="${PY_VERSION##*.}"
if [ "$PY_MAJOR" -lt 3 ] || { [ "$PY_MAJOR" -eq 3 ] && [ "$PY_MINOR" -lt 10 ]; }; then
    echo "[!] Detected Python $PY_VERSION — APIX targets 3.10+. Continuing anyway." >&2
fi

exec "$PYTHON_BIN" apix.py "$@"
