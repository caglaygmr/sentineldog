#!/usr/bin/env bash
# One-click interactive demonstration script for SentinelDog
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"

cd "$ROOT_DIR"

echo "=========================================================="
echo "    SentinelDog Security Watchdog & Sentinel Demo"
echo "=========================================================="

if [ ! -d ".venv" ]; then
    echo "[*] Creating virtual environment..."
    python3 -m venv .venv
    .venv/bin/pip install --upgrade pip setuptools
    .venv/bin/pip install -r requirements.txt
    .venv/bin/pip install --no-build-isolation -e .
fi

echo ""
echo "Select an action to demonstrate:"
echo "  1) Run Diagnostic Host Security Scan (sentineldog scan)"
echo "  2) Run Interactive Threat Simulation Suite (simulate_threats.py)"
echo "  3) Run Unit Tests (pytest)"
echo "  4) Generate / Refresh FIM Baseline (sentineldog baseline create)"
echo "  5) Launch Continuous Watchdog Daemon (sentineldog watch)"
echo ""
read -p "Enter choice [1-5]: " choice

case "$choice" in
    1)
        .venv/bin/sentineldog scan
        ;;
    2)
        .venv/bin/python3 tests/simulate_threats.py
        ;;
    3)
        .venv/bin/pytest -v
        ;;
    4)
        .venv/bin/sentineldog baseline create
        ;;
    5)
        .venv/bin/sentineldog watch
        ;;
    *)
        echo "[-] Invalid selection."
        exit 1
        ;;
esac
