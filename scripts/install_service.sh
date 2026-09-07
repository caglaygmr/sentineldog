#!/usr/bin/env bash
# SentinelDog Systemd Service Installer for Linux Servers
set -euo pipefail

if [ "$EUID" -ne 0 ]; then
  echo "[-] Please run as root: sudo bash scripts/install_service.sh"
  exit 1
fi

INSTALL_DIR="/opt/sentineldog"
SERVICE_FILE="/etc/systemd/system/sentineldog.service"

echo "[*] Installing SentinelDog to $INSTALL_DIR..."
mkdir -p "$INSTALL_DIR"
cp -r . "$INSTALL_DIR"

echo "[*] Setting up Python virtual environment..."
python3 -m venv "$INSTALL_DIR/.venv"
"$INSTALL_DIR/.venv/bin/pip" install --upgrade pip setuptools
"$INSTALL_DIR/.venv/bin/pip" install -r "$INSTALL_DIR/requirements.txt"
"$INSTALL_DIR/.venv/bin/pip" install --no-build-isolation -e "$INSTALL_DIR"

echo "[*] Initializing cryptographic FIM baseline..."
"$INSTALL_DIR/.venv/bin/sentineldog" baseline create

echo "[*] Installing systemd service..."
cp "$INSTALL_DIR/systemd/sentineldog.service" "$SERVICE_FILE"
systemctl daemon-reload
systemctl enable --now sentineldog.service

echo "[+] SentinelDog service installed and active!"
systemctl status sentineldog.service --no-pager
