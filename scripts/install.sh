#!/bin/bash
# Install airvpn-rs binaries and systemd units.
# Idempotent — safe to run multiple times.
#
# Usage: sudo ./scripts/install.sh

set -euo pipefail

if [[ $EUID -ne 0 ]]; then
    echo "error: must run as root (sudo ./scripts/install.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "$0")/.." && pwd)"

# Build release binaries
echo "Building release binaries..."
sudo -u "${SUDO_USER:-$(logname)}" bash -c "cd '$SCRIPT_DIR' && cargo build --release"

# Install binaries
echo "Installing binaries to /usr/bin/..."
install -Dm755 "$SCRIPT_DIR/target/release/airvpn" /usr/bin/airvpn
install -Dm755 "$SCRIPT_DIR/target/release/airvpn-gui" /usr/bin/airvpn-gui

# Install systemd units
echo "Installing systemd units..."
install -Dm644 "$SCRIPT_DIR/resources/airvpn-helper.socket" /etc/systemd/system/airvpn-helper.socket
install -Dm644 "$SCRIPT_DIR/resources/airvpn-helper.service" /etc/systemd/system/airvpn-helper.service

# Reload and enable socket activation
systemctl daemon-reload
systemctl enable --now airvpn-helper.socket

echo ""
echo "Installed:"
echo "  /usr/bin/airvpn"
echo "  /usr/bin/airvpn-gui"
echo "  /etc/systemd/system/airvpn-helper.socket (enabled)"
echo "  /etc/systemd/system/airvpn-helper.service"
echo ""
echo "Socket status:"
systemctl status --no-pager airvpn-helper.socket || true
