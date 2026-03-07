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

# Install provider config
echo "Installing provider config..."
install -Dm644 "$SCRIPT_DIR/resources/provider.json" /etc/airvpn-rs/provider.json

# Install desktop entry and icon
echo "Installing desktop entry..."
install -Dm644 "$SCRIPT_DIR/resources/airvpn-gui.desktop" /usr/share/applications/airvpn-gui.desktop
install -Dm644 "$SCRIPT_DIR/resources/airvpn.svg" /usr/share/icons/hicolor/scalable/apps/airvpn.svg

# Install systemd units
echo "Installing systemd units..."
install -Dm644 "$SCRIPT_DIR/resources/airvpn-helper.socket" /etc/systemd/system/airvpn-helper.socket
install -Dm644 "$SCRIPT_DIR/resources/airvpn-helper.service" /etc/systemd/system/airvpn-helper.service

# Reload units first (so stop uses the current unit file)
systemctl daemon-reload

# Stop helper if running (so it picks up the new binary on next activation)
if systemctl is-active --quiet airvpn-helper.service; then
    echo "Stopping running helper (socket stays active for next activation)..."
    systemctl stop airvpn-helper.service
fi

# Install shell completions
echo "Installing shell completions..."
/usr/bin/airvpn completions zsh > /usr/share/zsh/site-functions/_airvpn 2>/dev/null || true
/usr/bin/airvpn completions fish > /usr/share/fish/vendor_completions.d/airvpn.fish 2>/dev/null || true
/usr/bin/airvpn completions bash > /usr/share/bash-completion/completions/airvpn 2>/dev/null || true

# Create state directory for latency cache
echo "Creating state directory..."
install -dm755 /var/lib/airvpn-rs

# Enable socket activation
systemctl enable --now airvpn-helper.socket

echo ""
echo "Installed:"
echo "  /usr/bin/airvpn"
echo "  /usr/bin/airvpn-gui"
echo "  /usr/share/applications/airvpn-gui.desktop"
echo "  /usr/share/icons/hicolor/scalable/apps/airvpn.svg"
echo "  /usr/share/zsh/site-functions/_airvpn"
echo "  /usr/share/fish/vendor_completions.d/airvpn.fish"
echo "  /usr/share/bash-completion/completions/airvpn"
echo "  /etc/systemd/system/airvpn-helper.socket (enabled)"
echo "  /etc/systemd/system/airvpn-helper.service"
echo "  /var/lib/airvpn-rs/ (latency cache)"
echo ""
echo "Socket status:"
systemctl status --no-pager airvpn-helper.socket || true
