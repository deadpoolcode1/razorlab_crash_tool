#!/bin/bash
#
# install.sh - Install crash-logger as a systemd service
#

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
INSTALL_PATH="/usr/local/bin/crash-logger.sh"
SERVICE_PATH="/etc/systemd/system/crash-logger.service"

echo "Crash Logger Installer"
echo "======================"

# Check root
if [[ $EUID -ne 0 ]]; then
    echo "Error: Must run as root (sudo $0)"
    exit 1
fi

# Install script
echo "[1/4] Installing crash-logger.sh to $INSTALL_PATH..."
cp "$SCRIPT_DIR/crash-logger.sh" "$INSTALL_PATH"
chmod +x "$INSTALL_PATH"

# Install service
echo "[2/4] Installing systemd service..."
cp "$SCRIPT_DIR/crash-logger.service" "$SERVICE_PATH"
chmod 644 "$SERVICE_PATH"

# Reload systemd
echo "[3/4] Reloading systemd..."
systemctl daemon-reload

# Enable and start
echo "[4/4] Enabling and starting service..."
systemctl enable crash-logger.service
systemctl start crash-logger.service

echo ""
echo "Installation complete!"
echo ""
echo "Commands:"
echo "  systemctl status crash-logger    # Check status"
echo "  systemctl stop crash-logger      # Stop service"
echo "  systemctl start crash-logger     # Start service"
echo "  journalctl -u crash-logger -f    # Follow service logs"
echo "  crash-logger.sh status           # Show log status"
echo "  crash-logger.sh check            # Analyze for crashes"
echo ""
echo "Logs location: /var/log/crash-logger/"
echo ""
echo "Optional: Add alias for convenience:"
echo "  echo 'alias crash-logger=\"sudo /usr/local/bin/crash-logger.sh\"' >> ~/.bashrc"
