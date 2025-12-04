#!/bin/bash
#
# uninstall.sh - Remove crash-logger service
#

set -e

echo "Crash Logger Uninstaller"
echo "========================"

if [[ $EUID -ne 0 ]]; then
    echo "Error: Must run as root (sudo $0)"
    exit 1
fi

echo "[1/4] Stopping service..."
systemctl stop crash-logger.service 2>/dev/null || true

echo "[2/4] Disabling service..."
systemctl disable crash-logger.service 2>/dev/null || true

echo "[3/4] Removing files..."
rm -f /usr/local/bin/crash-logger.sh
rm -f /etc/systemd/system/crash-logger.service

echo "[4/4] Reloading systemd..."
systemctl daemon-reload

echo ""
echo "Uninstall complete!"
echo ""
echo "Note: Logs are preserved in /var/log/crash-logger/"
echo "To remove logs: sudo rm -rf /var/log/crash-logger"
