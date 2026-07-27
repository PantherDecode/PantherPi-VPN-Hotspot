#!/bin/bash
# PantherPi uninstaller - run with: sudo bash uninstall.sh
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash uninstall.sh"
  exit 1
fi

echo "Stopping and removing PantherPi service..."
systemctl stop pantherpi 2>/dev/null || true
systemctl disable pantherpi 2>/dev/null || true
rm -f /etc/systemd/system/pantherpi.service
systemctl daemon-reload

echo "Removing /opt/pantherpi..."
rm -rf /opt/pantherpi

read -p "Also remove saved config in /etc/pantherpi (password, hotspot settings, blocklist)? [y/N] " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]]; then
  rm -rf /etc/pantherpi
  echo "Config removed."
else
  echo "Config kept at /etc/pantherpi (a future reinstall will reuse it)."
fi

echo "PantherPi uninstalled."
