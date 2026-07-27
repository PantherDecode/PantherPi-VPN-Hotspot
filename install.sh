#!/bin/bash
# PantherPi installer
#
#   One-liner:  curl -sSL https://raw.githubusercontent.com/PantherDecode/PantherPi-VPN-Hotspot/main/install.sh | sudo bash
#   Or:         git clone https://github.com/PantherDecode/PantherPi-VPN-Hotspot.git
#               cd PantherPi-VPN-Hotspot && sudo bash install.sh
set -e

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root: sudo bash install.sh"
  exit 1
fi

REPO_URL="https://github.com/PantherDecode/PantherPi-VPN-Hotspot.git"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" 2>/dev/null && pwd || true)"

echo "===================================="
echo " PantherPi Installer"
echo "===================================="

if [ -z "$SCRIPT_DIR" ] || [ ! -f "$SCRIPT_DIR/app.py" ]; then
  echo "[0/7] Running standalone (piped via curl) - fetching source from GitHub..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y git >/dev/null
  CLONE_DIR="/opt/pantherpi-src"
  rm -rf "$CLONE_DIR"
  git clone --depth 1 "$REPO_URL" "$CLONE_DIR" >/dev/null
  SCRIPT_DIR="$CLONE_DIR"
fi

echo "[1/7] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
  sudo python3-flask hostapd dnsmasq dnsmasq-utils iptables iw curl unzip \
  network-manager openvpn wireguard wireguard-tools >/dev/null

echo "[2/7] Disabling default auto-start of hostapd/dnsmasq (PantherPi controls them directly)..."
systemctl stop hostapd dnsmasq 2>/dev/null || true
systemctl disable hostapd dnsmasq 2>/dev/null || true

echo "[3/7] Fixing NetworkManager DNS handling (prevents /etc/resolv.conf from being"
echo "      emptied when a WiFi radio goes dormant, which breaks DNS for hotspot clients too)..."
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/pantherpi-dns.conf <<'EOF'
[main]
dns=none
EOF
if [ ! -s /etc/resolv.conf ] || ! grep -q '^nameserver' /etc/resolv.conf; then
  cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
fi
systemctl restart NetworkManager 2>/dev/null || true

echo "[4/7] Installing PantherPi to /opt/pantherpi..."
rm -rf /opt/pantherpi
mkdir -p /opt/pantherpi
cp -r "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/templates" "$SCRIPT_DIR/static" /opt/pantherpi/

echo "[5/7] Setting up config directory (/etc/pantherpi)..."
mkdir -p /etc/pantherpi

echo "[6/7] Installing systemd service..."
cp "$SCRIPT_DIR/pantherpi.service" /etc/systemd/system/pantherpi.service
systemctl daemon-reload
systemctl enable pantherpi >/dev/null

echo "[7/7] Starting PantherPi..."
systemctl restart pantherpi
sleep 2

if systemctl is-active --quiet pantherpi; then
  IP=$(hostname -I | awk '{print $1}')
  echo ""
  echo "===================================="
  echo " PantherPi is running!"
  echo "===================================="
  echo " Open:     http://$IP/"
  echo " Login:    admin / admin"
  echo ""
  echo " IMPORTANT: change the default password now,"
  echo " under the Settings tab in the web UI."
  echo ""
  echo " The hotspot itself is NOT started automatically - go to the"
  echo " Hotspot tab and click START HOTSPOT (this is intentional, so"
  echo " you can always reach this admin GUI over plain WiFi/Ethernet"
  echo " during setup without also broadcasting an AP)."
  echo "===================================="
else
  echo ""
  echo "Something went wrong - PantherPi did not start."
  echo "Check details with: sudo systemctl status pantherpi"
  echo "                     sudo journalctl -u pantherpi -n 50"
  exit 1
fi
