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
  echo "[0/9] Running standalone (piped via curl) - fetching source from GitHub..."
  export DEBIAN_FRONTEND=noninteractive
  apt-get update -qq
  apt-get install -y git >/dev/null
  CLONE_DIR="/opt/pantherpi-src"
  rm -rf "$CLONE_DIR"
  git clone --depth 1 "$REPO_URL" "$CLONE_DIR" >/dev/null
  SCRIPT_DIR="$CLONE_DIR"
fi

echo "[1/9] Installing dependencies..."
export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y \
  sudo python3-flask python3-pip hostapd dnsmasq dnsmasq-utils iptables iw curl unzip \
  network-manager openvpn wireguard wireguard-tools avahi-daemon >/dev/null

echo "[2/9] Disabling default auto-start of hostapd/dnsmasq (PantherPi controls them directly)..."
# Raspberry Pi OS Desktop images (unlike Lite) ship hostapd masked by
# default, since NetworkManager wants to own WiFi AP mode itself - a masked
# unit silently refuses every future "systemctl start", with zero log
# output, which looks exactly like a mysteriously-not-starting hotspot.
# Unmask first so PantherPi's own start/stop control actually works.
systemctl unmask hostapd dnsmasq 2>/dev/null || true
systemctl stop hostapd dnsmasq 2>/dev/null || true
systemctl disable hostapd dnsmasq 2>/dev/null || true

echo "[3/9] Fixing NetworkManager DNS handling (prevents /etc/resolv.conf from being"
echo "      emptied when a WiFi radio goes dormant, which breaks DNS for hotspot clients too)..."
mkdir -p /etc/NetworkManager/conf.d
cat > /etc/NetworkManager/conf.d/pantherpi-dns.conf <<'EOF'
[main]
dns=none
EOF
systemctl restart NetworkManager 2>/dev/null || true
sleep 1
# write AFTER the restart, then lock it immutable - some NetworkManager
# versions regenerate an EMPTY resolv.conf on restart even with dns=none
# set, silently undoing a static file written beforehand (found live on a
# fresh Raspberry Pi OS Desktop install - restarting NM wiped the static
# nameservers written just before it, breaking all DNS including apt/pip)
chattr -i /etc/resolv.conf 2>/dev/null || true
cat > /etc/resolv.conf <<'EOF'
nameserver 1.1.1.1
nameserver 8.8.8.8
EOF
chattr +i /etc/resolv.conf 2>/dev/null || true

echo "[4/9] Setting hostname to pantherpi (reachable at http://pantherpi.local/ via mDNS)..."
hostnamectl set-hostname pantherpi
if grep -q '^127\.0\.1\.1' /etc/hosts; then
  sed -i 's/^127\.0\.1\.1.*/127.0.1.1\tpantherpi/' /etc/hosts
else
  echo -e "127.0.1.1\tpantherpi" >> /etc/hosts
fi
systemctl restart avahi-daemon 2>/dev/null || true

echo "[5/9] Installing PantherPi to /opt/pantherpi..."
rm -rf /opt/pantherpi
mkdir -p /opt/pantherpi
cp -r "$SCRIPT_DIR/app.py" "$SCRIPT_DIR/templates" "$SCRIPT_DIR/static" /opt/pantherpi/

echo "[6/9] Setting up config directory (/etc/pantherpi)..."
mkdir -p /etc/pantherpi

echo "[7/9] Installing VPN CLIs (NordVPN, ProtonVPN) and bundled free ProtonVPN servers..."
# Best-effort - these are convenience installs, not required for PantherPi
# itself to run, so a failure here (e.g. no internet yet) shouldn't abort
# the whole install.
curl -sSf https://downloads.nordcdn.com/apps/linux/install.sh 2>/dev/null | sh -s -- -y >/dev/null 2>&1 || \
  echo "  NordVPN CLI install failed/skipped - you can install it later, see README."
pip3 install --break-system-packages --quiet protonvpn-cli 2>/dev/null || \
  echo "  ProtonVPN CLI install failed/skipped - you can install it later, see README."
if [ -d "$SCRIPT_DIR/proton-free-servers" ]; then
  mkdir -p /etc/openvpn/protonvpn/configs
  cp "$SCRIPT_DIR"/proton-free-servers/*.ovpn /etc/openvpn/protonvpn/configs/ 2>/dev/null || true
fi

echo "[8/9] Installing systemd service..."
cp "$SCRIPT_DIR/pantherpi.service" /etc/systemd/system/pantherpi.service
systemctl daemon-reload
systemctl enable pantherpi >/dev/null

echo "[9/9] Starting PantherPi..."
systemctl restart pantherpi
sleep 2

if systemctl is-active --quiet pantherpi; then
  IP=$(hostname -I | awk '{print $1}')
  echo ""
  echo "===================================="
  echo " PantherPi is running!"
  echo "===================================="
  echo " Open:     http://$IP/  (or http://pantherpi.local/ on the same network)"
  echo " Login:    admin / admin"
  echo ""
  echo " IMPORTANT: change the default password now,"
  echo " under the Settings tab in the web UI."
  echo ""
  echo " The hotspot is already broadcasting on wlan0 (SSID: PantherPi)"
  echo " with eth0 as the internet uplink - go to the Hotspot tab to"
  echo " change the SSID/password/interfaces to your own. Whatever"
  echo " state you leave it in is remembered across reboots."
  echo ""
  echo " NordVPN and ProtonVPN CLIs were installed automatically - log in"
  echo " to NordVPN from the VPN tab (browser login), or run"
  echo " 'sudo protonvpn init' via SSH once for ProtonVPN. A set of free"
  echo " ProtonVPN OpenVPN servers is already available with no login"
  echo " needed, under VPN > ProtonVPN - Manual (OpenVPN)."
  echo "===================================="
else
  echo ""
  echo "Something went wrong - PantherPi did not start."
  echo "Check details with: sudo systemctl status pantherpi"
  echo "                     sudo journalctl -u pantherpi -n 50"
  exit 1
fi
