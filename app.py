import json
import os
import re
import subprocess
import hashlib
import secrets
import time
import threading
from pathlib import Path
from flask import Flask, render_template, request, jsonify, session, redirect, url_for

APP_NAME = "PantherPi"
CONFIG_PATH = "/etc/pantherpi/config.json"
HOSTAPD_CONF = "/etc/hostapd/hostapd.conf"
DNSMASQ_CONF = "/etc/dnsmasq.d/090_pantherpi.conf"
CAPTIVE_AUTH_FILE = "/etc/pantherpi/captive_portal_clients.json"
CAPTIVE_CHAIN = "PANTHERPI_CAPTIVE"
CAPTIVE_TAG = "pantherpi-captive-portal"
CAPTIVE_DNAT_TAG = "pantherpi-captive-dnat"
CAPTIVE_EXEMPT_PATHS = ("/captive-portal", "/captive-portal/login")

OVPN_DIR = "/etc/openvpn/nordvpn/configs/ovpn_udp"
OVPN_CREDS = "/etc/openvpn/nordvpn/credentials.txt"
OVPN_ARCHIVE_URL = "https://downloads.nordcdn.com/configs/archives/servers/ovpn_udp.zip"
OVPN_LOG = "/tmp/pantherpi_openvpn.log"
OVPN_PID = "/tmp/pantherpi_openvpn.pid"
OVPN_UNIT = "pantherpi-openvpn"

# ProtonVPN's server-list API requires an authenticated access token (no
# public/unauthenticated equivalent to NordVPN's config archive - confirmed
# by testing api.protonvpn.ch/vpn/logicals directly, which returns 401
# without a real login session). So instead of auto-fetching servers, the
# user pastes in .ovpn files they download themselves from their Proton
# account dashboard (Downloads > OpenVPN configuration files), one per
# country/server, each saved under a short label used as its "country code".
PROTON_OVPN_DIR = "/etc/openvpn/protonvpn"
PROTON_OVPN_CONFIGS_DIR = f"{PROTON_OVPN_DIR}/configs"
PROTON_OVPN_CREDS = f"{PROTON_OVPN_DIR}/credentials.txt"
PROTON_OVPN_LOG = "/tmp/pantherpi_protonvpn_openvpn.log"
PROTON_OVPN_UNIT = "pantherpi-protonvpn-openvpn"

# WireGuard is much simpler than the OpenVPN setups above: Debian's
# wireguard-tools package ships a native systemd template unit
# (wg-quick@<name>.service) that brings up a real kernel interface directly
# from a .conf file - no proxy bridging, no manual systemd-run wrapping
# needed. Any provider's WireGuard config works here (Proton, Mullvad,
# self-hosted, etc), not just one vendor.
#
# Multiple saved configs live in a "library" dir, each under a short label.
# Connecting copies the chosen one into the single canonical wg0.conf that
# wg-quick@wg0 actually operates on - keeps the interface name constant
# ("wg0") regardless of how many servers are saved, which matters because
# TUNNEL_IFACE_PREFIXES / dashboard detection key off that name.
WG_DIR = "/etc/wireguard"
WG_LIBRARY_DIR = f"{WG_DIR}/library"
WG_ACTIVE_CONF = f"{WG_DIR}/wg0.conf"
WG_UNIT = "wg-quick@wg0"

COUNTRY_NAMES = {
    "ad": "Andorra", "ae": "United Arab Emirates", "af": "Afghanistan", "al": "Albania",
    "am": "Armenia", "ao": "Angola", "ar": "Argentina", "at": "Austria", "au": "Australia",
    "az": "Azerbaijan", "ba": "Bosnia and Herzegovina", "bb": "Barbados", "bd": "Bangladesh",
    "be": "Belgium", "bf": "Burkina Faso", "bg": "Bulgaria", "bh": "Bahrain", "bj": "Benin",
    "bm": "Bermuda", "bn": "Brunei", "bo": "Bolivia", "br": "Brazil", "bs": "Bahamas",
    "bt": "Bhutan", "bw": "Botswana", "bz": "Belize", "ca": "Canada", "ch": "Switzerland",
    "ci": "Ivory Coast", "cl": "Chile", "cm": "Cameroon", "co": "Colombia", "cr": "Costa Rica",
    "cv": "Cape Verde", "cy": "Cyprus", "cz": "Czech Republic", "de": "Germany", "dk": "Denmark",
    "do": "Dominican Republic", "dz": "Algeria", "ec": "Ecuador", "ee": "Estonia", "eg": "Egypt",
    "es": "Spain", "et": "Ethiopia", "fi": "Finland", "fj": "Fiji", "fr": "France",
    "gd": "Grenada", "ge": "Georgia", "gh": "Ghana", "gl": "Greenland", "gm": "Gambia",
    "gr": "Greece", "gt": "Guatemala", "gu": "Guam", "gy": "Guyana", "hk": "Hong Kong",
    "hn": "Honduras", "hr": "Croatia", "hu": "Hungary", "id": "Indonesia", "ie": "Ireland",
    "il": "Israel", "im": "Isle of Man", "in": "India", "iq": "Iraq", "is": "Iceland",
    "it": "Italy", "je": "Jersey", "jm": "Jamaica", "jo": "Jordan", "jp": "Japan",
    "ke": "Kenya", "kg": "Kyrgyzstan", "kh": "Cambodia", "km": "Comoros", "kr": "South Korea",
    "kw": "Kuwait", "ky": "Cayman Islands", "kz": "Kazakhstan", "la": "Laos", "lb": "Lebanon",
    "lc": "Saint Lucia", "li": "Liechtenstein", "lk": "Sri Lanka", "lr": "Liberia",
    "lt": "Lithuania", "lu": "Luxembourg", "lv": "Latvia", "ly": "Libya", "ma": "Morocco",
    "mc": "Monaco", "md": "Moldova", "me": "Montenegro", "mg": "Madagascar",
    "mk": "North Macedonia", "mm": "Myanmar", "mn": "Mongolia", "mr": "Mauritania",
    "mt": "Malta", "mu": "Mauritius", "mv": "Maldives", "mw": "Malawi", "mx": "Mexico",
    "my": "Malaysia", "mz": "Mozambique", "ng": "Nigeria", "nl": "Netherlands",
    "no": "Norway", "np": "Nepal", "nz": "New Zealand", "pa": "Panama", "pe": "Peru",
    "pg": "Papua New Guinea", "ph": "Philippines", "pk": "Pakistan", "pl": "Poland",
    "pr": "Puerto Rico", "pt": "Portugal", "py": "Paraguay", "qa": "Qatar", "ro": "Romania",
    "rs": "Serbia", "rw": "Rwanda", "sc": "Seychelles", "se": "Sweden", "sg": "Singapore",
    "si": "Slovenia", "sk": "Slovakia", "sl": "Sierra Leone", "sm": "San Marino",
    "sn": "Senegal", "so": "Somalia", "sr": "Suriname", "sv": "El Salvador", "td": "Chad",
    "tg": "Togo", "th": "Thailand", "tj": "Tajikistan", "tn": "Tunisia", "tr": "Turkey",
    "tt": "Trinidad and Tobago", "tw": "Taiwan", "tz": "Tanzania", "ua": "Ukraine",
    "uk": "United Kingdom", "tz": "Tanzania", "us": "United States", "uy": "Uruguay",
    "uz": "Uzbekistan", "ve": "Venezuela", "vn": "Vietnam", "ws": "Samoa", "ye": "Yemen",
    "za": "South Africa", "zm": "Zambia",
}

app = Flask(__name__)


def default_config():
    return {
        "admin_user": "admin",
        "admin_pass_hash": hashlib.sha256(b"admin").hexdigest(),
        "secret_key": secrets.token_hex(16),
        "ap_interface": "wlan0",
        "ap_ssid": "PantherPi",
        "ap_password": "PantherPi123",
        "ap_ip": "10.3.141.1",
        "ap_dhcp_start": "10.3.141.50",
        "ap_dhcp_end": "10.3.141.254",
        "uplink_interface": "eth0",
        "leak_protection": True,
        "blocked_macs": [],
        "ap_channel": 6,
        # secure by default: hotspot clients get zero internet unless a real
        # VPN/proxy tunnel is actually up - never a silent plaintext fallback
        "vpn_kill_switch": True,
        "routing_rules": [],
        "proxy_enabled": False,
        "proxy_type": "http",
        "proxy_host": "",
        "proxy_port": 8080,
        "proxy_username": "",
        "proxy_password": "",
        "proxy_kill_switch": False,
        "wg_connected_code": None,
        "eth_lan_enabled": False,
        "eth_lan_interface": "eth0",
        "eth_lan_ip": "10.4.1.1",
        "eth_lan_dhcp_start": "10.4.1.50",
        "eth_lan_dhcp_end": "10.4.1.254",
        "eth_lan_uplink": "",
        "uplink_auto_failover": True,
        # wlan0 deliberately left out of the default failover list: it's the
        # default AP interface itself, so it can't also serve as a fallback
        # uplink (a radio can't be its own internet source). Add it back
        # manually if you switch the AP onto a different interface (e.g. a
        # USB dongle) and free up wlan0 for uplink duty instead.
        "uplink_priority": ["eth0"],
        "captive_portal_enabled": False,
        "captive_portal_username": "guest",
        "captive_portal_password": "",
        "hotspot_enabled": True,
    }


def load_config():
    if not os.path.exists(CONFIG_PATH):
        cfg = default_config()
        save_config(cfg)
        return cfg
    with open(CONFIG_PATH) as f:
        cfg = json.load(f)
    changed = False
    for k, v in default_config().items():
        if k not in cfg:
            cfg[k] = v
            changed = True
    if changed:
        save_config(cfg)
    return cfg


def save_config(cfg):
    Path(os.path.dirname(CONFIG_PATH)).mkdir(parents=True, exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        json.dump(cfg, f, indent=2)


CFG = load_config()
app.secret_key = CFG["secret_key"]


def run(cmd, timeout=15):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.returncode, r.stdout.strip(), r.stderr.strip()
    except Exception as e:
        return 1, "", str(e)


def is_logged_in():
    return session.get("logged_in") is True


def require_login():
    if not is_logged_in():
        return redirect(url_for("login"))
    return None


# ---------- system / network info ----------

def get_interfaces():
    code, out, _ = run(["ip", "-br", "addr"])
    interfaces = []
    for line in out.splitlines():
        parts = line.split()
        if len(parts) < 2:
            continue
        name = parts[0]
        state = parts[1]
        addrs = [p for p in parts[2:] if "." in p.split("/")[0]]
        if name == "lo":
            continue
        interfaces.append({
            "name": name,
            "state": state,
            "ip": addrs[0].split("/")[0] if addrs else None,
        })
    return interfaces


TUNNEL_IFACE_PREFIXES = ("tun", "nordlynx", "wg", "ppp", "proton", "prox")


def is_tunnel_interface(name):
    return any(name.startswith(p) for p in TUNNEL_IFACE_PREFIXES)


def get_active_tunnel_interface():
    """Returns the name of a currently active VPN tunnel interface (NordVPN's
    NordLynx, plain OpenVPN tun0, WireGuard, ProtonVPN, etc.), or None if no
    VPN is actually tunneling traffic right now.

    Tunnel devices commonly report link state as "UNKNOWN" rather than "UP"
    (point-to-point tun/tap interfaces don't have a real carrier-detect
    concept) even while fully functional - so state alone isn't reliable.
    Having an actual IP address assigned is a much stronger signal here."""
    for iface in get_interfaces():
        if iface["state"] not in ("UP", "UNKNOWN"):
            continue
        if is_tunnel_interface(iface["name"]) and iface["ip"]:
            return iface["name"]
    return None


def get_tunnel_provider_label(tunnel_iface):
    """Best-effort label for which VPN service owns the active tunnel
    interface, so the dashboard can show "NordVPN" / "ProtonVPN" / etc.
    instead of just the bare interface name."""
    if not tunnel_iface:
        return None
    if tunnel_iface.startswith("prox"):
        return "Proxy"
    if tunnel_iface.startswith("nordlynx"):
        return "NordVPN (NordLynx)"
    if tunnel_iface.startswith("proton"):
        return "ProtonVPN"
    if tunnel_iface.startswith("wg"):
        if wg_connected():
            code = load_config().get("wg_connected_code")
            if code:
                return f"WireGuard ({wg_server_name(code)})"
        return "WireGuard"
    if tunnel_iface.startswith("ppp"):
        return "PPP VPN"
    if tunnel_iface.startswith("tun"):
        if ovpn_connected():
            return "NordVPN (OpenVPN)"
        if proton_ovpn_connected():
            return "ProtonVPN (OpenVPN)"
        if nordvpn_installed() and nordvpn_status().get("connected"):
            return "NordVPN"
        if protonvpn_installed() and protonvpn_status().get("connected"):
            return "ProtonVPN"
        return "VPN Tunnel"
    return "VPN Tunnel"


def get_tunnel_ovpn_provider(tunnel_iface):
    """Which manual-OpenVPN backend (Nord vs Proton) owns the currently
    connected tun* interface, so the dashboard's country-switch control
    knows which API to call - both providers use interfaces named tun0."""
    if not tunnel_iface or not tunnel_iface.startswith("tun"):
        return None
    if ovpn_connected():
        return "nord"
    if proton_ovpn_connected():
        return "proton"
    return None


def get_tunnel_carrier_interface():
    """The physical/base interface actually carrying a VPN tunnel's traffic
    to the internet (e.g. wlan0 underneath tun0) - the tunnel's own packets
    are locally-originated traffic from the Pi, so they follow the MAIN
    routing table's default route, same as any other local traffic."""
    code, out, _ = run(["bash", "-c", "ip route show default | head -1"])
    m = re.search(r"dev (\S+)", out)
    return m.group(1) if m else None


def get_active_ssid(iface):
    code, out, _ = run(["nmcli", "-t", "-f", "GENERAL.CONNECTION", "device", "show", iface])
    if ":" in out:
        val = out.split(":", 1)[1].strip()
        if val and val != "--":
            return val
    return None


_external_geo_cache = {"ip": None, "country": None, "ts": 0}


def get_external_geo(force=False):
    now = time.time()
    # Always respect the cooldown, even after a failed lookup - retrying on
    # every request (e.g. every 3s dashboard poll) is what gets this rate-limited
    # by the free geo-IP service in the first place. A manual refresh click
    # bypasses the cooldown via force=True.
    if not force and now - _external_geo_cache["ts"] < 60:
        return _external_geo_cache["ip"], _external_geo_cache["country"]
    code, out, _ = run(["curl", "-s", "--max-time", "4", "http://ip-api.com/json/"])
    ip, country = None, None
    if code == 0 and out:
        try:
            data = json.loads(out)
            if data.get("status") == "success":
                ip = data.get("query")
                country = data.get("country")
        except Exception:
            pass
    # keep the last known-good value on a failed/empty lookup instead of
    # flashing "UNAVAILABLE" on the dashboard for a transient hiccup
    if ip:
        _external_geo_cache["ip"] = ip
        _external_geo_cache["country"] = country
    _external_geo_cache["ts"] = now
    return _external_geo_cache["ip"], _external_geo_cache["country"]


_external_geo_cache_per_iface = {}


def get_external_geo_for_iface(iface, force=False):
    now = time.time()
    entry = _external_geo_cache_per_iface.get(iface, {"ip": None, "country": None, "ts": 0})
    if not force and now - entry["ts"] < 120:
        return entry["ip"], entry["country"]
    code, out, _ = run(["curl", "-s", "--interface", iface, "--max-time", "4", "http://ip-api.com/json/"])
    ip, country = None, None
    if code == 0 and out:
        try:
            data = json.loads(out)
            if data.get("status") == "success":
                ip = data.get("query")
                country = data.get("country")
        except Exception:
            pass
    if ip:
        entry["ip"] = ip
        entry["country"] = country
    entry["ts"] = now
    _external_geo_cache_per_iface[iface] = entry
    return entry["ip"], entry["country"]


def get_wifi_interfaces():
    code, out, _ = run(["nmcli", "-t", "-f", "DEVICE,TYPE", "device"])
    ifaces = []
    for line in out.splitlines():
        if ":" not in line:
            continue
        dev, typ = line.split(":", 1)
        if typ == "wifi":
            ifaces.append(dev)
    return ifaces


def get_cpu_temp():
    code, out, _ = run(["vcgencmd", "measure_temp"])
    m = re.search(r"[\d.]+", out)
    return float(m.group()) if m else None


def get_mem_usage():
    try:
        with open("/proc/meminfo") as f:
            data = f.read()
        total = int(re.search(r"MemTotal:\s+(\d+)", data).group(1))
        avail = int(re.search(r"MemAvailable:\s+(\d+)", data).group(1))
        used_pct = round((total - avail) / total * 100, 1)
        return used_pct
    except Exception:
        return None


def get_dhcp_hostnames():
    hostnames = {}
    code, out, _ = run(["bash", "-c", "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            mac, hostname = parts[1].lower(), parts[3]
            if hostname != "*":
                hostnames[mac] = hostname
    return hostnames


def get_ap_clients(iface):
    code, out, _ = run(["sudo", "iw", "dev", iface, "station", "dump"])
    clients = []
    mac = None
    signal = None
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Station"):
            if mac:
                clients.append({"mac": mac, "signal": signal})
            mac = line.split()[1]
            signal = None
        elif line.startswith("signal:"):
            m = re.search(r"-?\d+", line)
            if m:
                signal = int(m.group())
    if mac:
        clients.append({"mac": mac, "signal": signal})
    hostnames = get_dhcp_hostnames()
    for c in clients:
        c["hostname"] = hostnames.get(c["mac"].lower())
    return clients


def hostapd_active():
    code, out, _ = run(["sudo", "systemctl", "is-active", "hostapd"])
    return out.strip() == "active"


def dnsmasq_active():
    code, out, _ = run(["sudo", "systemctl", "is-active", "dnsmasq"])
    return out.strip() == "active"


def get_ap_capable_interfaces():
    capable = []
    for iface in get_wifi_interfaces():
        code, out, _ = run(["nmcli", "-t", "-f", "GENERAL.DEVICE", "device", "show", iface])
        code2, phy_out, _ = run(["bash", "-c",
            f"sudo iw dev {iface} info | awk '/wiphy/{{print $2}}'"])
        phy_idx = phy_out.strip()
        if not phy_idx:
            continue
        code3, modes_out, _ = run(["bash", "-c",
            f"sudo iw phy phy{phy_idx} info | sed -n '/Supported interface modes/,/^\\tBand/p'"])
        if " * AP" in modes_out:
            capable.append(iface)
    return capable


# ---------- routes ----------

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        user = request.form.get("username", "")
        pw = request.form.get("password", "")
        pw_hash = hashlib.sha256(pw.encode()).hexdigest()
        cfg = load_config()
        if user == cfg["admin_user"] and pw_hash == cfg["admin_pass_hash"]:
            session["logged_in"] = True
            return redirect(url_for("dashboard"))
        error = "Invalid credentials"
    return render_template("login.html", app_name=APP_NAME, error=error)


@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


@app.route("/")
def dashboard():
    r = require_login()
    if r:
        return r
    return render_template("dashboard.html", app_name=APP_NAME)


@app.route("/api/interfaces/external")
def api_interfaces_external():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    force = request.args.get("force") == "1"
    only = request.args.get("iface")
    result = {}
    for iface in get_interfaces():
        if only and iface["name"] != only:
            continue
        ip, country = get_external_geo_for_iface(iface["name"], force=force)
        result[iface["name"]] = {"ip": ip, "country": country}
    return jsonify(result)


@app.route("/api/interfaces/speedtest")
def api_interfaces_speedtest():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    iface = request.args.get("iface")
    if not iface or iface not in [i["name"] for i in get_interfaces()]:
        return jsonify({"ok": False, "error": "unknown interface"}), 400
    # Downloads a fixed-size chunk from Cloudflare's speed-test endpoint bound
    # to this specific interface (same --interface trick used for per-iface
    # external IP lookups) and reads curl's own average-throughput stat -
    # accurate even if the transfer gets cut short by --max-time on a slow link.
    # Kept at 8MB: requests above ~10MB got rejected with 403 in testing
    # (Cloudflare rate/size-limiting bare, unauthenticated curl requests).
    code, out, err = run([
        "curl", "-s", "-o", "/dev/null", "--interface", iface, "--max-time", "15",
        "-w", "%{speed_download} %{http_code}",
        "https://speed.cloudflare.com/__down?bytes=8000000",
    ], timeout=20)
    if code != 0 or not out:
        return jsonify({"ok": False, "error": err or "download failed - interface may have no internet route"})
    try:
        bytes_per_sec, http_code = out.split()
        bytes_per_sec = float(bytes_per_sec)
    except Exception:
        return jsonify({"ok": False, "error": "unexpected response"})
    if http_code != "200" or bytes_per_sec <= 0:
        return jsonify({"ok": False, "error": f"download failed (HTTP {http_code})"})
    mbps = round(bytes_per_sec * 8 / 1_000_000, 2)
    return jsonify({"ok": True, "iface": iface, "mbps": mbps})


@app.route("/api/status")
def api_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    interfaces = get_interfaces()
    wifi_ifaces = set(get_wifi_interfaces())
    for i in interfaces:
        i["network"] = None
        if i["name"] == cfg["ap_interface"] and hostapd_active():
            i["network"] = cfg["ap_ssid"]
            i["role"] = "AP"
        elif i["name"] in wifi_ifaces:
            i["network"] = get_active_ssid(i["name"])
            i["role"] = "CLIENT"
        elif i["name"].startswith("eth"):
            i["role"] = "WIRED"
        else:
            i["role"] = None
    ap_clients = get_ap_clients(cfg["ap_interface"]) if hostapd_active() else []
    blocked = set(m.lower() for m in cfg.get("blocked_macs", []))
    for c in ap_clients:
        c["blocked"] = c["mac"].lower() in blocked
    ext_ip, ext_country = get_external_geo(force=request.args.get("force") == "1")
    tunnel = get_active_tunnel_interface()
    ap_active = hostapd_active()
    vpn_secure = bool(ap_active and tunnel and (cfg.get("vpn_kill_switch") or cfg.get("uplink_interface") == tunnel))
    return jsonify({
        "interfaces": interfaces,
        "hostapd_active": ap_active,
        "dnsmasq_active": dnsmasq_active(),
        "ap_interface": cfg["ap_interface"],
        "ap_ssid": cfg["ap_ssid"],
        "ap_clients": ap_clients,
        "blocked_macs": list(blocked),
        "external_ip": ext_ip,
        "external_country": ext_country,
        "cpu_temp": get_cpu_temp(),
        "mem_usage": get_mem_usage(),
        "tunnel_interface": tunnel,
        "tunnel_carrier": get_tunnel_carrier_interface() if tunnel else None,
        "tunnel_provider": get_tunnel_provider_label(tunnel) if tunnel else None,
        "tunnel_ovpn_provider": get_tunnel_ovpn_provider(tunnel) if tunnel else None,
        "vpn_secure": vpn_secure,
        "uplink_interface": cfg.get("uplink_interface"),
        "vpn_kill_switch": cfg.get("vpn_kill_switch", False),
        "leak_protection": cfg.get("leak_protection", True),
    })


@app.route("/wifi")
def wifi_client():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    ifaces = [i for i in get_wifi_interfaces() if i != cfg["ap_interface"]]
    return render_template("wifi_client.html", app_name=APP_NAME, interfaces=ifaces)


@app.route("/api/wifi/scan")
def api_wifi_scan():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    iface = request.args.get("iface")
    if not iface:
        return jsonify({"error": "iface required"}), 400
    run(["sudo", "nmcli", "device", "wifi", "rescan", "ifname", iface])
    code, out, err = run(["nmcli", "-t", "-f", "IN-USE,SSID,SIGNAL,SECURITY,CHAN", "device", "wifi", "list", "ifname", iface], timeout=20)
    networks = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 5:
            continue
        in_use, ssid, signal, security, chan = parts[0], parts[1], parts[2], parts[3], parts[4]
        if not ssid:
            continue
        networks.append({
            "ssid": ssid,
            "signal": signal,
            "security": security or "Open",
            "channel": chan,
            "in_use": in_use == "*",
        })
    return jsonify({"networks": networks})


@app.route("/api/wifi/connect", methods=["POST"])
def api_wifi_connect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json
    iface = data.get("iface")
    ssid = data.get("ssid")
    password = data.get("password", "")
    if not iface or not ssid:
        return jsonify({"ok": False, "error": "iface and ssid required"}), 400
    cmd = ["sudo", "nmcli", "device", "wifi", "connect", ssid, "ifname", iface]
    if password:
        cmd += ["password", password]
    code, out, err = run(cmd, timeout=30)
    return jsonify({"ok": code == 0, "output": out or err})


@app.route("/api/wifi/disconnect", methods=["POST"])
def api_wifi_disconnect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    iface = (request.json or {}).get("iface")
    if not iface:
        return jsonify({"ok": False, "error": "iface required"}), 400
    code, out, err = run(["sudo", "nmcli", "device", "disconnect", iface], timeout=15)
    return jsonify({"ok": code == 0, "output": out or err})


@app.route("/api/wifi/saved")
def api_wifi_saved():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code, out, _ = run(["nmcli", "-t", "-f", "NAME,TYPE", "connection", "show"])
    saved = []
    for line in out.splitlines():
        parts = line.split(":")
        if len(parts) < 2 or parts[1] != "802-11-wireless":
            continue
        name = parts[0]
        _, ssid_out, _ = run(["nmcli", "-g", "802-11-wireless.ssid", "connection", "show", name])
        _, pw_out, _ = run(["sudo", "nmcli", "-s", "-g", "802-11-wireless-security.psk", "connection", "show", name])
        saved.append({
            "name": name,
            "ssid": ssid_out.strip() or name,
            "password": pw_out.strip(),
        })
    return jsonify({"saved": saved})


@app.route("/api/wifi/forget", methods=["POST"])
def api_wifi_forget():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    name = (request.json or {}).get("name", "").strip()
    if not name:
        return jsonify({"ok": False, "error": "name required"}), 400
    code, out, err = run(["sudo", "nmcli", "connection", "delete", name])
    return jsonify({"ok": code == 0, "output": out or err})


@app.route("/hotspot")
def hotspot():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    all_ifaces = [i["name"] for i in get_interfaces()]
    # only VPN/Proxy tunnel interfaces are offered as an uplink - plain
    # physical interfaces (eth0/wlan0/etc) are never shown here, so the UI
    # can't be used to route hotspot traffic directly through an
    # unencrypted connection. The VPN kill switch already enforces this at
    # the firewall level; this keeps the config itself from ever pointing
    # at one in the first place.
    uplink_choices = [i for i in all_ifaces if i != cfg["ap_interface"] and is_tunnel_interface(i)]
    return render_template(
        "hotspot.html",
        app_name=APP_NAME,
        cfg=cfg,
        ap_capable=get_ap_capable_interfaces(),
        uplink_choices=uplink_choices,
        active=hostapd_active(),
    )


@app.route("/api/hotspot/save", methods=["POST"])
def api_hotspot_save():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json
    if "ap_password" in data and data["ap_password"] and not (8 <= len(data["ap_password"]) <= 63):
        return jsonify({"ok": False, "error": "AP password must be 8-63 characters (WPA2 requirement)"}), 400
    cfg = load_config()
    for key in ["ap_interface", "ap_ssid", "ap_password", "ap_ip", "ap_dhcp_start", "ap_dhcp_end", "uplink_interface"]:
        if key in data and data[key]:
            cfg[key] = data[key]
    if "leak_protection" in data:
        cfg["leak_protection"] = bool(data["leak_protection"])
    if "uplink_auto_failover" in data:
        cfg["uplink_auto_failover"] = bool(data["uplink_auto_failover"])
    save_config(cfg)
    if hostapd_active():
        apply_uplink_routing(cfg)
        apply_leak_protection(cfg)
    return jsonify({"ok": True})


def write_hostapd_conf(cfg):
    content = f"""driver=nl80211
ctrl_interface=/var/run/hostapd
ctrl_interface_group=0
beacon_int=100
auth_algs=1
wpa_key_mgmt=WPA-PSK
ssid={cfg['ap_ssid']}
channel={cfg.get('ap_channel', 6)}
hw_mode=g
ieee80211n=1
ht_capab=[HT20][SHORT-GI-20]
ap_max_inactivity=600
skip_inactivity_poll=1
wpa_passphrase={cfg['ap_password']}
interface={cfg['ap_interface']}
wpa=2
wpa_pairwise=CCMP
country_code=GB
"""
    with open("/tmp/pantherpi_hostapd.conf", "w") as f:
        f.write(content)
    run(["sudo", "cp", "/tmp/pantherpi_hostapd.conf", HOSTAPD_CONF])


MSS_TAG = "pantherpi-mss-clamp"


def apply_mss_clamp(cfg):
    """Fix TCP stalls caused by an MTU black hole somewhere upstream (common
    behind VPN tunnels): clamp TCP MSS on forwarded SYN packets so clients
    never negotiate a segment size larger than the path can actually carry,
    instead of relying on (often broken) ICMP-based PMTU discovery."""
    code, rules_out, _ = run(["sudo", "iptables", "-t", "mangle", "-S", "FORWARD"])
    for line in rules_out.splitlines():
        if MSS_TAG in line:
            del_rule = line.replace("-A FORWARD", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -t mangle -D FORWARD {del_rule}"])
    run(["sudo", "iptables", "-t", "mangle", "-A", "FORWARD",
         "-p", "tcp", "--tcp-flags", "SYN,RST", "SYN",
         "-m", "comment", "--comment", MSS_TAG,
         "-j", "TCPMSS", "--clamp-mss-to-pmtu"])


ROUTE_TABLE = "100"


def get_gateway(iface):
    code, out, _ = run(["bash", "-c", f"ip route show dev {iface} | grep default"])
    m = re.search(r"default via (\S+)", out)
    if m:
        return m.group(1)
    code, out, _ = run(["nmcli", "-g", "IP4.GATEWAY", "device", "show", iface])
    return out.strip() or None


def apply_uplink_routing(cfg):
    """Force forwarded hotspot-client traffic out a specific uplink interface,
    regardless of which interface the main routing table would otherwise pick
    (e.g. eth0 having a lower-metric default route than wlan0).

    Matches by *incoming interface* (iif = the AP interface), not by source IP
    range. Matching by source IP is a trap: the Pi's own AP address (e.g.
    10.3.141.1, which dnsmasq/hostapd use for locally-originated replies) sits
    inside that same /24, so it would also get forced through this table -
    which only has a route to the internet uplink, not back to the local
    hotspot subnet. That misroutes DNS replies etc. out the wrong interface,
    where clients send queries fine but never receive answers. Matching on
    iif only catches traffic actually being forwarded from clients."""
    uplink = cfg["uplink_interface"]
    ap_iface = cfg["ap_interface"]
    subnet = ".".join(cfg["ap_ip"].split(".")[:3]) + ".0/24"

    run(["sudo", "ip", "rule", "del", "from", subnet, "table", ROUTE_TABLE])
    run(["sudo", "ip", "rule", "del", "iif", ap_iface, "table", ROUTE_TABLE])
    run(["sudo", "ip", "route", "flush", "table", ROUTE_TABLE])

    gw = get_gateway(uplink)
    if gw:
        run(["sudo", "ip", "route", "add", "default", "via", gw, "dev", uplink, "table", ROUTE_TABLE])
    else:
        run(["sudo", "ip", "route", "add", "default", "dev", uplink, "table", ROUTE_TABLE])
    run(["sudo", "ip", "rule", "add", "iif", ap_iface, "table", ROUTE_TABLE, "priority", "100"])

    # remove any previously added masquerade rules for this subnet (may point
    # at a different, stale uplink interface), then add a fresh one
    code, rules_out, _ = run(["sudo", "iptables", "-t", "nat", "-S", "POSTROUTING"])
    for line in rules_out.splitlines():
        if f"-s {subnet}" in line and "MASQUERADE" in line:
            del_rule = line.replace("-A POSTROUTING", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -t nat -D POSTROUTING {del_rule}"])
    run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", uplink, "-j", "MASQUERADE"])


def set_default_route_metric(iface, metric):
    """Adjusts an existing default route's metric in the MAIN routing table
    (not the hotspot's dedicated policy table above) - this is what actually
    decides which physical interface the Pi's own locally-generated traffic
    (like a VPN client's connection to its server) goes out of. Lower metric
    wins."""
    code, out, _ = run(["bash", "-c", f"ip route show default dev {iface} | head -1"])
    if not out:
        return
    m = re.search(r"via (\S+)", out)
    if m:
        run(["sudo", "ip", "route", "replace", "default", "via", m.group(1), "dev", iface, "metric", str(metric)])
    else:
        run(["sudo", "ip", "route", "replace", "default", "dev", iface, "metric", str(metric)])


def reconnect_active_manual_tunnel():
    """OpenVPN pins its connection to whatever interface had routing
    priority when it first connected and won't notice a priority change on
    its own - restart it so it re-homes onto the newly-preferred uplink.
    WireGuard is connectionless (plain UDP) and typically re-routes on its
    own, but it's restarted too anyway since it's cheap and removes any
    doubt."""
    if ovpn_connected():
        run(["sudo", "systemctl", "restart", OVPN_UNIT])
    if proton_ovpn_connected():
        run(["sudo", "systemctl", "restart", PROTON_OVPN_UNIT])
    if wg_connected():
        run(["sudo", "systemctl", "restart", WG_UNIT])


_last_failover_uplink = "__unset__"


def apply_uplink_failover(cfg):
    """Automatically prefers interfaces earlier in cfg['uplink_priority']
    (default just eth0) whenever they're up, falling back down the list as
    they drop and back up again automatically when a higher-priority
    interface returns.

    This ONLY affects the Pi's own main routing table (default route
    metrics) - i.e. which physical interface the Pi's own locally-
    originated traffic prefers, which is what a VPN/proxy tunnel client
    needs in order to actually dial out and connect in the first place.
    It deliberately never touches cfg['uplink_interface'] (the hotspot's
    own forwarded-traffic uplink) - that stays whatever was explicitly
    picked on the Hotspot page, which only offers tunnel interfaces. A
    physical interface reconnecting must never silently become the
    hotspot's internet source in the background."""
    global _last_failover_uplink
    if not cfg.get("uplink_auto_failover", True):
        return
    priority = cfg.get("uplink_priority") or ["eth0"]
    chosen = next((iface for iface in priority if is_iface_up(iface)), None)
    if not chosen or chosen == _last_failover_uplink:
        return
    _last_failover_uplink = chosen

    base_metric = 50
    for idx, iface in enumerate(priority):
        if is_iface_up(iface):
            set_default_route_metric(iface, base_metric if iface == chosen else base_metric + 500 + idx)

    reconnect_active_manual_tunnel()


LEAK_TAG = "pantherpi-leak-guard"


def clear_leak_protection():
    code, rules_out, _ = run(["sudo", "iptables", "-S", "FORWARD"])
    for line in rules_out.splitlines():
        if LEAK_TAG in line:
            del_rule = line.replace("-A FORWARD", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -D FORWARD {del_rule}"])


def apply_leak_protection(cfg):
    """Kill-switch: only allow forwarded hotspot traffic to exit via the
    configured uplink interface. If that interface goes down or a different
    interface would otherwise carry the traffic, it's dropped instead of
    silently leaking out another connection (e.g. eth0 when wlan0 was chosen)."""
    clear_leak_protection()
    if not cfg.get("leak_protection", True):
        return
    subnet = ".".join(cfg["ap_ip"].split(".")[:3]) + ".0/24"
    uplink = cfg["uplink_interface"]
    run(["sudo", "iptables", "-I", "FORWARD", "1",
         "-s", subnet, "-o", uplink, "-m", "comment", "--comment", LEAK_TAG, "-j", "ACCEPT"])
    run(["sudo", "iptables", "-I", "FORWARD", "2",
         "-s", subnet, "!", "-o", uplink, "-m", "comment", "--comment", LEAK_TAG, "-j", "DROP"])


VPN_KS_TAG = "pantherpi-vpn-killswitch"


def clear_vpn_kill_switch():
    code, rules_out, _ = run(["sudo", "iptables", "-S", "FORWARD"])
    for line in rules_out.splitlines():
        if VPN_KS_TAG in line:
            del_rule = line.replace("-A FORWARD", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -D FORWARD {del_rule}"])


def apply_vpn_kill_switch(cfg):
    """Hard kill switch: hotspot clients get NO internet at all unless a real
    VPN tunnel is actively up. Unlike leak_protection (which allows a plain
    uplink like eth0/wlan0), this specifically requires a detected tunnel
    interface (NordLynx/tun/wg/ppp) - if none is up, ALL AP-subnet traffic is
    dropped outright, not just traffic that would leak out the wrong iface.
    Inserted ahead of the regular leak-guard rules so it's checked first."""
    clear_vpn_kill_switch()
    if not cfg.get("vpn_kill_switch", False):
        return
    subnet = ".".join(cfg["ap_ip"].split(".")[:3]) + ".0/24"
    tunnel = get_active_tunnel_interface()
    if tunnel:
        run(["sudo", "iptables", "-I", "FORWARD", "1",
             "-s", subnet, "-o", tunnel, "-m", "comment", "--comment", VPN_KS_TAG, "-j", "ACCEPT"])
        run(["sudo", "iptables", "-I", "FORWARD", "2",
             "-s", subnet, "!", "-o", tunnel, "-m", "comment", "--comment", VPN_KS_TAG, "-j", "DROP"])
    else:
        run(["sudo", "iptables", "-I", "FORWARD", "1",
             "-s", subnet, "-m", "comment", "--comment", VPN_KS_TAG, "-j", "DROP"])


ROUTING_TAG_PREFIX = "pantherpi-route-"


def routing_table_id(rule_id):
    # stable across restarts (unlike Python's built-in hash(), which is
    # randomized per-process) so previously-applied `ip rule`/`ip route`
    # entries can always be found again and cleared by table id.
    return 200 + (int(hashlib.md5(rule_id.encode()).hexdigest(), 16) % 50)


def routing_rule_priority(rule_id):
    # Must be LOWER than ROUTE_TABLE's ip-rule priority (apply_uplink_routing
    # uses "100") so a user-defined routing rule always wins over the
    # general uplink policy when both match the same iif - otherwise a rule
    # whose "to" is the AP interface (the single most common case for this
    # feature) gets silently shadowed by the general uplink rule and traffic
    # never actually takes the path the rule promises.
    return 50 + (int(hashlib.md5((rule_id + "-priority").encode()).hexdigest(), 16) % 49)


def get_iface_subnet(iface):
    code, out, _ = run(["bash", "-c", f"ip -o -4 addr show {iface} | awk '{{print $4}}'"])
    lines = [l for l in out.strip().splitlines() if l]
    return lines[0] if lines else None


def is_iface_up(iface):
    # tun/tap-style interfaces often report "UNKNOWN" state while fully
    # functional (see get_active_tunnel_interface) - treat that as up too,
    # as long as it actually has an IP.
    for i in get_interfaces():
        if i["name"] == iface:
            return i["state"] == "UP" or (i["state"] == "UNKNOWN" and bool(i["ip"]))
    return False


def clear_routing_rule(rule):
    rid = rule["id"]
    tag = ROUTING_TAG_PREFIX + rid
    table = routing_table_id(rid)
    run(["sudo", "ip", "rule", "del", "iif", rule["to"], "table", str(table)])
    run(["sudo", "ip", "route", "flush", "table", str(table)])
    for chain, tbl_args in [("FORWARD", []), ]:
        code, out, _ = run(["sudo", "iptables"] + tbl_args + ["-S", chain])
        for line in out.splitlines():
            if tag in line:
                del_rule = line.replace(f"-A {chain}", "", 1).strip()
                run(["bash", "-c", f"sudo iptables -D {chain} {del_rule}"])
    code, out, _ = run(["sudo", "iptables", "-t", "nat", "-S", "POSTROUTING"])
    for line in out.splitlines():
        if tag in line:
            del_rule = line.replace("-A POSTROUTING", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -t nat -D POSTROUTING {del_rule}"])


def apply_routing_rule(rule):
    rid = rule["id"]
    tag = ROUTING_TAG_PREFIX + rid
    clear_routing_rule(rule)
    if not rule.get("enabled", True):
        if rid == PROXY_ROUTE_RULE_ID:
            clear_proxy_udp_reject()
        return {"ok": False, "reason": "disabled"}

    from_iface = rule["from"]
    to_iface = rule["to"]
    table = routing_table_id(rid)
    subnet = get_iface_subnet(to_iface)
    if not subnet:
        return {"ok": False, "reason": f"{to_iface} has no IP/subnet of its own - configure one first"}

    from_up = is_iface_up(from_iface)

    if from_up:
        gw = get_gateway(from_iface)
        run(["sudo", "ip", "route", "flush", "table", str(table)])
        if gw:
            run(["sudo", "ip", "route", "add", "default", "via", gw, "dev", from_iface, "table", str(table)])
        else:
            run(["sudo", "ip", "route", "add", "default", "dev", from_iface, "table", str(table)])
        run(["sudo", "ip", "rule", "add", "iif", to_iface, "table", str(table), "priority", str(routing_rule_priority(rid))])
        run(["sudo", "iptables", "-t", "nat", "-A", "POSTROUTING", "-s", subnet, "-o", from_iface,
             "-m", "comment", "--comment", tag, "-j", "MASQUERADE"])

    if rule.get("kill_switch", True):
        if from_up:
            run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", subnet, "-o", from_iface,
                 "-m", "comment", "--comment", tag, "-j", "ACCEPT"])
            run(["sudo", "iptables", "-I", "FORWARD", "2", "-s", subnet, "!", "-o", from_iface,
                 "-m", "comment", "--comment", tag, "-j", "DROP"])
        else:
            run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", subnet,
                 "-m", "comment", "--comment", tag, "-j", "DROP"])
    elif from_up:
        run(["sudo", "iptables", "-A", "FORWARD", "-s", subnet, "-o", from_iface,
             "-m", "comment", "--comment", tag, "-j", "ACCEPT"])

    if rid == PROXY_ROUTE_RULE_ID:
        # must run AFTER the ACCEPT/DROP rules above so the UDP-reject rule
        # ends up ABOVE them in the FORWARD chain (both use -I FORWARD 1)
        proxy_cfg = load_config()
        apply_proxy_udp_reject(proxy_cfg) if proxy_cfg.get("proxy_enabled") else clear_proxy_udp_reject()

    return {"ok": from_up, "reason": None if from_up else f"{from_iface} is down - kill switch blocking" if rule.get("kill_switch", True) else f"{from_iface} is down"}


_routing_rule_last_from_up = {}


def reconcile_routing_rules(cfg):
    """Reactively re-applies routing rules ONLY when a rule's FROM interface
    has actually gone up or down since the last check. This is meant to be
    called periodically by the watcher thread. Calling apply_routing_rule
    unconditionally on every tick (as this used to) tears down and rebuilds
    the ip rule/route/iptables state every single time even when nothing
    changed, which briefly interrupts any in-flight connection riding that
    rule - noticeable on higher-latency paths, where it looked like the
    route was just broken rather than being churned every 10s for no
    reason."""
    for rule in cfg.get("routing_rules", []):
        if not rule.get("enabled", True):
            continue
        rid = rule["id"]
        now_up = is_iface_up(rule["from"])
        if _routing_rule_last_from_up.get(rid) != now_up:
            _routing_rule_last_from_up[rid] = now_up
            apply_routing_rule(rule)


def apply_all_routing_rules(cfg):
    """Unconditional apply - used right after a rule is added/edited/deleted,
    or when the hotspot (re)starts, where a fresh apply is actually wanted."""
    results = {}
    for rule in cfg.get("routing_rules", []):
        results[rule["id"]] = apply_routing_rule(rule)
        _routing_rule_last_from_up[rule["id"]] = is_iface_up(rule["from"])
    return results


def clear_all_routing_rules(cfg):
    for rule in cfg.get("routing_rules", []):
        clear_routing_rule(rule)


# ---------- Proxy (real "prox0" tunnel interface, routed like any other VPN) ----------
#
# Same approach as WireGuard/the removed Tor experiment: a genuine TUN
# device (via tun2socks bridging it to the configured HTTP/SOCKS5 proxy),
# not a NAT redirect trick. Plugs directly into the generalized Routing
# engine (proxy0 -> wlan1, with its own kill switch) instead of needing
# bespoke iptables plumbing.

TUN2SOCKS_BIN = "/opt/pantherpi/bin/tun2socks"
TUN2SOCKS_ARCH_ASSETS = {
    "armhf": "linux-armv7",
    "arm64": "linux-arm64",
    "amd64": "linux-amd64",
    "i386": "linux-386",
}

PROXY_IFACE = "prox0"
PROXY_TUN2SOCKS_CONF = "/etc/pantherpi/tun2socks-proxy.yaml"
PROXY_TUN2SOCKS_UNIT = "pantherpi-prox0"
PROXY_ROUTE_RULE_ID = "proxy-auto"
PROXY_UDP_REJECT_TAG = "pantherpi-proxy-udp-reject"


def tun2socks_installed():
    return os.path.exists(TUN2SOCKS_BIN)


def install_tun2socks():
    code, arch, _ = run(["dpkg", "--print-architecture"])
    asset = TUN2SOCKS_ARCH_ASSETS.get(arch.strip())
    if not asset:
        return False, f"unsupported architecture: {arch}"
    url = f"https://github.com/xjasonlyu/tun2socks/releases/latest/download/tun2socks-{asset}.zip"
    run(["sudo", "mkdir", "-p", "/opt/pantherpi/bin"])
    code, out, err = run(
        ["bash", "-c",
         f"curl -sL --max-time 30 -o /tmp/pantherpi_tun2socks.zip '{url}' && "
         f"cd /tmp && unzip -o pantherpi_tun2socks.zip -d pantherpi_tun2socks_extracted && "
         f"sudo mv pantherpi_tun2socks_extracted/tun2socks-{asset} {TUN2SOCKS_BIN} && "
         f"sudo chmod +x {TUN2SOCKS_BIN} && "
         f"rm -rf /tmp/pantherpi_tun2socks.zip /tmp/pantherpi_tun2socks_extracted"],
        timeout=60,
    )
    return (code == 0 and tun2socks_installed()), (out + "\n" + err).strip()


def test_proxy_connection(proxy_type, host, port, username, password):
    auth = f"{username}:{password}@" if username else ""
    scheme = "socks5h" if proxy_type == "socks5" else "http"
    proxy_url = f"{scheme}://{auth}{host}:{port}"
    code, out, err = run([
        "curl", "-x", proxy_url, "-s", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "8", "http://ip-api.com/json/",
    ], timeout=12)
    ok = code == 0 and out.strip() in ("200",)
    return ok, out or err or "no response"


def write_proxy_tun2socks_conf(cfg):
    scheme = "socks5" if cfg.get("proxy_type") == "socks5" else "http"
    auth = f"{cfg.get('proxy_username')}:{cfg.get('proxy_password')}@" if cfg.get("proxy_username") else ""
    proxy_url = f"{scheme}://{auth}{cfg.get('proxy_host')}:{cfg.get('proxy_port')}"
    content = f"""device: tun://{PROXY_IFACE}
proxy: {proxy_url}
loglevel: info
tun-post-up: sh -c "ip addr add 198.18.2.1/15 dev {PROXY_IFACE} && ip link set {PROXY_IFACE} up"
"""
    Path(os.path.dirname(PROXY_TUN2SOCKS_CONF)).mkdir(parents=True, exist_ok=True)
    with open("/tmp/pantherpi_tun2socks_proxy.yaml", "w") as f:
        f.write(content)
    run(["sudo", "cp", "/tmp/pantherpi_tun2socks_proxy.yaml", PROXY_TUN2SOCKS_CONF])


def restart_proxy_tun2socks():
    run(["sudo", "systemctl", "stop", PROXY_TUN2SOCKS_UNIT])
    time.sleep(1)
    run(["sudo", "systemd-run", f"--unit={PROXY_TUN2SOCKS_UNIT}", "--collect",
         "--", TUN2SOCKS_BIN, "--config", PROXY_TUN2SOCKS_CONF])
    time.sleep(2)


def stop_proxy_tun2socks():
    run(["sudo", "systemctl", "stop", PROXY_TUN2SOCKS_UNIT])


def upsert_proxy_routing_rule(cfg):
    rules = cfg.setdefault("routing_rules", [])
    rule = next((r for r in rules if r["id"] == PROXY_ROUTE_RULE_ID), None)
    if not rule:
        rule = {"id": PROXY_ROUTE_RULE_ID, "from": PROXY_IFACE,
                 "to": cfg["ap_interface"], "kill_switch": True, "enabled": True}
        rules.append(rule)
    rule["from"] = PROXY_IFACE
    rule["to"] = cfg["ap_interface"]
    rule["kill_switch"] = bool(cfg.get("proxy_kill_switch", False))
    rule["enabled"] = True
    save_config(cfg)
    return rule


def remove_proxy_routing_rule(cfg):
    rules = cfg.get("routing_rules", [])
    rule = next((r for r in rules if r["id"] == PROXY_ROUTE_RULE_ID), None)
    if rule:
        clear_routing_rule(rule)
        cfg["routing_rules"] = [r for r in rules if r["id"] != PROXY_ROUTE_RULE_ID]
        save_config(cfg)


def clear_proxy_udp_reject():
    code, out, _ = run(["sudo", "iptables", "-S", "FORWARD"])
    for line in out.splitlines():
        if PROXY_UDP_REJECT_TAG in line:
            del_rule = line.replace("-A FORWARD", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -D FORWARD {del_rule}"])


def apply_proxy_udp_reject(cfg):
    """Most HTTP/SOCKS5 proxies can't relay UDP either (HTTP CONNECT never
    can; most SOCKS5 servers don't implement UDP ASSOCIATE) - same fix as
    Tor's tor0: reject UDP instantly instead of letting it hang until the
    client times out, so browsers fall back to plain TCP right away."""
    clear_proxy_udp_reject()
    if not cfg.get("proxy_enabled"):
        return
    subnet = ".".join(cfg["ap_ip"].split(".")[:3]) + ".0/24"
    run(["sudo", "iptables", "-I", "FORWARD", "1",
         "-s", subnet, "-p", "udp", "-m", "comment", "--comment", PROXY_UDP_REJECT_TAG,
         "-j", "REJECT", "--reject-with", "icmp-port-unreachable"])



_last_vpn_ks_tunnel = "__unset__"


def vpn_kill_switch_watcher():
    global _last_vpn_ks_tunnel
    while True:
        try:
            cfg = load_config()
            apply_uplink_failover(cfg)
            if cfg.get("vpn_kill_switch", False) and hostapd_active():
                # only reapply when the tunnel actually changed state, same
                # reasoning as reconcile_routing_rules below - unconditional
                # reapply every tick briefly interrupts live connections
                tunnel_now = get_active_tunnel_interface()
                if tunnel_now != _last_vpn_ks_tunnel:
                    _last_vpn_ks_tunnel = tunnel_now
                    apply_vpn_kill_switch(cfg)
            if cfg.get("routing_rules"):
                reconcile_routing_rules(cfg)
        except Exception:
            pass
        time.sleep(10)


BLOCK_TAG = "pantherpi-client-block"


def apply_client_blocks(cfg):
    code, rules_out, _ = run(["sudo", "iptables", "-S", "FORWARD"])
    for line in rules_out.splitlines():
        if BLOCK_TAG in line:
            del_rule = line.replace("-A FORWARD", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -D FORWARD {del_rule}"])
    for mac in cfg.get("blocked_macs", []):
        run(["sudo", "iptables", "-I", "FORWARD", "1",
             "-m", "mac", "--mac-source", mac,
             "-m", "comment", "--comment", BLOCK_TAG, "-j", "DROP"])


def load_captive_clients():
    if not os.path.exists(CAPTIVE_AUTH_FILE):
        return []
    try:
        with open(CAPTIVE_AUTH_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def save_captive_clients(macs):
    Path(os.path.dirname(CAPTIVE_AUTH_FILE)).mkdir(parents=True, exist_ok=True)
    with open(CAPTIVE_AUTH_FILE, "w") as f:
        json.dump(macs, f)


def get_mac_for_ip(ip):
    code, out, _ = run(["bash", "-c", "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true"])
    for line in out.splitlines():
        parts = line.split()
        if len(parts) >= 3 and parts[2] == ip:
            return parts[1].lower()
    return None


def is_captive_authenticated(mac):
    if not mac:
        return False
    return mac.lower() in [m.lower() for m in load_captive_clients()]


def clear_captive_portal_rules():
    run(["sudo", "iptables", "-F", CAPTIVE_CHAIN])
    code, out, _ = run(["sudo", "iptables", "-S", "FORWARD"])
    for line in out.splitlines():
        if CAPTIVE_TAG in line:
            del_rule = line.replace("-A FORWARD", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -D FORWARD {del_rule}"])
    code, out, _ = run(["sudo", "iptables", "-t", "nat", "-S", "PREROUTING"])
    for line in out.splitlines():
        if CAPTIVE_DNAT_TAG in line:
            del_rule = line.replace("-A PREROUTING", "", 1).strip()
            run(["bash", "-c", f"sudo iptables -t nat -D PREROUTING {del_rule}"])


def apply_captive_portal_rules(cfg):
    """Guests must authenticate against the captive-portal credentials before
    any forwarded traffic passes. Authenticated MACs RETURN out of the
    CAPTIVE_CHAIN jump and fall through to the normal leak-protection/
    vpn-kill-switch/routing-rule checks below - they aren't blanket-ACCEPTed,
    so those other security layers still apply to them same as anyone else.
    Unauthenticated HTTP requests to ANY destination get DNAT'd to this box's
    own portal page so the OS's captive-portal detection pops the sign-in
    prompt; everything else is rejected outright."""
    clear_captive_portal_rules()
    if not cfg.get("captive_portal_enabled"):
        return
    ap_iface = cfg["ap_interface"]
    ap_ip = cfg["ap_ip"]
    subnet = ".".join(ap_ip.split(".")[:3]) + ".0/24"
    macs = load_captive_clients()

    run(["sudo", "iptables", "-N", CAPTIVE_CHAIN])
    for mac in macs:
        run(["sudo", "iptables", "-A", CAPTIVE_CHAIN, "-m", "mac", "--mac-source", mac, "-j", "RETURN"])
    run(["sudo", "iptables", "-A", CAPTIVE_CHAIN, "-j", "REJECT", "--reject-with", "icmp-port-unreachable"])
    run(["sudo", "iptables", "-I", "FORWARD", "1", "-s", subnet,
         "-m", "comment", "--comment", CAPTIVE_TAG, "-j", CAPTIVE_CHAIN])

    for mac in macs:
        run(["sudo", "iptables", "-t", "nat", "-I", "PREROUTING", "1", "-i", ap_iface,
             "-m", "mac", "--mac-source", mac,
             "-m", "comment", "--comment", CAPTIVE_DNAT_TAG, "-j", "RETURN"])
    run(["sudo", "iptables", "-t", "nat", "-A", "PREROUTING", "-i", ap_iface, "-p", "tcp", "--dport", "80",
         "-m", "comment", "--comment", CAPTIVE_DNAT_TAG, "-j", "DNAT", "--to-destination", f"{ap_ip}:80"])


@app.before_request
def captive_portal_gate():
    if request.path.startswith("/static/") or request.path in CAPTIVE_EXEMPT_PATHS:
        return None
    cfg = load_config()
    if not cfg.get("captive_portal_enabled"):
        return None
    subnet_prefix = ".".join(cfg.get("ap_ip", "").split(".")[:3])
    remote = request.remote_addr or ""
    if not subnet_prefix or not remote.startswith(subnet_prefix + "."):
        return None
    mac = get_mac_for_ip(remote)
    if is_captive_authenticated(mac):
        return None
    ip, country = get_external_geo()
    return render_template("captive_portal.html", app_name=APP_NAME, error=None,
                            ext_ip=ip, ext_country=country or "Unknown")


def write_dnsmasq_conf(cfg):
    subnet_prefix = ".".join(cfg["ap_ip"].split(".")[:3])
    content = f"""interface={cfg['ap_interface']}
domain-needed
dhcp-range={cfg['ap_dhcp_start']},{cfg['ap_dhcp_end']},255.255.255.0,12h
"""
    with open("/tmp/pantherpi_dnsmasq.conf", "w") as f:
        f.write(content)
    run(["sudo", "cp", "/tmp/pantherpi_dnsmasq.conf", DNSMASQ_CONF])


def start_hotspot(cfg):
    iface = cfg["ap_interface"]

    run(["sudo", "systemctl", "stop", "hostapd"])
    run(["sudo", "systemctl", "stop", "dnsmasq"])
    run(["sudo", "nmcli", "device", "set", iface, "managed", "no"])
    write_hostapd_conf(cfg)
    write_dnsmasq_conf(cfg)

    # hostapd's nl80211 AP-mode init resets the interface, so bring it up
    # and let hostapd fully enable AP mode BEFORE assigning the static IP -
    # otherwise hostapd's init wipes the address we just set.
    run(["sudo", "systemctl", "start", "hostapd"])
    for _ in range(10):
        time.sleep(0.5)
        if hostapd_active():
            break

    run(["sudo", "ip", "addr", "flush", "dev", iface])
    run(["sudo", "ip", "addr", "add", f"{cfg['ap_ip']}/24", "dev", iface])
    run(["sudo", "ip", "link", "set", iface, "up"])

    run(["sudo", "systemctl", "start", "dnsmasq"])

    run(["bash", "-c", "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"])
    apply_uplink_routing(cfg)
    apply_leak_protection(cfg)
    apply_vpn_kill_switch(cfg)
    apply_client_blocks(cfg)
    apply_mss_clamp(cfg)
    if cfg.get("routing_rules"):
        apply_all_routing_rules(cfg)
    apply_captive_portal_rules(cfg)


def stop_hotspot(cfg):
    run(["sudo", "systemctl", "stop", "hostapd"])
    run(["sudo", "systemctl", "stop", "dnsmasq"])
    run(["sudo", "nmcli", "device", "set", cfg["ap_interface"], "managed", "yes"])
    clear_leak_protection()
    clear_vpn_kill_switch()
    clear_captive_portal_rules()


@app.route("/api/hotspot/start", methods=["POST"])
def api_hotspot_start():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    start_hotspot(cfg)
    cfg["hotspot_enabled"] = True
    save_config(cfg)

    iface = cfg["ap_interface"]
    code, ip_out, _ = run(["bash", "-c", f"ip -br addr show {iface}"])
    return jsonify({
        "ok": hostapd_active() and (f"{cfg['ap_ip']}" in ip_out),
        "hostapd_active": hostapd_active(),
        "dnsmasq_active": dnsmasq_active(),
        "ap_iface_state": ip_out,
    })


@app.route("/api/hotspot/stop", methods=["POST"])
def api_hotspot_stop():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    stop_hotspot(cfg)
    cfg["hotspot_enabled"] = False
    save_config(cfg)
    return jsonify({"ok": True})


@app.route("/api/client/block", methods=["POST"])
def api_client_block():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mac = (request.json or {}).get("mac", "").strip().lower()
    if not mac:
        return jsonify({"ok": False, "error": "mac required"}), 400
    cfg = load_config()
    if mac not in [m.lower() for m in cfg.get("blocked_macs", [])]:
        cfg.setdefault("blocked_macs", []).append(mac)
        save_config(cfg)
    if hostapd_active():
        apply_client_blocks(cfg)
        run(["sudo", "hostapd_cli", "-i", cfg["ap_interface"], "deauthenticate", mac])
    return jsonify({"ok": True})


@app.route("/api/client/unblock", methods=["POST"])
def api_client_unblock():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mac = (request.json or {}).get("mac", "").strip().lower()
    cfg = load_config()
    cfg["blocked_macs"] = [m for m in cfg.get("blocked_macs", []) if m.lower() != mac]
    save_config(cfg)
    if hostapd_active():
        apply_client_blocks(cfg)
    return jsonify({"ok": True})


@app.route("/firewall")
def firewall():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    return render_template(
        "firewall.html", app_name=APP_NAME, cfg=cfg, active=hostapd_active(),
        tunnel=get_active_tunnel_interface(),
    )


@app.route("/api/firewall/save", methods=["POST"])
def api_firewall_save():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    cfg = load_config()
    cfg["leak_protection"] = bool(data.get("leak_protection", True))
    cfg["vpn_kill_switch"] = bool(data.get("vpn_kill_switch", False))
    save_config(cfg)
    if hostapd_active():
        apply_leak_protection(cfg)
        apply_vpn_kill_switch(cfg)
    return jsonify({"ok": True})


@app.route("/proxy")
def proxy_page():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    return render_template("proxy.html", app_name=APP_NAME, cfg=cfg)


@app.route("/api/proxy/status")
def api_proxy_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    rule = next((r for r in cfg.get("routing_rules", []) if r["id"] == PROXY_ROUTE_RULE_ID), None)
    return jsonify({
        "tun2socks_installed": tun2socks_installed(),
        "prox0_up": is_iface_up(PROXY_IFACE),
        "route_applied": bool(rule and rule.get("enabled")),
        "enabled": cfg.get("proxy_enabled", False),
        "kill_switch": cfg.get("proxy_kill_switch", False),
        "type": cfg.get("proxy_type", "http"),
        "host": cfg.get("proxy_host", ""),
        "port": cfg.get("proxy_port", 8080),
        "username": cfg.get("proxy_username", ""),
        "password": cfg.get("proxy_password", ""),
        "hostapd_active": hostapd_active(),
    })


@app.route("/api/proxy/test", methods=["POST"])
def api_proxy_test():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    cfg = load_config()
    proxy_type = data.get("type", cfg.get("proxy_type", "http"))
    host = data.get("host", cfg.get("proxy_host", ""))
    port = data.get("port", cfg.get("proxy_port", 8080))
    username = data.get("username", cfg.get("proxy_username", ""))
    password = data.get("password") or cfg.get("proxy_password", "")
    if not host or not port:
        return jsonify({"ok": False, "error": "host and port required"}), 400
    ok, output = test_proxy_connection(proxy_type, host, port, username, password)
    return jsonify({"ok": ok, "output": output})


@app.route("/api/proxy/save", methods=["POST"])
def api_proxy_save():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    cfg = load_config()
    cfg["proxy_type"] = "socks5" if data.get("type") == "socks5" else "http"
    cfg["proxy_host"] = (data.get("host") or "").strip()
    try:
        cfg["proxy_port"] = int(data.get("port") or 8080)
    except (TypeError, ValueError):
        cfg["proxy_port"] = 8080
    cfg["proxy_username"] = (data.get("username") or "").strip()
    if data.get("password"):
        cfg["proxy_password"] = data["password"]
    cfg["proxy_enabled"] = bool(data.get("enabled", False))
    cfg["proxy_kill_switch"] = bool(data.get("kill_switch", False))

    if cfg["proxy_enabled"] and not cfg["proxy_host"]:
        return jsonify({"ok": False, "error": "Proxy host is required to enable the proxy"}), 400

    save_config(cfg)

    install_output = None
    if cfg["proxy_enabled"]:
        if not tun2socks_installed():
            success, install_output = install_tun2socks()
            if not success:
                return jsonify({"ok": False, "error": "Failed to install tun2socks", "output": install_output}), 500
        write_proxy_tun2socks_conf(cfg)
        restart_proxy_tun2socks()
        rule = upsert_proxy_routing_rule(cfg)
        apply_routing_rule(rule)
        apply_proxy_udp_reject(cfg)
    else:
        remove_proxy_routing_rule(cfg)
        stop_proxy_tun2socks()
        clear_proxy_udp_reject()

    return jsonify({"ok": True, "install_output": install_output})


@app.route("/api/proxy/off", methods=["POST"])
def api_proxy_off():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    cfg["proxy_enabled"] = False
    save_config(cfg)
    remove_proxy_routing_rule(cfg)
    stop_proxy_tun2socks()
    clear_proxy_udp_reject()
    return jsonify({"ok": True})


@app.route("/captive-portal")
def captive_portal_page():
    cfg = load_config()
    ip, country = get_external_geo()
    return render_template("captive_portal.html", app_name=APP_NAME, error=None,
                            ext_ip=ip, ext_country=country or "Unknown")


@app.route("/captive-portal/login", methods=["POST"])
def captive_portal_login():
    cfg = load_config()
    user = request.form.get("username", "")
    pw = request.form.get("password", "")
    ip, country = get_external_geo()
    error = None
    success = False
    if user == cfg.get("captive_portal_username") and pw == cfg.get("captive_portal_password"):
        mac = get_mac_for_ip(request.remote_addr)
        if mac:
            macs = load_captive_clients()
            if mac not in macs:
                macs.append(mac)
                save_captive_clients(macs)
            if hostapd_active():
                apply_captive_portal_rules(cfg)
            success = True
        else:
            error = "Could not identify your device - reconnect to the WiFi network and try again."
    else:
        error = "Invalid username or password"
    return render_template("captive_portal.html", app_name=APP_NAME, error=error, success=success,
                            ext_ip=ip, ext_country=country or "Unknown")


@app.route("/captive-portal-settings")
def captive_portal_settings():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    return render_template("captive_portal_settings.html", app_name=APP_NAME, cfg=cfg,
                            clients=load_captive_clients())


@app.route("/api/captive_portal/status")
def api_captive_portal_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    return jsonify({
        "enabled": cfg.get("captive_portal_enabled", False),
        "username": cfg.get("captive_portal_username", ""),
        "password": cfg.get("captive_portal_password", ""),
        "clients": load_captive_clients(),
        "hostapd_active": hostapd_active(),
    })


@app.route("/api/captive_portal/save", methods=["POST"])
def api_captive_portal_save():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    cfg = load_config()
    cfg["captive_portal_enabled"] = bool(data.get("enabled", False))
    username = (data.get("username") or "").strip()
    if username:
        cfg["captive_portal_username"] = username
    if data.get("password"):
        cfg["captive_portal_password"] = data["password"]
    save_config(cfg)
    if hostapd_active():
        apply_captive_portal_rules(cfg)
    return jsonify({"ok": True})


@app.route("/api/captive_portal/revoke", methods=["POST"])
def api_captive_portal_revoke():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    mac = (request.json or {}).get("mac", "").strip().lower()
    macs = [m for m in load_captive_clients() if m.lower() != mac]
    save_captive_clients(macs)
    cfg = load_config()
    if hostapd_active():
        apply_captive_portal_rules(cfg)
    return jsonify({"ok": True})


@app.route("/routing")
def routing():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    return render_template(
        "routing.html", app_name=APP_NAME, cfg=cfg,
        interfaces=[i["name"] for i in get_interfaces()],
    )


@app.route("/api/routing/list")
def api_routing_list():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    rules = cfg.get("routing_rules", [])
    for rule in rules:
        rule["from_up"] = is_iface_up(rule["from"])
        rule["to_up"] = is_iface_up(rule["to"])
    return jsonify({"rules": rules, "interfaces": [i["name"] for i in get_interfaces()]})


@app.route("/api/routing/add", methods=["POST"])
def api_routing_add():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    from_iface = data.get("from", "").strip()
    to_iface = data.get("to", "").strip()
    if not from_iface or not to_iface or from_iface == to_iface:
        return jsonify({"ok": False, "error": "pick two different interfaces"}), 400
    cfg = load_config()
    rule = {
        "id": secrets.token_hex(6),
        "from": from_iface,
        "to": to_iface,
        "kill_switch": bool(data.get("kill_switch", True)),
        "enabled": True,
    }
    cfg.setdefault("routing_rules", []).append(rule)
    save_config(cfg)
    result = apply_routing_rule(rule)
    return jsonify({"ok": True, "rule": rule, "apply_result": result})


@app.route("/api/routing/update", methods=["POST"])
def api_routing_update():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    rid = data.get("id", "")
    cfg = load_config()
    rules = cfg.get("routing_rules", [])
    rule = next((r for r in rules if r["id"] == rid), None)
    if not rule:
        return jsonify({"ok": False, "error": "rule not found"}), 404
    if "enabled" in data:
        rule["enabled"] = bool(data["enabled"])
    if "kill_switch" in data:
        rule["kill_switch"] = bool(data["kill_switch"])
    save_config(cfg)
    result = apply_routing_rule(rule)
    return jsonify({"ok": True, "rule": rule, "apply_result": result})


@app.route("/api/routing/delete", methods=["POST"])
def api_routing_delete():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    rid = (request.json or {}).get("id", "")
    cfg = load_config()
    rules = cfg.get("routing_rules", [])
    rule = next((r for r in rules if r["id"] == rid), None)
    if rule:
        clear_routing_rule(rule)
        cfg["routing_rules"] = [r for r in rules if r["id"] != rid]
        save_config(cfg)
    return jsonify({"ok": True})


@app.route("/api/account/change_password", methods=["POST"])
def api_change_password():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    current = data.get("current_password", "")
    new = data.get("new_password", "")
    cfg = load_config()
    if hashlib.sha256(current.encode()).hexdigest() != cfg["admin_pass_hash"]:
        return jsonify({"ok": False, "error": "Current password is incorrect"}), 400
    if len(new) < 4:
        return jsonify({"ok": False, "error": "New password too short"}), 400
    cfg["admin_pass_hash"] = hashlib.sha256(new.encode()).hexdigest()
    save_config(cfg)
    return jsonify({"ok": True})


def nordvpn_installed():
    code, _, _ = run(["bash", "-c", "which nordvpn"])
    return code == 0


def nordvpn_logged_in():
    code, out, _ = run(["sudo", "nordvpn", "account"], timeout=10)
    return code == 0 and "not logged in" not in out.lower() and "log in" not in out.lower()


NORDVPN_LOGIN_LOG = "/tmp/pantherpi_nordvpn_login.log"


@app.route("/api/vpn/login/start", methods=["POST"])
def api_vpn_login_start():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    # kill any stale attempt from a previous click, then start a fresh one
    # fully detached - NOT wrapped in `timeout`, since that was the bug last
    # time: it killed the process (and the login attempt with it) long before
    # the user finished the OAuth flow in their browser.
    run(["sudo", "pkill", "-9", "-f", "nordvpn login"])
    # `yes n` (not `echo n`) - a single echoed line hits EOF on stdin right
    # after being consumed, which was killing the process early, before the
    # user had a chance to finish the OAuth flow in their browser.
    run(["bash", "-c", f"rm -f {NORDVPN_LOGIN_LOG}; setsid bash -c \"yes n | sudo nordvpn login > {NORDVPN_LOGIN_LOG} 2>&1\" < /dev/null > /dev/null 2>&1 &"])
    time.sleep(3)
    code, out, _ = run(["bash", "-c", f"cat {NORDVPN_LOGIN_LOG} 2>/dev/null"])
    m = re.search(r"(https://\S+)", out)
    url = m.group(1) if m else None
    return jsonify({"ok": True, "url": url, "raw": out})


@app.route("/api/vpn/login/check")
def api_vpn_login_check():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"logged_in": nordvpn_logged_in()})


@app.route("/api/vpn/login/token", methods=["POST"])
def api_vpn_login_token():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    token = (request.json or {}).get("token", "").strip()
    if not token:
        return jsonify({"ok": False, "error": "token required"}), 400
    code, out, err = run(["sudo", "nordvpn", "login", "--token", token], timeout=20)
    full = (out or "") + (err or "")
    # never echo the token itself back in any response
    full = full.replace(token, "[hidden]")
    return jsonify({"ok": code == 0 and nordvpn_logged_in(), "output": full})


def nordvpn_status():
    code, out, _ = run(["sudo", "nordvpn", "status"], timeout=10)
    status = {"connected": False, "country": None, "server": None}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith("Status:"):
            status["connected"] = "Connected" in line
        elif line.startswith("Country:"):
            status["country"] = line.split(":", 1)[1].strip()
        elif line.startswith("Hostname:"):
            status["server"] = line.split(":", 1)[1].strip()
    return status


def nordvpn_countries():
    code, out, _ = run(["nordvpn", "countries"], timeout=15)
    if code != 0:
        return []
    names = set()
    for line in out.splitlines():
        line = line.strip()
        if not line or line.startswith("-"):
            continue
        for part in re.split(r"\s{2,}|\t|,", line):
            part = part.strip()
            if part:
                names.add(part)
    return sorted(names)


@app.route("/vpn")
def vpn():
    r = require_login()
    if r:
        return r
    return render_template("vpn.html", app_name=APP_NAME)


@app.route("/api/vpn/status")
def api_vpn_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    if not nordvpn_installed():
        return jsonify({"installed": False})
    logged_in = nordvpn_logged_in()
    if not logged_in:
        return jsonify({"installed": True, "logged_in": False})
    status = nordvpn_status()
    return jsonify({"installed": True, "logged_in": True, **status})


@app.route("/api/vpn/countries")
def api_vpn_countries():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"countries": nordvpn_countries()})


@app.route("/api/vpn/raw_status")
def api_vpn_raw_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code, out, err = run(["sudo", "nordvpn", "status"], timeout=15)
    return jsonify({"ok": code == 0, "output": out or err})


@app.route("/api/vpn/connect", methods=["POST"])
def api_vpn_connect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    country = (request.json or {}).get("country", "").strip()
    cmd = ["sudo", "nordvpn", "connect"]
    if country:
        cmd.append(country)
    code, out, err = run(cmd, timeout=30)
    return jsonify({"ok": code == 0, "output": out or err})


@app.route("/api/vpn/disconnect", methods=["POST"])
def api_vpn_disconnect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code, out, err = run(["sudo", "nordvpn", "disconnect"], timeout=20)
    return jsonify({"ok": code == 0, "output": out or err})


def protonvpn_installed():
    code, _, _ = run(["bash", "-c", "which protonvpn"])
    return code == 0


def protonvpn_logged_in():
    code, out, _ = run(["sudo", "protonvpn", "status"], timeout=10)
    return "no profile initialized" not in out.lower() and "protonvpn init" not in out.lower()


def protonvpn_status():
    code, out, _ = run(["sudo", "protonvpn", "status"], timeout=10)
    status = {"connected": False, "country": None, "server": None}
    for line in out.splitlines():
        line = line.strip()
        low = line.lower()
        if low.startswith("status"):
            status["connected"] = "connected" in low and "disconnected" not in low
        elif low.startswith("server"):
            status["server"] = line.split(":", 1)[1].strip() if ":" in line else None
        elif low.startswith("country"):
            status["country"] = line.split(":", 1)[1].strip() if ":" in line else None
    return status


@app.route("/api/protonvpn/status")
def api_protonvpn_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    if not protonvpn_installed():
        return jsonify({"installed": False})
    logged_in = protonvpn_logged_in()
    if not logged_in:
        return jsonify({"installed": True, "logged_in": False})
    status = protonvpn_status()
    return jsonify({"installed": True, "logged_in": True, **status})


@app.route("/api/protonvpn/connect", methods=["POST"])
def api_protonvpn_connect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    country = (request.json or {}).get("country", "").strip()
    cmd = ["sudo", "protonvpn", "connect"]
    if country:
        cmd += ["--cc", country]
    else:
        cmd += ["--fastest"]
    code, out, err = run(cmd, timeout=30)
    return jsonify({"ok": code == 0, "output": out or err})


@app.route("/api/protonvpn/disconnect", methods=["POST"])
def api_protonvpn_disconnect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code, out, err = run(["sudo", "protonvpn", "disconnect"], timeout=20)
    return jsonify({"ok": code == 0, "output": out or err})


def ovpn_country_name(code):
    if code in COUNTRY_NAMES:
        return COUNTRY_NAMES[code]
    if "-" in code:
        parts = [COUNTRY_NAMES.get(p, p.upper()) for p in code.split("-")]
        return " -> ".join(parts)
    return code.upper()


def ovpn_server_list():
    if not os.path.isdir(OVPN_DIR):
        return {}
    groups = {}
    for fname in os.listdir(OVPN_DIR):
        if not fname.endswith(".ovpn") or fname.endswith("_2.6.ovpn"):
            continue
        m = re.match(r"^([a-z-]+?)(\d+)\.nordvpn\.com\.udp\.ovpn$", fname)
        if not m:
            continue
        code = m.group(1)
        groups.setdefault(code, []).append(fname)
    result = []
    for code, files in groups.items():
        result.append({
            "code": code,
            "name": ovpn_country_name(code),
            "count": len(files),
            "sample": sorted(files)[0],
        })
    result.sort(key=lambda x: x["name"])
    return result


def ovpn_has_credentials():
    return os.path.exists(OVPN_CREDS)


def ovpn_saved_username():
    if not os.path.exists(OVPN_CREDS):
        return None
    try:
        with open(OVPN_CREDS) as f:
            return f.readline().strip() or None
    except Exception:
        return None


def ovpn_saved_password():
    if not os.path.exists(OVPN_CREDS):
        return None
    try:
        with open(OVPN_CREDS) as f:
            lines = f.readlines()
        return lines[1].strip() if len(lines) > 1 else None
    except Exception:
        return None


def ovpn_connected():
    code, out, _ = run(["sudo", "systemctl", "is-active", OVPN_UNIT])
    return out.strip() == "active"


def ovpn_connected_server():
    """Which server config the running openvpn process was actually started
    with, so the UI can show/pre-select it after a switch or page reload."""
    code, out, _ = run(["bash", "-c", "ps -o args= -C openvpn 2>/dev/null | grep -- '--config'"])
    m = re.search(r"--config\s+'?([^\s']+\.ovpn)'?", out)
    if not m:
        return None, None
    fname = os.path.basename(m.group(1))
    m2 = re.match(r"^([a-z-]+?)\d+\.nordvpn\.com\.udp\.ovpn$", fname)
    return (m2.group(1), fname) if m2 else (None, fname)


@app.route("/api/vpn/quick_status")
def api_vpn_quick_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    tunnel = get_active_tunnel_interface()
    # prox0 isn't a VPN - it's tracked separately (see /api/proxy/status) so
    # the VPN and Proxy nav items reflect independent security states
    connected = bool(tunnel and not tunnel.startswith("prox")) or ovpn_connected() or proton_ovpn_connected()
    if not connected and nordvpn_installed():
        connected = nordvpn_status().get("connected", False)
    if not connected and protonvpn_installed():
        connected = protonvpn_status().get("connected", False)
    return jsonify({"connected": connected})


@app.route("/api/vpn/openvpn/servers")
def api_ovpn_servers():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    connected = ovpn_connected()
    connected_code, connected_file = ovpn_connected_server() if connected else (None, None)
    return jsonify({
        "servers": ovpn_server_list(),
        "has_credentials": ovpn_has_credentials(),
        "username": ovpn_saved_username(),
        "password": ovpn_saved_password(),
        "connected": connected,
        "connected_code": connected_code,
        "connected_file": connected_file,
        "configs_installed": os.path.isdir(OVPN_DIR),
    })


@app.route("/api/vpn/openvpn/credentials", methods=["POST"])
def api_ovpn_credentials():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required"}), 400
    Path(os.path.dirname(OVPN_CREDS)).mkdir(parents=True, exist_ok=True)
    with open(OVPN_CREDS, "w") as f:
        f.write(f"{username}\n{password}\n")
    os.chmod(OVPN_CREDS, 0o600)
    return jsonify({"ok": True})


_ovpn_update_state = {"running": False, "downloaded": 0, "total": 0, "done": False, "ok": None, "error": None}


def _run_ovpn_update():
    global _ovpn_update_state
    tmp_path = "/tmp/ovpn_update.zip"
    try:
        run(["sudo", "systemctl", "stop", OVPN_UNIT])
        run(["sudo", "mkdir", "-p", OVPN_DIR])
        _, head_out, _ = run(["curl", "-sI", "--max-time", "15", OVPN_ARCHIVE_URL])
        m = re.search(r"(?i)content-length:\s*(\d+)", head_out)
        if m:
            _ovpn_update_state["total"] = int(m.group(1))
        if os.path.exists(tmp_path):
            os.remove(tmp_path)
        # --speed-time/--speed-limit: abort if throughput drops under
        # 512 B/s for a sustained 30s - distinguishes a genuinely-dead
        # stalled connection (which used to hang for the full timeout,
        # freezing this whole update) from a real transfer that's just slow
        proc = subprocess.Popen([
            "curl", "-s", "--speed-time", "30", "--speed-limit", "512",
            "--retry", "2", "--retry-delay", "3", "-o", tmp_path, OVPN_ARCHIVE_URL,
        ])
        while proc.poll() is None:
            time.sleep(1)
            if os.path.exists(tmp_path):
                _ovpn_update_state["downloaded"] = os.path.getsize(tmp_path)
        if proc.returncode != 0:
            _ovpn_update_state.update({"running": False, "done": True, "ok": False,
                                        "error": "Download failed or stalled - check your internet connection."})
            return
        code, out, err = run(["sudo", "bash", "-c",
            f"unzip -oq {tmp_path} -d /etc/openvpn/nordvpn/configs/ && rm -f {tmp_path}"], timeout=60)
        _ovpn_update_state.update({"running": False, "done": True, "ok": code == 0,
                                    "error": None if code == 0 else (out or err)})
    except Exception as e:
        _ovpn_update_state.update({"running": False, "done": True, "ok": False, "error": str(e)})


@app.route("/api/vpn/openvpn/update", methods=["POST"])
def api_ovpn_update():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    global _ovpn_update_state
    if _ovpn_update_state["running"]:
        return jsonify({"ok": True, "already_running": True})
    _ovpn_update_state = {"running": True, "downloaded": 0, "total": 0, "done": False, "ok": None, "error": None}
    threading.Thread(target=_run_ovpn_update, daemon=True).start()
    return jsonify({"ok": True, "started": True})


@app.route("/api/vpn/openvpn/update/status")
def api_ovpn_update_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    state = dict(_ovpn_update_state)
    if state["done"] and state["ok"]:
        servers = ovpn_server_list()
        state["count"] = sum(s["count"] for s in servers)
    return jsonify(state)


@app.route("/api/vpn/openvpn/connect", methods=["POST"])
def api_ovpn_connect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    if not ovpn_has_credentials():
        return jsonify({"ok": False, "error": "Save your service credentials first"}), 400
    code = (request.json or {}).get("code", "").strip()
    servers = {s["code"]: s for s in ovpn_server_list()}
    if code not in servers:
        return jsonify({"ok": False, "error": "unknown server group"}), 400
    config_path = os.path.join(OVPN_DIR, servers[code]["sample"])
    # Run as its own independent systemd unit (--collect), NOT a detached
    # child of the pantherpi process - a plain `setsid ... &` child still
    # inherits pantherpi.service's cgroup, so `systemctl restart pantherpi`
    # (e.g. every time this app gets updated/redeployed) was silently killing
    # the VPN tunnel along with it. This transient unit is fully independent.
    run(["sudo", "systemctl", "stop", OVPN_UNIT])
    time.sleep(1)
    run(["sudo", "systemd-run", f"--unit={OVPN_UNIT}", "--collect",
         "--", "openvpn", "--config", config_path, "--auth-user-pass", OVPN_CREDS,
         "--auth-nocache", "--log", OVPN_LOG])
    time.sleep(4)
    return jsonify({"ok": ovpn_connected(), "server": servers[code]["sample"]})


@app.route("/api/vpn/openvpn/disconnect", methods=["POST"])
def api_ovpn_disconnect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    run(["sudo", "systemctl", "stop", OVPN_UNIT])
    return jsonify({"ok": True})


# ---------- ProtonVPN manual (OpenVPN) ----------

def proton_ovpn_has_credentials():
    return os.path.exists(PROTON_OVPN_CREDS)


def proton_ovpn_saved_username():
    if not os.path.exists(PROTON_OVPN_CREDS):
        return None
    try:
        with open(PROTON_OVPN_CREDS) as f:
            return f.readline().strip() or None
    except Exception:
        return None


def proton_ovpn_saved_password():
    if not os.path.exists(PROTON_OVPN_CREDS):
        return None
    try:
        with open(PROTON_OVPN_CREDS) as f:
            lines = f.readlines()
        return lines[1].strip() if len(lines) > 1 else None
    except Exception:
        return None


def proton_ovpn_server_name(code):
    # Proton's own downloaded filenames look like "mx-free-1.ovpn" - turn
    # that into a readable "Mexico (Free #1)" instead of showing the raw code.
    m = re.match(r"^([a-z]{2})-free-(\d+)$", code)
    if m:
        return f"{ovpn_country_name(m.group(1))} (Free #{m.group(2)})"
    if len(code) == 2:
        return ovpn_country_name(code)
    return code


def proton_ovpn_server_list():
    if not os.path.isdir(PROTON_OVPN_CONFIGS_DIR):
        return []
    result = []
    for fname in sorted(os.listdir(PROTON_OVPN_CONFIGS_DIR)):
        if not fname.endswith(".ovpn"):
            continue
        code = fname[:-len(".ovpn")]
        result.append({"code": code, "name": proton_ovpn_server_name(code), "filename": fname})
    result.sort(key=lambda x: x["name"])
    return result


def proton_ovpn_connected():
    code, out, _ = run(["sudo", "systemctl", "is-active", PROTON_OVPN_UNIT])
    return out.strip() == "active"


def proton_ovpn_connected_server():
    """Which saved config the running openvpn process was actually started
    with, so the UI can pre-select it after a switch or page reload."""
    code, out, _ = run(["bash", "-c", "ps -o args= -C openvpn 2>/dev/null | grep -- '--config'"])
    m = re.search(r"--config\s+'?([^\s']+\.ovpn)'?", out)
    if not m:
        return None
    fname = os.path.basename(m.group(1))
    if fname.endswith(".ovpn"):
        return fname[:-len(".ovpn")]
    return None


@app.route("/api/protonvpn/openvpn/status")
def api_proton_ovpn_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    connected = proton_ovpn_connected()
    return jsonify({
        "has_credentials": proton_ovpn_has_credentials(),
        "username": proton_ovpn_saved_username(),
        "password": proton_ovpn_saved_password(),
        "servers": proton_ovpn_server_list(),
        "connected": connected,
        "connected_code": proton_ovpn_connected_server() if connected else None,
    })


@app.route("/api/protonvpn/openvpn/credentials", methods=["POST"])
def api_proton_ovpn_credentials():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    username = data.get("username", "").strip()
    password = data.get("password", "").strip()
    if not username or not password:
        return jsonify({"ok": False, "error": "username and password required"}), 400
    run(["sudo", "mkdir", "-p", PROTON_OVPN_DIR])
    with open("/tmp/pantherpi_proton_creds.txt", "w") as f:
        f.write(f"{username}\n{password}\n")
    run(["sudo", "cp", "/tmp/pantherpi_proton_creds.txt", PROTON_OVPN_CREDS])
    run(["sudo", "chmod", "600", PROTON_OVPN_CREDS])
    run(["rm", "-f", "/tmp/pantherpi_proton_creds.txt"])
    return jsonify({"ok": True})


@app.route("/api/protonvpn/openvpn/config", methods=["POST"])
def api_proton_ovpn_config():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    code = re.sub(r"[^a-z0-9_-]", "", (data.get("code") or "").strip().lower())
    content = (data.get("config") or "").strip()
    if not code:
        return jsonify({"ok": False, "error": "give this server a short label (e.g. a country code)"}), 400
    if not content:
        return jsonify({"ok": False, "error": "paste a .ovpn config first"}), 400
    if "remote " not in content:
        return jsonify({"ok": False, "error": "doesn't look like a valid .ovpn file - no 'remote' server line found"}), 400
    run(["sudo", "mkdir", "-p", PROTON_OVPN_CONFIGS_DIR])
    tmp_path = f"/tmp/pantherpi_proton_{code}.ovpn"
    with open(tmp_path, "w") as f:
        f.write(content + "\n")
    run(["sudo", "cp", tmp_path, f"{PROTON_OVPN_CONFIGS_DIR}/{code}.ovpn"])
    run(["rm", "-f", tmp_path])
    return jsonify({"ok": True, "servers": proton_ovpn_server_list()})


@app.route("/api/protonvpn/openvpn/upload_zip", methods=["POST"])
def api_proton_ovpn_upload_zip():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "no file uploaded"}), 400
    if not f.filename.lower().endswith(".zip"):
        return jsonify({"ok": False, "error": "please upload a .zip file"}), 400

    tmp_zip = "/tmp/pantherpi_proton_upload.zip"
    extract_dir = "/tmp/pantherpi_proton_upload_extracted"
    f.save(tmp_zip)
    run(["rm", "-rf", extract_dir])
    code, out, err = run(["bash", "-c", f"mkdir -p {extract_dir} && cd {extract_dir} && unzip -oq {tmp_zip}"])
    if code != 0:
        run(["rm", "-rf", tmp_zip, extract_dir])
        return jsonify({"ok": False, "error": "failed to extract zip", "output": err}), 400

    run(["sudo", "mkdir", "-p", PROTON_OVPN_CONFIGS_DIR])
    added = []
    for root, _dirs, files in os.walk(extract_dir):
        for fname in files:
            if not fname.lower().endswith(".ovpn"):
                continue
            label = re.sub(r"[^a-z0-9_-]", "-", fname[:-len(".ovpn")].lower()).strip("-")
            if not label:
                continue
            src_path = os.path.join(root, fname)
            run(["sudo", "cp", src_path, f"{PROTON_OVPN_CONFIGS_DIR}/{label}.ovpn"])
            added.append(label)
    run(["rm", "-rf", tmp_zip, extract_dir])
    return jsonify({"ok": True, "added": len(added), "servers": proton_ovpn_server_list()})


@app.route("/api/protonvpn/openvpn/config/delete", methods=["POST"])
def api_proton_ovpn_config_delete():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code = re.sub(r"[^a-z0-9_-]", "", (request.json or {}).get("code", "").strip().lower())
    path = f"{PROTON_OVPN_CONFIGS_DIR}/{code}.ovpn"
    if os.path.exists(path):
        run(["sudo", "rm", "-f", path])
    return jsonify({"ok": True, "servers": proton_ovpn_server_list()})


@app.route("/api/protonvpn/openvpn/connect", methods=["POST"])
def api_proton_ovpn_connect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    if not proton_ovpn_has_credentials():
        return jsonify({"ok": False, "error": "Save your OpenVPN credentials first"}), 400
    code = (request.json or {}).get("code", "").strip()
    servers = {s["code"]: s for s in proton_ovpn_server_list()}
    if code not in servers:
        return jsonify({"ok": False, "error": "unknown server - add a config for it first"}), 400
    config_path = f"{PROTON_OVPN_CONFIGS_DIR}/{servers[code]['filename']}"
    # Independent transient unit (--collect), same reasoning as NordVPN's
    # manual OpenVPN connect: a plain background child would get killed
    # every time pantherpi.service restarts (e.g. on redeploy).
    run(["sudo", "systemctl", "stop", PROTON_OVPN_UNIT])
    time.sleep(1)
    run(["sudo", "systemd-run", f"--unit={PROTON_OVPN_UNIT}", "--collect",
         "--", "openvpn", "--config", config_path, "--auth-user-pass", PROTON_OVPN_CREDS,
         "--auth-nocache", "--log", PROTON_OVPN_LOG])
    time.sleep(4)
    return jsonify({"ok": proton_ovpn_connected(), "server": servers[code]["filename"]})


@app.route("/api/protonvpn/openvpn/disconnect", methods=["POST"])
def api_proton_ovpn_disconnect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    run(["sudo", "systemctl", "stop", PROTON_OVPN_UNIT])
    return jsonify({"ok": True})


# ---------- WireGuard (any provider) ----------

def sanitize_wg_config(content):
    """Strip the [Interface]'s DNS directive if present. wg-quick shells out
    to `resolvconf` to apply it, which isn't installed on this Pi (and most
    minimal Debian images) - without this, connecting fails outright with
    "resolvconf: command not found" even though the tunnel itself would
    otherwise come up fine. Not needed for our use case anyway: PantherPi
    uses this tunnel as a routing source for hotspot clients via the Routing
    page, not to override the Pi's own system resolver - dnsmasq already
    handles DNS for clients independently."""
    return "\n".join(
        line for line in content.splitlines()
        if not re.match(r"^\s*DNS\s*=", line, re.IGNORECASE)
    )


def wg_installed():
    code, out, _ = run(["bash", "-c", "which wg-quick"])
    return code == 0 and bool(out)


def install_wg():
    run(["sudo", "apt-get", "update"], timeout=90)
    code, out, err = run(
        ["sudo", "bash", "-c", "DEBIAN_FRONTEND=noninteractive apt-get install -y wireguard wireguard-tools"],
        timeout=180,
    )
    return code == 0, (out + "\n" + err).strip()


def wg_server_name(code):
    m = re.match(r"^([a-z]{2})-(.+)$", code)
    if m and len(m.group(1)) == 2:
        return f"{ovpn_country_name(m.group(1))} ({m.group(2)})"
    return code


def wg_server_list():
    if not os.path.isdir(WG_LIBRARY_DIR):
        return []
    result = []
    for fname in sorted(os.listdir(WG_LIBRARY_DIR)):
        if not fname.endswith(".conf"):
            continue
        code = fname[:-len(".conf")]
        result.append({"code": code, "name": wg_server_name(code), "filename": fname})
    result.sort(key=lambda x: x["name"])
    return result


def wg_connected():
    code, out, _ = run(["sudo", "systemctl", "is-active", WG_UNIT])
    return out.strip() == "active"


@app.route("/api/wireguard/status")
def api_wg_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    connected = wg_connected()
    return jsonify({
        "installed": wg_installed(),
        "servers": wg_server_list(),
        "connected": connected,
        "connected_code": cfg.get("wg_connected_code") if connected else None,
    })


@app.route("/api/wireguard/config", methods=["POST"])
def api_wg_config():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    code = re.sub(r"[^a-z0-9_-]", "", (data.get("code") or "").strip().lower())[:15]
    content = (data.get("config") or "").strip()
    if not code:
        return jsonify({"ok": False, "error": "give this server a short label (e.g. a country code)"}), 400
    if "[Interface]" not in content or "[Peer]" not in content:
        return jsonify({"ok": False, "error": "doesn't look like a valid WireGuard .conf - missing [Interface]/[Peer] section"}), 400
    content = sanitize_wg_config(content)
    run(["sudo", "mkdir", "-p", WG_LIBRARY_DIR])
    tmp_path = f"/tmp/pantherpi_wg_{code}.conf"
    with open(tmp_path, "w") as f:
        f.write(content + "\n")
    run(["sudo", "cp", tmp_path, f"{WG_LIBRARY_DIR}/{code}.conf"])
    run(["sudo", "chmod", "600", f"{WG_LIBRARY_DIR}/{code}.conf"])
    run(["rm", "-f", tmp_path])
    return jsonify({"ok": True, "servers": wg_server_list()})


@app.route("/api/wireguard/config/delete", methods=["POST"])
def api_wg_config_delete():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code = re.sub(r"[^a-z0-9_-]", "", (request.json or {}).get("code", "").strip().lower())
    path = f"{WG_LIBRARY_DIR}/{code}.conf"
    if os.path.exists(path):
        run(["sudo", "rm", "-f", path])
    return jsonify({"ok": True, "servers": wg_server_list()})


@app.route("/api/wireguard/upload_zip", methods=["POST"])
def api_wg_upload_zip():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    f = request.files.get("file")
    if not f or not f.filename:
        return jsonify({"ok": False, "error": "no file uploaded"}), 400
    if not f.filename.lower().endswith(".zip"):
        return jsonify({"ok": False, "error": "please upload a .zip file"}), 400

    tmp_zip = "/tmp/pantherpi_wg_upload.zip"
    extract_dir = "/tmp/pantherpi_wg_upload_extracted"
    f.save(tmp_zip)
    run(["rm", "-rf", extract_dir])
    code, out, err = run(["bash", "-c", f"mkdir -p {extract_dir} && cd {extract_dir} && unzip -oq {tmp_zip}"])
    if code != 0:
        run(["rm", "-rf", tmp_zip, extract_dir])
        return jsonify({"ok": False, "error": "failed to extract zip", "output": err}), 400

    run(["sudo", "mkdir", "-p", WG_LIBRARY_DIR])
    added = []
    for root, _dirs, files in os.walk(extract_dir):
        for fname in files:
            if not fname.lower().endswith(".conf"):
                continue
            label = re.sub(r"[^a-z0-9_-]", "-", fname[:-len(".conf")].lower()).strip("-")[:15]
            if not label:
                continue
            src_path = os.path.join(root, fname)
            try:
                with open(src_path) as sf:
                    sanitized = sanitize_wg_config(sf.read())
                with open(src_path, "w") as sf:
                    sf.write(sanitized)
            except Exception:
                pass
            dest = f"{WG_LIBRARY_DIR}/{label}.conf"
            run(["sudo", "cp", src_path, dest])
            run(["sudo", "chmod", "600", dest])
            added.append(label)
    run(["rm", "-rf", tmp_zip, extract_dir])
    return jsonify({"ok": True, "added": len(added), "servers": wg_server_list()})


@app.route("/api/wireguard/connect", methods=["POST"])
def api_wg_connect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    code = (request.json or {}).get("code", "").strip()
    servers = {s["code"]: s for s in wg_server_list()}
    if code not in servers:
        return jsonify({"ok": False, "error": "unknown server - add a config for it first"}), 400
    if not wg_installed():
        success, output = install_wg()
        if not success:
            return jsonify({"ok": False, "error": "Failed to install wireguard-tools", "output": output}), 500
    run(["sudo", "systemctl", "stop", WG_UNIT])
    time.sleep(1)
    run(["sudo", "cp", f"{WG_LIBRARY_DIR}/{servers[code]['filename']}", WG_ACTIVE_CONF])
    run(["sudo", "chmod", "600", WG_ACTIVE_CONF])
    run(["sudo", "systemctl", "start", WG_UNIT])
    time.sleep(2)
    ok = wg_connected()
    if ok:
        cfg = load_config()
        cfg["wg_connected_code"] = code
        save_config(cfg)
    return jsonify({"ok": ok, "server": servers[code]["filename"]})


@app.route("/api/wireguard/disconnect", methods=["POST"])
def api_wg_disconnect():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    run(["sudo", "systemctl", "stop", WG_UNIT])
    cfg = load_config()
    cfg["wg_connected_code"] = None
    save_config(cfg)
    return jsonify({"ok": True})


# ---------- Ethernet LAN (eth0 as a real router LAN port) ----------
#
# Gives a wired device plugged into eth0 real internet access, the same way
# the wireless hotspot does for wlan1: eth0 gets a static IP + its own DHCP
# range, and the existing Routing engine (see apply_routing_rule) handles
# NAT/masquerade + kill switch for wherever the internet actually comes
# from. Reuses that engine entirely rather than reimplementing routing.

ETH_LAN_DNSMASQ_CONF = "/etc/dnsmasq.d/091_pantherpi_ethlan.conf"
ETH_LAN_ROUTE_RULE_ID = "ethlan-auto"


def write_eth_lan_dnsmasq_conf(cfg):
    content = f"""interface={cfg['eth_lan_interface']}
dhcp-range={cfg['eth_lan_dhcp_start']},{cfg['eth_lan_dhcp_end']},255.255.255.0,12h
"""
    with open("/tmp/pantherpi_ethlan_dnsmasq.conf", "w") as f:
        f.write(content)
    run(["sudo", "cp", "/tmp/pantherpi_ethlan_dnsmasq.conf", ETH_LAN_DNSMASQ_CONF])


def clear_eth_lan_dnsmasq_conf():
    run(["sudo", "rm", "-f", ETH_LAN_DNSMASQ_CONF])


def upsert_eth_lan_routing_rule(cfg):
    rules = cfg.setdefault("routing_rules", [])
    rule = next((r for r in rules if r["id"] == ETH_LAN_ROUTE_RULE_ID), None)
    if not rule:
        rule = {"id": ETH_LAN_ROUTE_RULE_ID, "from": cfg["eth_lan_uplink"],
                 "to": cfg["eth_lan_interface"], "kill_switch": True, "enabled": True}
        rules.append(rule)
    rule["from"] = cfg["eth_lan_uplink"]
    rule["to"] = cfg["eth_lan_interface"]
    rule["enabled"] = True
    save_config(cfg)
    return rule


def remove_eth_lan_routing_rule(cfg):
    rules = cfg.get("routing_rules", [])
    rule = next((r for r in rules if r["id"] == ETH_LAN_ROUTE_RULE_ID), None)
    if rule:
        clear_routing_rule(rule)
        cfg["routing_rules"] = [r for r in rules if r["id"] != ETH_LAN_ROUTE_RULE_ID]
        save_config(cfg)


@app.route("/api/ethlan/status")
def api_ethlan_status():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cfg = load_config()
    iface = cfg["eth_lan_interface"]
    rule = next((r for r in cfg.get("routing_rules", []) if r["id"] == ETH_LAN_ROUTE_RULE_ID), None)
    return jsonify({
        "enabled": cfg.get("eth_lan_enabled", False),
        "interface": iface,
        "ip": cfg.get("eth_lan_ip"),
        "dhcp_start": cfg.get("eth_lan_dhcp_start"),
        "dhcp_end": cfg.get("eth_lan_dhcp_end"),
        "uplink": cfg.get("eth_lan_uplink"),
        "iface_up": is_iface_up(iface),
        "uplink_up": is_iface_up(cfg["eth_lan_uplink"]) if cfg.get("eth_lan_uplink") else False,
        "route_applied": bool(rule and rule.get("enabled")),
        "interfaces": [i["name"] for i in get_interfaces() if i["name"] != iface],
    })


@app.route("/api/ethlan/save", methods=["POST"])
def api_ethlan_save():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    cfg = load_config()
    enabled = bool(data.get("enabled", False))
    iface = (data.get("interface") or cfg["eth_lan_interface"]).strip()
    ip = (data.get("ip") or cfg["eth_lan_ip"]).strip()
    dhcp_start = (data.get("dhcp_start") or cfg["eth_lan_dhcp_start"]).strip()
    dhcp_end = (data.get("dhcp_end") or cfg["eth_lan_dhcp_end"]).strip()
    uplink = (data.get("uplink") or "").strip()

    if enabled and not uplink:
        return jsonify({"ok": False, "error": "pick an uplink interface to share internet from"}), 400
    if enabled and uplink == iface:
        return jsonify({"ok": False, "error": "uplink can't be the same interface as the LAN port"}), 400

    cfg["eth_lan_enabled"] = enabled
    cfg["eth_lan_interface"] = iface
    cfg["eth_lan_ip"] = ip
    cfg["eth_lan_dhcp_start"] = dhcp_start
    cfg["eth_lan_dhcp_end"] = dhcp_end
    cfg["eth_lan_uplink"] = uplink
    save_config(cfg)

    if enabled:
        run(["sudo", "ip", "addr", "flush", "dev", iface])
        run(["sudo", "ip", "addr", "add", f"{ip}/24", "dev", iface])
        run(["sudo", "ip", "link", "set", iface, "up"])
        write_eth_lan_dnsmasq_conf(cfg)
        run(["sudo", "systemctl", "restart", "dnsmasq"])
        run(["bash", "-c", "echo 1 | sudo tee /proc/sys/net/ipv4/ip_forward"])
        rule = upsert_eth_lan_routing_rule(cfg)
        apply_routing_rule(rule)
    else:
        remove_eth_lan_routing_rule(cfg)
        clear_eth_lan_dnsmasq_conf()
        run(["sudo", "systemctl", "restart", "dnsmasq"])
        run(["sudo", "ip", "addr", "flush", "dev", iface])

    return jsonify({"ok": True})


@app.route("/network")
def network():
    r = require_login()
    if r:
        return r
    cfg = load_config()
    code, leases, _ = run(["bash", "-c", "cat /var/lib/misc/dnsmasq.leases 2>/dev/null || true"])
    lease_list = []
    for line in leases.splitlines():
        parts = line.split()
        if len(parts) >= 4:
            lease_list.append({"mac": parts[1], "ip": parts[2], "hostname": parts[3]})
    return render_template("network.html", app_name=APP_NAME, cfg=cfg, leases=lease_list)


@app.route("/settings")
def settings():
    r = require_login()
    if r:
        return r
    return render_template("settings.html", app_name=APP_NAME)


@app.route("/api/lease/remove", methods=["POST"])
def api_lease_remove():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    data = request.json or {}
    mac = data.get("mac", "").strip()
    ip = data.get("ip", "").strip()
    if not mac or not ip:
        return jsonify({"ok": False, "error": "mac and ip required"}), 400
    cfg = load_config()
    run(["sudo", "dhcp_release", cfg["ap_interface"], ip, mac])
    run(["sudo", "hostapd_cli", "-i", cfg["ap_interface"], "deauthenticate", mac])
    return jsonify({"ok": True})


@app.route("/api/terminal/exec", methods=["POST"])
def api_terminal_exec():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    cmd = (request.json or {}).get("cmd", "")
    if not cmd.strip():
        return jsonify({"output": "", "cwd": session.get("term_cwd", "/root")})
    cwd = session.get("term_cwd", "/root")
    # run in the remembered directory, then report the new cwd so `cd` persists
    # across commands even though each request is a fresh subprocess
    wrapped = f"cd {cwd} 2>/dev/null && {cmd}; echo __PANTHERPI_CWD__$(pwd)"
    code, out, err = run(["bash", "-c", wrapped], timeout=30)
    full = out + err
    new_cwd = cwd
    if "__PANTHERPI_CWD__" in full:
        full, _, tail = full.rpartition("__PANTHERPI_CWD__")
        new_cwd = tail.strip() or cwd
    session["term_cwd"] = new_cwd
    return jsonify({"output": full.rstrip("\n"), "cwd": new_cwd})


@app.route("/api/terminal/complete", methods=["POST"])
def api_terminal_complete():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    text = (request.json or {}).get("text", "")
    cwd = session.get("term_cwd", "/root")
    last_word = text.split(" ")[-1] if text else ""
    prefix = text[: len(text) - len(last_word)] if last_word else text
    is_first_word = " " not in text.strip()

    escaped = last_word.replace("'", "'\\''")
    if is_first_word:
        compgen_flags = "-A command -A alias -A function"
    else:
        compgen_flags = "-A file -A directory"
    shell_cmd = f"cd {cwd} 2>/dev/null; compgen {compgen_flags} -- '{escaped}' | sort -u"
    code, out, _ = run(["bash", "-c", shell_cmd], timeout=5)
    candidates = [c for c in out.splitlines() if c]
    return jsonify({"candidates": candidates, "prefix": prefix, "partial": last_word})


@app.route("/api/system/reboot", methods=["POST"])
def api_system_reboot():
    if not is_logged_in():
        return jsonify({"error": "unauthorized"}), 401
    run(["bash", "-c", "sleep 1 && sudo reboot &"])
    return jsonify({"ok": True})


def restore_hotspot_on_boot():
    """Runs once per service start (boot, or a service restart after a
    deploy). If the hotspot was on when it was last stopped, bring it back
    up automatically - same expectation as any normal router. Runs in its
    own thread so the web UI itself is reachable immediately rather than
    waiting on hostapd's startup retry loop."""
    cfg = load_config()
    if not cfg.get("hotspot_enabled"):
        return
    time.sleep(5)  # let NetworkManager finish enumerating interfaces after boot
    try:
        start_hotspot(cfg)
    except Exception:
        pass


threading.Thread(target=restore_hotspot_on_boot, daemon=True).start()
threading.Thread(target=vpn_kill_switch_watcher, daemon=True).start()


if __name__ == "__main__":
    # threaded=True is essential - without it Flask's dev server handles one
    # request at a time, so any single slow/blocking request (e.g. the VPN
    # server-package download) freezes the ENTIRE web UI for every user
    # until it finishes.
    app.run(host="0.0.0.0", port=80, debug=False, threaded=True)
