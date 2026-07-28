# PantherPi VPN Hotspot

A self-hosted, dark-HUD network control panel for the Raspberry Pi — turn any Pi into a
VPN-routed WiFi hotspot with a real web GUI, no config-file editing required. Think
[RaspAP](https://raspap.com), but built around VPN/proxy routing, per-rule kill switches, and a
captive portal, as a single Flask app with zero external database or build step.

<!--
  TODO before publishing: add real screenshots to docs/screenshots/ and uncomment, e.g.:
  ![PantherPi dashboard](docs/screenshots/dashboard.png)
  ![Hotspot page](docs/screenshots/hotspot.png)
  ![VPN page](docs/screenshots/vpn.png)
-->

## Install (one command)

```bash
curl -sSL https://raw.githubusercontent.com/PantherDecode/PantherPi-VPN-Hotspot/main/install.sh | sudo bash
```

This fetches the source, installs every dependency, and starts PantherPi as a systemd service in
under two minutes on a Pi 4/5. Then open `http://<pi-ip>/` in a browser — or just
`http://pantherpi.local/`, since the installer sets the hostname and enables mDNS so you don't
have to go hunting for the IP (works from any device on the same network that supports `.local`
resolution - Windows, macOS, iOS, and Linux all do; some Android versions are inconsistent).

**Default login:** `admin` / `admin` — change it immediately under **Settings**.

Prefer to review the script first (recommended for anything piped into `sudo bash`)?

```bash
git clone https://github.com/PantherDecode/PantherPi-VPN-Hotspot.git
cd PantherPi-VPN-Hotspot
sudo bash install.sh
```

## What it does

PantherPi turns a Raspberry Pi into a WiFi access point whose upstream traffic you fully
control — route it through a VPN, an upstream proxy, a specific network interface, or any
combination, each with its own independent kill switch so nothing leaks if that path drops.

```
                    ┌─────────────┐        ┌──────────────────┐        ┌─────────────┐
  Internet  ───────▶│  uplink      │──────▶│   VPN / Proxy /   │──────▶│   Hotspot    │───▶ your devices
 (eth0/wlan0)        │  interface   │        │  routing engine   │        │  (wlan1/AP)  │
                    └─────────────┘        └──────────────────┘        └─────────────┘
                                                     ▲
                                            kill switch per hop:
                                       traffic drops, never leaks unprotected
```

A common setup: a USB WiFi adapter (or a second onboard radio) broadcasts the hotspot, while
`eth0` or the onboard WiFi supplies internet — optionally through a VPN tunnel or upstream proxy
before it ever reaches your devices.

## Features

- **Dashboard** — live CPU/memory gauges, every interface's own state and *individually
  checked* external IP/country, connected hotspot clients with hostname + one-click block,
  per-interface speed test, and country-switching for any connected VPN
- **WiFi Client** — scan and connect any interface to a nearby network, with a disconnect button
- **Hotspot** — SSID/password/channel/static IP/DHCP range on any AP-capable interface, with
  **automatic uplink failover** (prefers `eth0`, falls back to `wlan0`, switches back
  automatically, and reconnects any active VPN tunnel so it re-homes onto the new path)
- **Firewall** —
  - *Leak protection*: hotspot traffic may only exit via the configured uplink; anything that
    would otherwise leak out a different interface is dropped instead
  - *VPN kill switch* (**on by default**): hard-blocks ALL hotspot internet unless a real tunnel
    (VPN or proxy) is actively up — a plain unencrypted uplink never satisfies it, and this stays
    enforced through interface changes (e.g. moving the AP from `wlan1` to `wlan0`) with no
    manual re-wiring needed
  - Manual MAC address blocklist
- **Captive Portal** — gate the whole hotspot behind a sign-in page (real iptables-level
  enforcement by MAC address, not just an app-layer redirect) — shows guests the external IP and
  country they'll be browsing as *before* they sign in, and lets you revoke individual devices
- **Routing** — a generic engine: route traffic from any "distribution" interface out through any
  "source" interface, each rule with its own independent kill switch. This is what the VPN and
  Proxy features are themselves built on
- **VPN** —
  - NordVPN: native CLI wrapper (connect/disconnect/country) or manual multi-server OpenVPN
    (paste a `.ovpn` or upload a zip of them)
  - ProtonVPN: same — native CLI wrapper, or manual multi-server OpenVPN
  - WireGuard: multi-server config management (paste or zip upload), connect/disconnect/switch
- **Proxy** — routes hotspot traffic through an upstream HTTP/SOCKS5 proxy via a real `prox0`
  tunnel interface (built on [tun2socks](https://github.com/xjasonlyu/tun2socks), not a NAT
  redirect) — shows up on the Dashboard like any other tunnel, with its own kill switch and a
  one-click off button
- **Network** — active DHCP leases with a kick/remove option, current config summary
- **Settings** — change the admin password
- **Terminal** — a floating web terminal on every page, root shell with tab-completion, no SSH
  client needed

The VPN and Proxy nav items reflect a combined security state: each turns green when its own
protection is active, and both only turn red if *neither* is protecting your traffic — either one
alone is treated as secure.

## Requirements

- A Raspberry Pi (or any Debian-based SBC) running **Raspberry Pi OS Bookworm/Trixie** or newer
- At least one WiFi interface that supports **AP mode** for the hotspot itself — check with
  `iw list` (look for `AP` under `Supported interface modes`); not every USB WiFi chipset does
- A second interface (WiFi or Ethernet) for the internet uplink, if you want the AP and the
  internet source to be different interfaces (recommended)
- Run the installer as root — the app itself also runs as root, since it needs direct control of
  `hostapd`, `dnsmasq`, `iptables`, and network interfaces

## After install

1. Log in (`admin` / `admin`) and change the password under **Settings**.
2. By default the hotspot is already broadcasting on `wlan0` (SSID `PantherPi`, password
   `PantherPi123`) with `eth0` as the internet uplink — same out-of-box behavior as a normal
   router. Go to **Hotspot** to change the SSID/password/interfaces to your own, and hit **SAVE
   CONFIGURATION** then **RESTART HOTSPOT** to apply. If your AP and uplink need to be different
   interfaces than the defaults (e.g. a USB WiFi dongle for the AP, onboard `wlan0` free for
   something else), switch that here too.
3. Whatever hotspot state you leave it in (on or off, whichever interfaces) is remembered and
   restored automatically on every future boot or service restart.
4. **The VPN kill switch is ON by default** (see Firewall) — hotspot clients get **zero internet**
   until a real VPN or Proxy tunnel is actually up, with no silent plaintext fallback. This means a
   fresh install broadcasts a hotspot with no internet on it until you either set up a
   VPN/Proxy (below), or turn the kill switch off under **Firewall** if you'd rather allow a plain
   `eth0`/`wlan0` connection through.
5. Set up a VPN (NordVPN/ProtonVPN/WireGuard) or Proxy tunnel, then either point the **uplink** at
   it, or use **Routing** to send hotspot traffic through it directly — this is what satisfies the
   kill switch above.
6. Optionally enable **Captive Portal** if you want guests to sign in before getting online.

## Uninstall

```bash
sudo bash uninstall.sh
```

Optionally keeps your saved config (`/etc/pantherpi`) for a future reinstall.

## Security notes

- VPN/proxy credentials, WireGuard private keys, and the captive portal password are stored in
  **plaintext** in `/etc/pantherpi/config.json` (root-only, mode 600 by default on most distros'
  `/etc`, but treat the file as sensitive regardless — this isn't a secrets vault).
- The default admin login is `admin` / `admin`. Change it immediately after install.
- The captive portal, once enabled, gates the *entire* hotspot subnet — including this admin GUI
  if you access it from a device connected to the hotspot itself.

## Project layout

```
app.py                 Flask application - all routes and system-control logic
templates/              Jinja2 HTML templates (one per page)
static/                 CSS + JS
pantherpi.service       systemd unit, installed to /etc/systemd/system/
install.sh              installer (also usable standalone via curl | sudo bash)
uninstall.sh            uninstaller
```

Config lives at `/etc/pantherpi/config.json` (created with sane defaults on first run).

## License

[MIT](LICENSE)
