// PantherPi shared client-side helpers (page-specific logic lives inline per template)
document.addEventListener('DOMContentLoaded', () => {
  console.log('PantherPi UI online');
  pollNavLiveStates();
  setInterval(pollNavLiveStates, 6000);

  const menuBtn = document.getElementById('mobile-menu-btn');
  const overlay = document.getElementById('sidebar-overlay');
  const sidebar = document.querySelector('.sidebar');
  function toggleSidebar() {
    sidebar.classList.toggle('open');
    overlay.classList.toggle('open');
  }
  function closeSidebar() {
    sidebar.classList.remove('open');
    overlay.classList.remove('open');
  }
  if (menuBtn && overlay && sidebar) {
    // click covers desktop + most mobile browsers; touchend is a fallback
    // for mobile browsers where a fixed-position button's click event can
    // be unreliable/delayed - preventDefault stops it from also firing a
    // trailing click and double-toggling
    menuBtn.addEventListener('click', toggleSidebar);
    menuBtn.addEventListener('touchend', (e) => { e.preventDefault(); toggleSidebar(); });
    overlay.addEventListener('click', closeSidebar);
    overlay.addEventListener('touchend', (e) => { e.preventDefault(); closeSidebar(); });
  }
});

function setNavLive(href, active) {
  const link = document.querySelector(`nav a[href="${href}"]`);
  if (link) link.classList.toggle('nav-live', !!active);
}

function setNavState(href, isLive, isDanger) {
  const link = document.querySelector(`nav a[href="${href}"]`);
  if (!link) return;
  link.classList.toggle('nav-live', !!isLive);
  link.classList.toggle('nav-danger', !!isDanger);
}

function setNavLabel(id, text) {
  const el = document.getElementById(`nav-label-${id}`);
  if (el) el.textContent = text;
}

function vpnShortLabel(data) {
  if (data.tunnel_provider) {
    if (data.tunnel_provider.startsWith('NordVPN')) return 'Nord';
    if (data.tunnel_provider.startsWith('ProtonVPN')) return 'Proton';
    if (data.tunnel_provider.startsWith('WireGuard')) return 'WireGuard';
    if (data.tunnel_provider === 'PPP VPN') return 'PPP';
    return 'VPN';
  }
  return null;
}

async function pollNavLiveStates() {
  let vpnConnected = false;
  let proxyConnected = false;

  try {
    const res = await fetch('/api/vpn/quick_status');
    const data = await res.json();
    vpnConnected = !!data.connected;
    const dot = document.getElementById('vpn-nav-dot');
    if (dot) dot.classList.toggle('vpn-connected', vpnConnected);
  } catch (e) { /* ignore */ }

  try {
    const res = await fetch('/api/proxy/status');
    const data = await res.json();
    proxyConnected = !!(data.enabled && data.prox0_up && data.route_applied);
  } catch (e) { /* ignore */ }

  try {
    const res = await fetch('/api/captive_portal/status');
    const data = await res.json();
    setNavLive('/captive-portal-settings', !!data.enabled);
  } catch (e) { /* ignore */ }

  // VPN and Proxy are independent security layers - either one alone still
  // counts as "secure", so each only turns red if NEITHER is active. Both
  // green when both are on.
  setNavState('/vpn', vpnConnected, !vpnConnected && !proxyConnected);
  setNavState('/proxy', proxyConnected, !proxyConnected && !vpnConnected);

  try {
    const res = await fetch('/api/status');
    const data = await res.json();
    setNavLive('/hotspot', data.hostapd_active);
    setNavLabel('hotspot', data.hostapd_active ? `HOTSPOT - ${data.ap_ssid}` : 'HOTSPOT');

    const bothKillSwitchesOn = !!data.leak_protection && !!data.vpn_kill_switch;
    setNavState('/firewall', bothKillSwitchesOn, !bothKillSwitchesOn);

    const wifiClient = (data.interfaces || []).find(i => i.role === 'CLIENT' && i.network);
    setNavLive('/wifi', !!wifiClient);
    setNavLabel('wifi', wifiClient ? `WIFI CLIENT - ${wifiClient.network}` : 'WIFI CLIENT');

    const vpnLabel = vpnShortLabel(data);
    setNavLabel('vpn', vpnConnected && vpnLabel ? `VPN - ${vpnLabel}` : 'VPN');
  } catch (e) { /* ignore */ }
}
