'use strict';

/*
 * "Open your router's settings": the router's own sign-in page, at the gateway
 * address the router check read from this computer's routing table.
 *
 * Only the address crosses IPC (window.rescue.openRouter); main builds the URL
 * and accepts only private home-network addresses (router-url.js). The person
 * signs in themselves; nothing here sees or handles a password.
 *
 * No button when the ARP check says another device may be answering for the
 * router: opening that address could hand the router password to whatever is
 * pretending to be it. The person is told to check the router's label instead.
 * When the ARP check didn't run (not in this profile, errored, unsupported), that
 * is "couldn't check", not "clean": the button stays, and its hint says so.
 */
const RouterLink = (function () {
  // Warning/critical findings whose fix happens on the router's own pages.
  const ROUTER_CODES = new Set([
    'network.router_security_audit.admin_service_open',
    'network.router_security_audit.upnp_enabled',
    'network.lan_device_inventory.unrecognised_device',
    'network.lan_device_inventory.device_count_exceeded',
    'network.wifi_security_audit.wep_connected',
    'network.wifi_security_audit.wpa2_only',
  ]);
  // Info findings that are themselves "go and look at your router".
  const ALWAYS_CODES = new Set([
    'network.router_security_audit.router_manual_review',
    'network.lan_device_inventory.lan_inventory',
  ]);
  // ARP findings that mean the router's address may not be the router.
  const IMPERSONATION_CHECKS = new Set(['gateway_impersonation', 'locally_administered_gateway', 'multiple_gateways']);

  const OCTET = '(25[0-5]|2[0-4][0-9]|1[0-9][0-9]|[1-9]?[0-9])';
  const IPV4 = new RegExp(`^${OCTET}\\.${OCTET}\\.${OCTET}\\.${OCTET}$`);
  // Same rule main enforces; checked here too so no button points at an address main would refuse.
  function isPrivateIpv4(ip) {
    const m = typeof ip === 'string' ? IPV4.exec(ip) : null;
    if (!m) return false;
    const a = Number(m[1]);
    const b = Number(m[2]);
    return a === 10 || (a === 172 && b >= 16 && b <= 31) || (a === 192 && b === 168);
  }

  function allFindings(doc) {
    const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
    return modules.flatMap((m) => (Array.isArray(m.findings) ? m.findings.map((f) => ({ module: m.name, ...f })) : []));
  }

  // { ip, blocked, unverified, browser } for a scan, or null when it has no usable router address.
  function contextFrom(doc, browser) {
    const findings = allFindings(doc);
    const fromRouter = findings.find((f) => f.module === 'router_security_audit' && f.data && isPrivateIpv4(f.data.gateway_ip));
    if (!fromRouter) return null;
    const blocked = findings.some((f) => f.module === 'arp_spoof_check' && f.data && IMPERSONATION_CHECKS.has(f.data.check));
    const arp = (doc.modules || []).find((m) => m && m.name === 'arp_spoof_check');
    const unverified = !arp || arp.status !== 'ok' || arp.supported === false;
    return { ip: fromRouter.data.gateway_ip, blocked, unverified, browser: typeof browser === 'string' && browser ? browser : null };
  }

  function offersRouter(finding) {
    if (!finding || !finding.code) return false;
    if (ALWAYS_CODES.has(finding.code)) return true;
    return ROUTER_CODES.has(finding.code) && (finding.severity === 'critical' || finding.severity === 'warning');
  }

  function hintText(ctx) {
    const where = ctx.browser ? `in ${ctx.browser}` : 'in your web browser';
    return `Opens your router’s sign-in page (http://${ctx.ip}/) ${where}. You sign in there yourself; Reclaim City never sees the password. `
      + `You can also type ${ctx.ip} into any browser’s address bar. If your router is managed by a phone app, use the app instead.`
      + (ctx.unverified ? ' This checkup couldn’t confirm that this address is really your router, so compare it with the address on the router’s label before you sign in.' : '');
  }

  const BLOCKED_TEXT = 'Not opening your router’s page: this checkup saw signs that another device may be pretending to be your router. '
    + 'Before you sign in anywhere, check the address printed on the router’s label, or connect to the router with a cable.';

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // The plain results' button for a finding card, or ''.
  function findingLinkHtml(finding, ctx) {
    if (!ctx || !offersRouter(finding)) return '';
    if (ctx.blocked) return `<div class="setting-link"><p class="muted setting-link__hint">${esc(BLOCKED_TEXT)}</p></div>`;
    return `<div class="setting-link">
      <button type="button" class="btn btn--secondary btn--small" data-router-ip="${esc(ctx.ip)}">Open your router’s settings</button>
      <p class="muted setting-link__hint">${esc(hintText(ctx))}</p>
    </div>`;
  }

  // Game mode's version (mission briefings and lessons), or ''.
  function gameLinkHtml(ctx) {
    if (!ctx) return '';
    if (ctx.blocked) return `<p class="setting-hint">${esc(BLOCKED_TEXT)}</p>`;
    return `<button type="button" class="btn-s setting-open" data-act="open-router">OPEN YOUR ROUTER ▶</button>
      <p class="setting-hint">${esc(hintText(ctx))}</p>`;
  }

  return { ROUTER_CODES, ALWAYS_CODES, isPrivateIpv4, contextFrom, offersRouter, hintText, BLOCKED_TEXT, findingLinkHtml, gameLinkHtml };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = RouterLink;
}
// Game mode's ES modules read it from window, like SettingPanes.
if (typeof window !== 'undefined') {
  window.RouterLink = RouterLink;
}
