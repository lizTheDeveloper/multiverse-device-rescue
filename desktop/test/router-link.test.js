const test = require('node:test');
const assert = require('node:assert');
const RouterLink = require('../renderer/router-link');

const f = (module, check, severity = 'warning', data = {}) => ({
  module, severity, code: `network.${module}.${check}`, title: 't', data: { check, ...data },
});
const doc = (...findings) => {
  const modules = {};
  for (const x of findings) (modules[x.module] = modules[x.module] || []).push(x);
  return { modules: Object.entries(modules).map(([name, fs]) => ({ name, status: 'ok', supported: true, findings: fs })) };
};
const routerInfo = f('router_security_audit', 'router_manual_review', 'info', { gateway_ip: '192.168.0.1' });

test('context takes the gateway address from the router check', () => {
  const ctx = RouterLink.contextFrom(doc(routerInfo), 'Safari');
  assert.deepStrictEqual(ctx, { ip: '192.168.0.1', blocked: false, browser: 'Safari' });
});

test('no context without a private gateway address', () => {
  assert.strictEqual(RouterLink.contextFrom(doc(f('wifi_security_audit', 'wpa2_only')), 'Safari'), null);
  assert.strictEqual(RouterLink.contextFrom(doc(f('router_security_audit', 'router_manual_review', 'info', { gateway_ip: '8.8.8.8' }))), null);
  assert.strictEqual(RouterLink.contextFrom(null), null);
  assert.strictEqual(RouterLink.contextFrom({}), null);
});

test('blocked when the ARP check says the router may be impersonated', () => {
  for (const check of ['gateway_impersonation', 'locally_administered_gateway', 'multiple_gateways']) {
    const ctx = RouterLink.contextFrom(doc(routerInfo, f('arp_spoof_check', check)), 'Safari');
    assert.strictEqual(ctx.blocked, true, check);
  }
  // A device answering for several addresses is not about the router.
  assert.strictEqual(RouterLink.contextFrom(doc(routerInfo, f('arp_spoof_check', 'duplicate_mac')), 'Safari').blocked, false);
});

test('which findings offer the router page', () => {
  assert.strictEqual(RouterLink.offersRouter(f('router_security_audit', 'admin_service_open', 'warning')), true);
  assert.strictEqual(RouterLink.offersRouter(f('router_security_audit', 'admin_service_open', 'info')), false);
  assert.strictEqual(RouterLink.offersRouter(f('router_security_audit', 'upnp_enabled')), true);
  assert.strictEqual(RouterLink.offersRouter(routerInfo), true);
  assert.strictEqual(RouterLink.offersRouter(f('lan_device_inventory', 'lan_inventory', 'info')), true);
  assert.strictEqual(RouterLink.offersRouter(f('lan_device_inventory', 'unrecognised_device')), true);
  assert.strictEqual(RouterLink.offersRouter(f('wifi_security_audit', 'wpa2_only')), true);
  assert.strictEqual(RouterLink.offersRouter(f('wifi_security_audit', 'open_saved')), false);
  assert.strictEqual(RouterLink.offersRouter(f('arp_spoof_check', 'gateway_impersonation', 'critical')), false);
  assert.strictEqual(RouterLink.offersRouter(null), false);
});

test('the button names the address and the browser, and says who signs in', () => {
  const html = RouterLink.findingLinkHtml(f('router_security_audit', 'upnp_enabled'), { ip: '192.168.0.1', blocked: false, browser: 'Safari' });
  assert.match(html, /data-router-ip="192\.168\.0\.1"/);
  assert.match(html, /Open your router’s settings/);
  assert.match(html, /in Safari/);
  assert.match(html, /type 192\.168\.0\.1/);
  assert.match(html, /never sees/);
  assert.match(html, /phone app/);
});

test('without a browser name it says "your web browser"', () => {
  assert.match(RouterLink.hintText({ ip: '10.0.0.1', blocked: false, browser: null }), /in your web browser/);
});

test('blocked: no button, a warning instead', () => {
  const html = RouterLink.findingLinkHtml(f('router_security_audit', 'upnp_enabled'), { ip: '192.168.0.1', blocked: true, browser: 'Safari' });
  assert.doesNotMatch(html, /data-router-ip/);
  assert.match(html, /pretending to be your router/);
  assert.match(html, /label/);
});

test('nothing for findings that do not offer it, or without context', () => {
  assert.strictEqual(RouterLink.findingLinkHtml(f('wifi_security_audit', 'open_saved'), { ip: '192.168.0.1', blocked: false }), '');
  assert.strictEqual(RouterLink.findingLinkHtml(f('router_security_audit', 'upnp_enabled'), null), '');
});

test('escapes the browser name', () => {
  const html = RouterLink.findingLinkHtml(f('router_security_audit', 'upnp_enabled'), { ip: '192.168.0.1', blocked: false, browser: '<img src=x>' });
  assert.doesNotMatch(html, /<img/);
});

test('a lesson question marked `router` shows the router button when there is a context', async () => {
  const { pathToFileURL } = require('url');
  const path = require('path');
  const { renderLesson } = await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'views', 'lesson.js')).href);
  global.window = { RouterLink };
  const lesson = { id: 'x', title: 'X', briefing: 'b', whatTheScanLooksFor: 'w',
    questions: [{ teach: 't', prompt: 'p', router: true, options: [{ text: 'a', correct: true, feedback: 'f' }] }] };
  const args = { lesson, qIndex: 0, picked: null, scan: {}, scout: () => '', pendingCity: false };
  assert.match(renderLesson({ ...args, routerFor: () => ({ ip: '192.168.0.1', blocked: false, browser: null }) }), /data-act="open-router"/);
  assert.doesNotMatch(renderLesson({ ...args, routerFor: () => null }), /open-router/);
  assert.doesNotMatch(renderLesson(args), /open-router/);
  delete global.window;
});

test('whos-on-wifi marks its "where is the full list" question as a router question', async () => {
  const { pathToFileURL } = require('url');
  const path = require('path');
  const l = (await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', 'lessons', 'whos-on-wifi.js')).href)).default;
  const q = l.questions.find((x) => /full list of devices/.test(x.prompt));
  assert.strictEqual(q.router, true);
});

test('index.html loads router-link.js before app.js', () => {
  const fs = require('fs');
  const path = require('path');
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  const a = html.indexOf('src="router-link.js"');
  assert.ok(a > 0 && a < html.indexOf('src="app.js"'));
});
