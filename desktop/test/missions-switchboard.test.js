'use strict';
// The Switchboard (network lines) mini-game: missions/games/switchboard.js.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const FIXTURE = path.join(__dirname, 'fixtures', 'missions', 'switchboard-items.json');

async function load() {
  const C = await import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
  const mod = await import(pathToFileURL(path.join(MISSIONS, 'games', 'switchboard.js')).href);
  const fixtures = JSON.parse(fs.readFileSync(FIXTURE, 'utf8')).findings;
  const items = fixtures.map(({ expect, platform, ...f }) => C.makeItem(f));
  return { C, mod, game: mod.default, fixtures, items };
}

const ctxFor = (C, f, extra = {}) => C.testContext({ platform: f.platform || 'darwin', ...extra });
const ids = (ds) => ds.map((d) => d.id);
const byId = (ds, id) => ds.find((d) => d.id === id);
// The default order: Expected first only on a note; on a critical or warning line (or one that can alert someone)
// Look closer leads, or "close it" for a website name sent to a real address. Expected goes last.
const orderFor = (f, mod) => {
  const wary = f.severity === 'critical' || f.severity === 'warning' || !!f.removal_alert;
  if (!wary) return ['expected', 'odd', 'closer'];
  return mod.lineKind(f) === 'hosts' && mod.redirectsElsewhere(f) ? ['odd', 'closer', 'expected'] : ['closer', 'odd', 'expected'];
};

test('passes every contract check on fixture and practice items', async () => {
  const { C, game, items } = await load();
  assert.deepStrictEqual(C.runContractChecks(game, items), []);
  // ...and on Windows.
  const winItems = items.map((i) => i);
  for (const mode of ['standard', 'city']) {
    for (const item of winItems) {
      const ctx = C.testContext({ mode, platform: 'win32' });
      const d = game.decisions(item, ctx);
      assert.deepStrictEqual(C.checkDecisions(d, item), [], item.key);
      assert.deepStrictEqual(C.checkResearch(game.research(item, ctx)), [], item.key);
      const html = game.render({ item, research: game.research(item, ctx), decisions: d, index: 0, total: 1 }, ctx);
      assert.deepStrictEqual(C.checkInert(html), [], item.key);
      if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(html), [], item.key);
    }
  }
});

test('each fixture finding is traced as its kind, with at least one line', async () => {
  const { C, mod, fixtures, items } = await load();
  fixtures.forEach((f, i) => {
    const t = mod.linesOf(items[i].finding, ctxFor(C, f));
    assert.strictEqual(t.kind, f.expect.kind, f.code || f.module);
    assert.ok(t.lines.length >= 1, `${f.code}: no line`);
    for (const l of t.lines) assert.ok(l.via && l.to, `${f.code}: line needs via and to`);
  });
});

test('Expected marks only when markable; Odd fixes, opens the right pane, or gives steps', async () => {
  const { C, mod, game, fixtures, items } = await load();
  fixtures.forEach((f, i) => {
    const d = game.decisions(items[i], ctxFor(C, f));
    assert.strictEqual(d.length, 3, f.code);
    assert.deepStrictEqual(ids(d), orderFor(items[i].finding, mod), f.code);
    const expected = byId(d, 'expected'); const odd = byId(d, 'odd'); const closer = byId(d, 'closer');
    assert.strictEqual(expected.effect.kind, f.expect.expected, `${f.code} expected`);
    assert.strictEqual(odd.effect.kind, f.expect.odd, `${f.code} odd`);
    if (f.expect.pane) assert.strictEqual(odd.effect.pane, f.expect.pane, `${f.code} pane`);
    if (odd.effect.kind === 'odd') assert.ok(Array.isArray(odd.effect.steps) && odd.effect.steps.length, `${f.code} steps`);
    assert.strictEqual(closer.effect.kind, 'closer');
    assert.ok(closer.effect.checklist.length >= 2, `${f.code} checklist`);
    assert.notStrictEqual(d[0].effect.kind, 'fix');
    assert.ok(!['keep', 'mark'].includes(d[0].effect.kind) || f.severity === 'info', `${f.code}: Expected leads a ${f.severity} line`);
    // R6: the change on an alerting item carries the removal warning; others don't.
    assert.strictEqual(!!odd.effect.warning, !!f.removal_alert, `${f.code} warning`);
  });
});

test('render draws only the card: no buttons, links or evidence rows (the runner draws those)', async () => {
  const { C, game, items } = await load();
  const rows = [{ label: 'Program', value: 'ROWVALUE' }];
  for (const item of items) {
    const ctx = C.testContext({ evidenceRows: () => rows });
    const r = game.research(item, ctx);
    const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.doesNotMatch(html, /<button|<a\b|href=|ROWVALUE/, item.key);
  }
});

test('a marked-but-changed item can be marked again; a bad markable block is kept, not marked', async () => {
  const { C, game } = await load();
  const good = { kind: 'network_proxy', id: '1a2b3c4d5e6f', code: 'security.network_proxy.proxy_enabled', group: '6f5e4d3c2b1a' };
  const f = { module: 'network_proxy', code: 'security.network_proxy.proxy_enabled', data: { http_server: 'proxy.example:8080' } };
  const exp = (mk) => byId(game.decisions(C.makeItem({ ...f, markable: mk }), C.testContext()), 'expected').effect.kind;
  assert.strictEqual(exp(good), 'mark');
  assert.strictEqual(exp({ ...good, id: 'not-an-id' }), 'keep');
  assert.strictEqual(exp({ ...good, kind: 'background_task' }), 'keep');
});

test('covers: the spec modules and their Windows equivalents; never a firewall on/off code', async () => {
  const { game } = await load();
  const cov = game.covers;
  assert.ok(Array.isArray(cov));
  const names = cov.map((c) => c.module);
  assert.strictEqual(new Set(names).size, names.length, 'a module listed twice');
  for (const m of ['firewall_rules_audit', 'open_ports_scan', 'network_connections_monitor', 'suspicious_connections',
    'dns_config', 'dns_poisoning_check', 'hosts_file_check', 'network_proxy', 'network_proxy_check', 'network_proxy_detect',
    'remote_login_check', 'sharing_preferences_audit', 'router_security_audit', 'wifi_security_audit', 'vpn_leak_check',
    'airdrop_config', 'win_firewall_rules_audit', 'win_hosts_file', 'win_hosts_file_check', 'win_proxy_detect',
    'win_rdp_check', 'win_remote_access_audit', 'win_network_shares_audit', 'win_dns_config']) {
    assert.ok(names.includes(m), `covers ${m}`);
  }
  // Lock Run owns the firewall switch.
  assert.ok(!names.includes('firewall_audit'));
  assert.ok(!names.includes('win_firewall'));
  const fr = cov.find((c) => c.module === 'firewall_rules_audit');
  assert.ok(Array.isArray(fr.codes) && fr.codes.length);
  for (const code of fr.codes) assert.ok(!/alf_|stealth_/.test(code), code);
  assert.ok(fr.codes.includes('security.firewall_rules_audit.too_many_apps'));
  assert.ok(fr.codes.includes('security.firewall_rules_audit.allow_signed_enabled'));
});

test('covers: every module named is a real engine module', async () => {
  const { game } = await load();
  const root = path.join(__dirname, '..', '..', 'modules');
  const real = new Set();
  for (const cat of fs.readdirSync(root)) {
    const d = path.join(root, cat);
    if (fs.statSync(d).isDirectory()) for (const m of fs.readdirSync(d)) real.add(m);
  }
  for (const c of game.covers) assert.ok(real.has(c.module), `no engine module ${c.module}`);
});

test('DNS filtering profile asks whose profile it is; city mode drops the finding prose', async () => {
  const { C, game, fixtures, items } = await load();
  const i = fixtures.findIndex((f) => f.code === 'security.dns_poisoning_check.dns_filtering_profile');
  const item = items[i];
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const d = game.decisions(item, ctx);
    assert.strictEqual(byId(d, 'expected').effect.kind, 'mark');
    assert.strictEqual(d[0].id, 'closer', 'whose profile is it: Look closer leads, never the mark');
    const html = game.render({ item, research: game.research(item, ctx), decisions: d, index: 0, total: 1 }, ctx);
    assert.match(html, /sb-ask/);
    assert.match(html, /ExampleDNS/);
    assert.match(html, /192\.0\.2\.53/);
    if (mode === 'standard') {
      assert.match(html, /Whose profile is this\?/);
      assert.strictEqual(byId(d, 'expected').label.standard, 'It’s my profile');
    } else {
      assert.deepStrictEqual(C.checkCityWords(html), []);
      assert.doesNotMatch(html, /advocate|hotline|monitor/i);
    }
  }
  const r = game.research(item, C.testContext());
  assert.ok(r.links.some((l) => l.kind === 'settings' && l.pane === 'dns'));
  assert.ok(r.links.some((l) => l.kind === 'lookup' && /ExampleDNS/.test(l.query)));
});

test('city mode never prints the finding title or description', async () => {
  const { C, game, items } = await load();
  for (const item of items) {
    const ctx = C.testContext({ mode: 'city' });
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.ok(!html.includes(ctx.esc(item.finding.title)), item.key);
  }
});

test('port lines: loopback reads only this computer; 0.0.0.0 reads open to the network and is odd', async () => {
  const { C, mod } = await load();
  const f = { module: 'open_ports_scan', code: 'security.open_ports_scan.listening_ports',
    data: { ports: ['Port 631 (ipp) - cupsd on 127.0.0.1', 'Port 5432 (postgresql) - postgres on 0.0.0.0', 'odd text'] } };
  const t = mod.linesOf(f, C.testContext());
  assert.strictEqual(t.kind, 'port');
  assert.match(t.lines[0].via, /631/);
  assert.match(t.lines[0].via, /cupsd/);
  assert.match(t.lines[0].to, /Only this Mac/);
  assert.ok(!t.lines[0].odd);
  assert.match(t.lines[1].to, /network/i);
  assert.ok(t.lines[1].odd);
  assert.strictEqual(t.lines[2].via, 'odd text');
  const exposed = mod.linesOf({ module: 'open_ports_scan', data: { ports: ['3306 (mysqld) listening on 0.0.0.0'] } }, C.testContext({ platform: 'win32' }));
  assert.match(exposed.lines[0].via, /3306/);
  assert.match(exposed.lines[0].via, /mysqld/);
  assert.ok(exposed.lines[0].odd);
  // Windows words.
  const loop = mod.linesOf(f, C.testContext({ platform: 'win32' }));
  assert.match(loop.lines[0].to, /Only this PC/);
});

test('connection and hosts lines read their real fields', async () => {
  const { C, mod } = await load();
  const c = mod.linesOf({ module: 'network_connections_monitor', code: 'security.network_connections_monitor.unusual_ports',
    data: { connections: ['relayd (PID 501) -> 198.51.100.23:31337'] } }, C.testContext());
  assert.match(c.lines[0].via, /relayd/);
  assert.match(c.lines[0].to, /198\.51\.100\.23/);
  assert.match(c.lines[0].to, /31337/);
  const h = mod.linesOf({ module: 'hosts_file_check', code: 'security.hosts_file_check.wellknown_domain_redirect',
    data: { entries: [{ ip: '203.0.113.7', hostname: 'mail.example' }, { ip: '127.0.0.1', hostname: 'ads.example' }] } }, C.testContext());
  assert.strictEqual(h.kind, 'hosts');
  assert.match(h.lines[0].via, /mail\.example/);
  assert.match(h.lines[0].to, /203\.0\.113\.7/);
  assert.ok(h.lines[0].odd);
  assert.match(h.lines[1].to, /blocked/i);
  assert.ok(!h.lines[1].odd);
});

test('more than four lines are folded into "and N more"', async () => {
  const { C, mod, game } = await load();
  const entries = Array.from({ length: 9 }, (_, n) => ({ ip: '203.0.113.9', hostname: `site${n}.example` }));
  const f = { module: 'hosts_file_check', code: 'security.hosts_file_check.suspicious_ip_redirect', data: { entries } };
  const t = mod.linesOf(f, C.testContext());
  assert.strictEqual(t.lines.length, 4);
  assert.strictEqual(t.more, 5);
  const item = C.makeItem(f);
  const ctx = C.testContext();
  assert.match(game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx), /and 5 more/);
});

test('hostile values inside entries, ports, servers and proxies render inert', async () => {
  const { C, game } = await load();
  for (const h of C.HOSTILE) {
    const findings = [
      { module: 'hosts_file_check', code: 'security.hosts_file_check.suspicious_ip_redirect', data: { entries: [{ ip: h, hostname: h }] } },
      { module: 'open_ports_scan', code: 'security.open_ports_scan.listening_ports', data: { ports: [h, `Port 80 (http) - ${h} on 0.0.0.0`] } },
      { module: 'dns_poisoning_check', code: 'security.dns_poisoning_check.dns_filtering_profile', data: { provider: h, servers: [h], profile_ids: [h] } },
      { module: 'network_proxy', code: 'security.network_proxy.pac_url_detected', data: { interface: h, pac_url: h } },
      { module: 'network_connections_monitor', code: 'security.network_connections_monitor.backdoor_ports', data: { connections: [h] } },
      { module: 'win_remote_access_audit', code: 'security.win_remote_access_audit.multiple_tools', data: { tools: [h, h] } },
      { module: 'wifi_security_audit', code: 'network.wifi_security_audit.open_saved', data: { networks: [h] } },
    ];
    for (const f of findings) {
      for (const mode of ['standard', 'city']) {
        const item = C.makeItem(f);
        const ctx = C.testContext({ mode });
        const r = game.research(item, ctx);
        assert.deepStrictEqual(C.checkResearch(r), []);
        const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
        assert.deepStrictEqual(C.checkInert(html), [], `${f.module} ${JSON.stringify(h)}`);
        assert.ok(!html.includes('<script'), f.module);
      }
    }
  }
});

test('research: pane per platform, lesson, look-up intent, and a didn\'t-finish line', async () => {
  const { C, game } = await load();
  const f = { module: 'suspicious_connections', code: 'security.suspicious_connections.unusual_listening_port',
    data: { process: 'helperd', port: 4444, ports: [4444], pid: 1 } };
  const mac = game.research(C.makeItem(f), C.testContext());
  assert.ok(mac.links.some((l) => l.kind === 'settings' && l.pane === 'firewall'));
  assert.ok(mac.links.some((l) => l.kind === 'lesson'));
  const look = mac.links.find((l) => l.kind === 'lookup');
  assert.ok(look && /helperd/.test(look.query) && /4444/.test(look.query));
  const win = game.research(C.makeItem(f), C.testContext({ platform: 'win32' }));
  assert.ok(win.links.some((l) => l.kind === 'settings' && l.pane === 'windows-firewall'));
  assert.ok(typeof mac.what === 'string' && mac.what.length);
  const rows = [{ label: 'Program', value: 'helperd' }];
  assert.deepStrictEqual(game.research(C.makeItem(f), C.testContext({ evidenceRows: () => rows })).rows, rows);
  for (const extra of [{ unfinished: true }, { complete: false }]) {
    const item = C.makeItem(f, extra);
    for (const mode of ['standard', 'city']) {
      const ctx = C.testContext({ mode });
      const r = game.research(item, ctx);
      assert.ok(r.unfinished);
      const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
      assert.match(html, /didn’t finish/);
    }
  }
});

test('practice: a printer port, an unknown listener and a hosts redirect, with a script that names real moves', async () => {
  const { C, game } = await load();
  const p = game.practice;
  assert.strictEqual(p.items.length, 3);
  const [printer, unknown, hosts] = p.items;
  assert.match(JSON.stringify(printer.finding.data), /631/);
  assert.match(JSON.stringify(printer.finding.data), /cups/i);
  assert.strictEqual(unknown.finding.code, 'security.suspicious_connections.unusual_listening_port');
  assert.strictEqual(hosts.finding.module, 'hosts_file_check');
  const ctx = C.testContext({ practice: true });
  for (const step of p.script) {
    assert.ok(step.item >= 0 && step.item < p.items.length);
    assert.ok(step.say.standard && step.say.city);
    assert.deepStrictEqual(C.checkCityWords(step.say.city), []);
    if (step.expect) assert.ok(ids(game.decisions(p.items[step.item], ctx)).includes(step.expect), step.expect);
  }
  const expects = p.script.filter((s) => s.expect).map((s) => [s.item, s.expect]);
  assert.deepStrictEqual(expects, [[0, 'expected'], [1, 'closer'], [2, 'odd']]);
  // Synthetic only.
  const text = JSON.stringify(p.items);
  assert.doesNotMatch(text, /\/Users\/|C:\\\\Users\\\\|([0-9a-f]{2}:){5}[0-9a-f]{2}/i);
  // A step shows in the card.
  const step = p.script[0];
  for (const mode of ['standard', 'city']) {
    const c = C.testContext({ mode, practice: true });
    const item = p.items[step.item];
    const html = game.render({ item, research: game.research(item, c), decisions: game.decisions(item, c), index: 0, total: 3, practice: true, step }, c);
    assert.ok(html.includes(c.esc(step.say[mode])));
  }
});

test('summary counts the decisions and never says all clear', async () => {
  const { C, game } = await load();
  const results = [{ decision: 'expected' }, { decision: { id: 'odd' } }, { id: 'closer' }, { decision: 'expected' }];
  const std = game.summary(results, C.testContext());
  assert.match(std, /4 lines/);
  assert.match(std, /2 expected/);
  const city = game.summary(results, C.testContext({ mode: 'city' }));
  assert.deepStrictEqual(C.checkCityWords(city), []);
  for (const s of [std, city, game.summary([], C.testContext()), game.summary(null, C.testContext({ mode: 'city' }))]) {
    assert.doesNotMatch(s, /all clear|nothing (?:wrong|found)|you(?:’|')re safe/i);
  }
});

test('the game module is pure: no DOM, storage, network or clipboard', async () => {
  const src = fs.readFileSync(path.join(MISSIONS, 'games', 'switchboard.js'), 'utf8');
  assert.doesNotMatch(src, /\b(document|window|localStorage|sessionStorage|fetch|XMLHttpRequest|navigator|require)\b/);
  assert.doesNotMatch(src, /https?:\/\//);
});

test('the stylesheet exists and styles the line diagram', () => {
  const css = fs.readFileSync(path.join(MISSIONS, 'games', 'switchboard.css'), 'utf8');
  for (const sel of ['.sb-card', '.sb-line', '.sb-node', '.sb-wire', '.sb-odd', '.sb-ask', '.sb-step']) assert.ok(css.includes(sel), sel);
  assert.match(css, /@media/);
});
