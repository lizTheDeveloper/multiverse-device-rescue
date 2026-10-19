'use strict';
// Every game: the default (first) decision never waves through a critical or
// warning item. "Mine", "Expected", "Keep", "Let it in", "Looks right" (any
// keep or mark effect) lead only on a note; on anything worse Look closer or
// the safe move leads (controller ruling P1-6).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const FIXTURES = path.join(__dirname, 'fixtures', 'missions');
const TYPES = ['door', 'keyring', 'loadout', 'seal', 'switchboard', 'locker', 'locks', 'junkyard', 'notes', 'simple'];

async function load() {
  const C = await import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
  const games = {};
  for (const t of TYPES) games[t] = (await import(pathToFileURL(path.join(MISSIONS, 'games', `${t}.js`)).href)).default;
  return { C, games };
}

// Every finding in the synthetic mission fixtures, whatever the file's shape.
function fixtureFindings() {
  const out = [];
  const walk = (v, module) => {
    if (Array.isArray(v)) { v.forEach((x) => walk(x, module)); return; }
    if (!v || typeof v !== 'object') return;
    if (typeof v.title === 'string' && (typeof v.module === 'string' || module) && (v.severity || v.data)) {
      const { expect, platform, id, area, ...f } = v;
      out.push({ module, ...f });
      return;
    }
    if (typeof v.name === 'string' && Array.isArray(v.findings)) { walk(v.findings, v.name); return; }
    for (const k of Object.keys(v)) walk(v[k], module);
  };
  for (const file of fs.readdirSync(FIXTURES).filter((x) => x.endsWith('.json'))) walk(JSON.parse(fs.readFileSync(path.join(FIXTURES, file), 'utf8')), null);
  return out;
}

const wavesThrough = (d) => !!(d && d.effect && (d.effect.kind === 'keep' || d.effect.kind === 'mark'));
const claims = (game, f) => (game.covers || []).some((c) => c.module === f.module);

test('no game leads with a keep or mark on a critical or warning item (fixtures, practice, both modes)', async () => {
  const { C, games } = await load();
  const findings = fixtureFindings();
  assert.ok(findings.length > 100, `found ${findings.length} fixture findings`);
  let checked = 0;
  for (const [type, game] of Object.entries(games)) {
    const items = [...findings.filter((f) => claims(game, f)).map((f) => C.makeItem(f)), ...game.practice.items];
    for (const item of items) {
      for (const severity of ['critical', 'warning']) {
        const it = { ...item, severity, finding: { ...item.finding, severity } };
        for (const mode of ['standard', 'city']) {
          for (const platform of ['darwin', 'win32']) {
            const d = game.decisions(it, C.testContext({ mode, platform }));
            assert.ok(!wavesThrough(d[0]), `${type} ${item.key} (${severity}, ${mode}, ${platform}) leads with ${d[0] && d[0].id}`);
            checked += 1;
          }
        }
      }
    }
    assert.deepStrictEqual(C.runContractChecks(game, items), [], type);
  }
  assert.ok(checked > 400, `checked ${checked}`);
});

test('on a note, the games that keep or mark still lead with it (nothing changes for info)', async () => {
  const { C, games } = await load();
  const note = (module, data, extra = {}) => C.makeItem({ module, severity: 'info', title: 'A note', description: 'x', data, ...extra });
  const ctx = C.testContext();
  assert.strictEqual(games.door.decisions(note('launch_agent_audit', { label: 'com.example.x', program: '/Applications/X.app/Contents/MacOS/x' }), ctx)[0].id, 'mine');
  assert.strictEqual(games.switchboard.decisions(note('open_ports_scan', { check: 'listening_ports', ports: ['Port 631 (ipp) - cupsd on 127.0.0.1'] }), ctx)[0].id, 'expected');
  assert.strictEqual(games.junkyard.decisions(note('trash_cleanup', { type: 'large_trash', size_bytes: 1024 }), ctx)[0].id, 'keep');
});

test('switchboard: a redirected bank name leads with "close it"; an unknown port leads with Look closer; Expected is last', async () => {
  const { C, games } = await load();
  const g = games.switchboard;
  const ctx = C.testContext();
  const bank = C.makeItem({ module: 'hosts_file_check', code: 'security.hosts_file_check.bank_domain_redirect', severity: 'critical', title: 'A bank website name is being redirected', description: 'x',
    data: { check: 'bank_domain_redirect', count: 1, entries: [{ ip: '203.0.113.7', hostname: 'mybank.example' }] } });
  assert.deepStrictEqual(g.decisions(bank, ctx).map((d) => d.id), ['odd', 'closer', 'expected']);
  const blocked = C.makeItem({ module: 'hosts_file_check', code: 'security.hosts_file_check.custom_entries', severity: 'warning', title: 'Custom hosts entries', description: 'x',
    data: { entries: [{ ip: '0.0.0.0', hostname: 'ads.example' }] } });
  assert.deepStrictEqual(g.decisions(blocked, ctx).map((d) => d.id), ['closer', 'odd', 'expected']);
  const port = C.makeItem({ module: 'suspicious_connections', code: 'security.suspicious_connections.malware_port', severity: 'critical', title: 'A connection on port 31337', description: 'x',
    data: { check: 'malware_port', process: 'relayd', remote_address: '198.51.100.23', remote_port: 31337 } });
  assert.deepStrictEqual(g.decisions(port, ctx).map((d) => d.id), ['closer', 'odd', 'expected']);
  for (const mode of ['standard', 'city']) assert.strictEqual(g.decisions(bank, C.testContext({ mode }))[0].effect.kind === 'fix', false);
});
