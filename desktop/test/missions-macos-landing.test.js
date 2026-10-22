'use strict';
// Where every macOS check that can raise a to-do (a critical or warning
// finding) lands: which mini-game type. The table is checked in
// (fixtures/missions/macos-landing.json) so a change in where something lands
// shows up in review; only checks listed on purpose (types.js ODD_JOBS) may land
// in Odd Jobs ('simple'). Regenerate after an intended change with:
//   UPDATE_LANDING=1 node --test test/missions-macos-landing.test.js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
require('../renderer/not-checked.js');

const MODULES = path.join(__dirname, '..', '..', 'modules');
const SNAPSHOT = path.join(__dirname, 'fixtures', 'missions', 'macos-landing.json');
const NO_CODE = '(no code)';
const imp = (rel) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', rel)).href);

// Every macOS engine module and the codes of its critical/warning findings,
// read from its source: each Finding( … ) block with Severity.CRITICAL or
// Severity.WARNING gives its literal code, or NO_CODE when it has none.
// A computed severity: the block passes `severity=<name>`, and an assignment to that name (`name = …`, a
// statement, not a keyword argument) between the Finding( before and this one can be CRITICAL or WARNING
// (remote_access_tools' tool_found: INFO when marked quiet, else WARNING; an if/else of INFO and CRITICAL).
function computedTodo(block, before) {
  const v = /\bseverity=([a-z_][a-z0-9_]*)\b/.exec(block.split(/\bFinding\(|\bCheckResult\(/)[0]);
  if (!v) return false;
  return [...before.matchAll(new RegExp(`^\\s*${v[1]}\\s+=\\s+(.+)$`, 'gm'))].some((a) => /Severity\.(?:CRITICAL|WARNING)/.test(a[1]));
}

function macosTodoChecks() {
  const out = {};
  for (const cat of fs.readdirSync(MODULES)) {
    const cdir = path.join(MODULES, cat);
    if (!fs.statSync(cdir).isDirectory()) continue;
    for (const dir of fs.readdirSync(cdir)) {
      const mdir = path.join(cdir, dir);
      const init = path.join(mdir, '__init__.py');
      if (!fs.existsSync(init)) continue;
      const head = fs.readFileSync(init, 'utf8');
      const name = (/^\s+name = "([a-z0-9_]+)"/m.exec(head) || [])[1];
      const platforms = (/platforms = \[([^\]]*)\]/.exec(head) || [])[1] || '';
      if (!name || !/Platform\.DARWIN/.test(platforms)) continue;
      const src = fs.readdirSync(mdir).filter((f) => f.endsWith('.py')).map((f) => fs.readFileSync(path.join(mdir, f), 'utf8')).join('\n');
      const codes = new Set();
      const parts = src.split(/\bFinding\(/);
      const blocks = parts.slice(1);
      blocks.forEach((b, i) => {
        if (!/Severity\.(?:CRITICAL|WARNING)/.test(b.split(/\bFinding\(|\bCheckResult\(/)[0])
          && !computedTodo(b, parts[i])) return;
        const m = /\bcode="([a-z0-9_.]+)"/.exec(b);
        codes.add(m ? m[1] : NO_CODE);
      });
      if (!codes.size && /Severity\.(?:CRITICAL|WARNING)/.test(src)) codes.add(NO_CODE);
      if (codes.size) out[name] = [...codes].sort();
    }
  }
  return out;
}

async function landing() {
  const T = await imp('types.js');
  const I = await imp('games/index.js');
  const reg = await I.loadGames();
  assert.deepStrictEqual(reg.problems, [], 'every game loads and nothing is claimed twice');
  const table = T.buildTable(I.ownGames(reg));
  const checks = macosTodoChecks();
  const out = {};
  for (const name of Object.keys(checks).sort()) {
    out[name] = {};
    for (const code of checks[name]) {
      out[name][code] = T.typeOf({ module: name, severity: 'warning', ...(code === NO_CODE ? {} : { code }), data: {} }, table);
    }
  }
  return { out, T };
}

test('every macOS check that can raise a to-do lands in a mini-game; only intentional ones in Odd Jobs', async () => {
  const { out, T } = await landing();
  assert.ok(Object.keys(out).length > 100, 'the engine’s macOS modules were read');
  if (process.env.UPDATE_LANDING === '1') fs.writeFileSync(SNAPSHOT, `${JSON.stringify(out, null, 1)}\n`);
  const odd = new Set(T.ODD_JOBS);
  const unintended = [];
  for (const [m, codes] of Object.entries(out)) for (const [c, type] of Object.entries(codes)) if (type === 'simple' && !odd.has(m)) unintended.push(`${m} ${c}`);
  assert.deepStrictEqual(unintended, [], 'these land in Odd Jobs without being listed in types.js ODD_JOBS');
  assert.deepStrictEqual(out, JSON.parse(fs.readFileSync(SNAPSHOT, 'utf8')), 'where checks land changed: review, then regenerate the table');
});

test('the integration moves: storage piles to the Junkyard; firewall stealth, SIP, Secure Boot, Safe Mode, ClamAV and browser settings to Lock Run', async () => {
  const { out } = await landing();
  assert.deepStrictEqual(Object.values(out.temp_file_scanner), ['junkyard']);
  assert.strictEqual(out.firewall_audit['security.firewall_audit.stealth_mode'], 'locks');
  assert.strictEqual(out.firewall_rules_audit['security.firewall_rules_audit.stealth_disabled'], 'locks');
  assert.strictEqual(out.firewall_rules_audit['security.firewall_rules_audit.alf_disabled'], 'locks');
  assert.strictEqual(out.firewall_rules_audit['security.firewall_rules_audit.too_many_apps'], 'switchboard');
  assert.strictEqual(out.rootkit_check['security.rootkit_check.sip_disabled'], 'locks');
  assert.strictEqual(out.rootkit_check['security.rootkit_check.hidden_processes'], 'locker');
  // ClamAV missing is a note (an optional extra scanner); a ClamAV that's there but not working is a lock.
  for (const c of Object.keys(out.clamav_scanner)) assert.strictEqual(out.clamav_scanner[c], /clamav_not_installed$/.test(c) ? 'notes' : 'locks', c);
  // Sleep, screen-off, Power Nap and wake are settings, not clutter: Lock Run's sleep locks.
  for (const m of ['energy_saver_check', 'energy_settings', 'power_settings', 'clamshell_mode']) assert.deepStrictEqual(Object.values(out[m]), ['locks'], m);
  for (const c of Object.keys(out.browser_privacy_check)) assert.strictEqual(out.browser_privacy_check[c], 'locks', c);
  assert.deepStrictEqual(Object.values(out.default_browser), ['locks']);
  const T = await imp('types.js');
  const I = await imp('games/index.js');
  const table = T.buildTable(I.ownGames(await I.loadGames()));
  const w = (module, code) => T.typeOf({ module, code, severity: 'warning' }, table);
  assert.strictEqual(w('win_rootkit_check', 'security.win_rootkit_check.secure_boot_disabled'), 'locks');
  assert.strictEqual(w('win_rootkit_check', 'security.win_rootkit_check.unsigned_drivers'), 'seal');
  assert.strictEqual(w('win_rootkit_check', 'security.win_rootkit_check.hidden_services'), 'locker');
  assert.strictEqual(w('win_malware_indicators', 'security.win_malware_indicators.safe_mode_disabled'), 'locks');
  assert.strictEqual(w('win_malware_indicators', 'security.win_malware_indicators.malware_folder'), 'locker');
  assert.strictEqual(w('win_temp_files', undefined), 'junkyard');
});

test('the moved items play in their new games: contract checks, the right lock and its switch', async () => {
  const C = await imp('contract.js');
  const I = await imp('games/index.js');
  const reg = await I.loadGames();
  const item = (module, code, data = {}, severity = 'warning') => C.makeItem({ module, ...(code ? { code: `security.${module}.${code}` } : {}), title: `${module} ${code}`, description: 'x', severity, data });
  const moved = {
    locks: [item('firewall_audit', 'stealth_mode', { check: 'stealth_mode' }), item('firewall_rules_audit', 'stealth_disabled', { check: 'stealth_disabled' }),
      item('firewall_rules_audit', 'alf_disabled', { check: 'alf_disabled' }, 'critical'), item('rootkit_check', 'sip_disabled', { check: 'sip_status' }, 'critical'),
      item('win_rootkit_check', 'secure_boot_disabled', { check: 'secure_boot_disabled' }, 'critical'), item('win_malware_indicators', 'safe_mode_disabled', { check: 'safe_mode_disabled' }),
      item('clamav_scanner', 'clamav_not_installed', { check: 'clamav_not_installed' }), item('clamav_scanner', 'clamav_outdated_definitions', {}, 'critical'),
      item('browser_privacy_check', 'fraud_warning_disabled', { browser: 'Safari' }), item('default_browser', null, { check: 'browser_not_installed', browser_id: 'com.example.gone' })],
    junkyard: [item('temp_file_scanner', null, { type: 'total_waste', size_bytes: 5e9, size_formatted: '4.7 GB' })],
    locker: [item('suspicious_processes', 'known_malware', { check: 'known_malware', process: 'evil', pid: 7 }, 'critical'),
      item('suspicious_processes', 'suspicious_paths', { check: 'suspicious_paths', path: '/tmp/x' })],
    switchboard: [item('airdrop_security_check', 'airdrop_mode_everyone', { check: 'airdrop_mode_everyone' })],
    door: [item('system_extensions', 'unusual_state', { check: 'unusual_state', bundle_id: 'com.example.ext' })],
  };
  for (const [type, items] of Object.entries(moved)) {
    assert.ok(reg.own.has(type), type);
    assert.deepStrictEqual(C.runContractChecks(reg.games[type], items), [], type);
  }
  const L = await imp('games/locks.js');
  const lock = (i) => L.lockOf(moved.locks[i].finding);
  assert.deepStrictEqual(moved.locks.map((_, i) => lock(i)),
    ['stealth', 'stealth', 'firewall', 'sip', 'secure-boot', 'safe-mode', 'scanner', 'scanner', 'browser-safety', 'default-browser']);
  const ctx = C.testContext();
  assert.deepStrictEqual(L.research(moved.locks[0], ctx).links[0], { kind: 'settings', pane: 'firewall' });
  assert.match(L.research(moved.locks[0], ctx).where, /stealth mode/);
  // No pane to open: Show me how, with the steps.
  const sip = L.decisions(moved.locks[3], ctx)[0];
  assert.strictEqual(sip.effect.kind, 'closer');
  assert.ok(sip.effect.checklist.some((s) => /csrutil enable/.test(s)));
  const win = L.decisions(moved.locks[4], C.testContext({ platform: 'win32' }))[0];
  assert.ok(win.effect.checklist.some((s) => /Secure Boot/.test(s)));
  for (const it of moved.locks) {
    const html = L.render({ item: it, research: L.research(it, C.testContext({ mode: 'city' })), index: 0, total: 1 }, C.testContext({ mode: 'city' }));
    assert.deepStrictEqual(C.checkCityWords(html.replace(/<p class="lr-title">[^<]*<\/p>/, '')), []);
  }
});
