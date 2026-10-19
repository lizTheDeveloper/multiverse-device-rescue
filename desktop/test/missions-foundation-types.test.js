'use strict';
// Little missions: the type table and groupMissions (missions/types.js).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const NotChecked = require('../renderer/not-checked.js');

const load = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'types.js')).href);

const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}.`, severity, data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });

// Six launch agents (door), two app permissions (keyring), one unmapped warning, notes.
function bigDoc() {
  const agents = Array.from({ length: 6 }, (_, i) => f(`Agent ${i}`, i === 5 ? 'critical' : 'warning',
    { plist: `/Library/LaunchAgents/com.example.a${i}.plist` }, { code: 'security.launch_agent_audit.unsigned' }));
  return scan(
    mod('launch_agent_audit', agents),
    mod('app_permissions', [
      f('Camera access', 'warning', { app: 'com.example.cam' }, { code: 'security.app_permissions.camera' }),
      f('Screen access', 'warning', { app: 'com.example.screen' }, { code: 'security.app_permissions.screen' }),
    ]),
    mod('battery_health', [f('Battery is worn', 'warning', { cycles: 900 })], { category: 'integrity' }),
    mod('disk_space', Array.from({ length: 7 }, (_, i) => f(`Note ${i}`, 'info', { name: `n${i}` })), { category: 'performance' }),
  );
}

test('a mission holds at most 4 items; a bigger set is split into parts, worst first', async () => {
  const T = await load();
  const ms = T.groupMissions(bigDoc(), { mode: 'standard' });
  const door = ms.filter((m) => m.type === 'door');
  assert.deepStrictEqual(door.map((m) => m.items.length), [4, 2]);
  assert.deepStrictEqual(door.map((m) => [m.part, m.of]), [[1, 2], [2, 2]]);
  assert.strictEqual(door[0].severity, 'critical');
  assert.strictEqual(door[0].items[0].finding.title, 'Agent 5', 'the critical item leads');
  for (const m of ms.filter((x) => x.type !== 'notes')) assert.ok(m.items.length <= T.MAX_ITEMS);
  for (const m of ms) assert.ok(m.title.standard && m.title.city, m.id);
});

test('order: critical first, then warnings; within a level, an alerting or fixable mission first', async () => {
  const T = await load();
  const doc = scan(
    mod('app_permissions', [f('Mic', 'warning', { app: 'com.x.mic' }, { code: 'security.app_permissions.mic' })]),
    mod('chrome_extensions', [f('Ext', 'warning', { extension_id: 'a'.repeat(32) }, { code: 'security.chrome_extensions.broad', removal_alert: true })]),
    mod('automatic_updates', [f('Updates off', 'warning', {}, { code: 'security.automatic_updates.automatic_check',
      fixable: { will_change: 'x', how_to_undo: ['y'] } })]),
    mod('launch_agent_audit', [f('Bad agent', 'critical', { plist: '/L/x.plist' }, { code: 'security.launch_agent_audit.unsigned' })]),
  );
  const ms = T.groupMissions(doc, { mode: 'standard' }).filter((m) => m.type !== 'notes');
  assert.strictEqual(ms[0].type, 'door');
  assert.deepStrictEqual(ms.slice(1, 3).map((m) => m.type).sort(), ['loadout', 'locks']);
  assert.strictEqual(ms[3].type, 'keyring');
  assert.strictEqual(ms.find((m) => m.type === 'loadout').items[0].removal_alert, true);
});

test('held items never enter a mission in city mode; standard mode keeps them', async () => {
  const T = await load();
  const doc = scan(mod('stalkerware_scan', [f('Monitoring app found', 'critical', { path: '/Applications/Watcher.app' }, { code: 'security.stalkerware_scan.found' })]),
    mod('launch_agent_audit', [f('Agent', 'warning', { plist: '/L/a.plist' })]));
  const city = T.groupMissions(doc, { mode: 'city' });
  assert.ok(city.every((m) => m.items.every((i) => i.finding.module !== 'stalkerware_scan')));
  const std = T.groupMissions(doc, { mode: 'standard' });
  const it = std.flatMap((m) => m.items).find((i) => i.finding.module === 'stalkerware_scan');
  assert.ok(it, 'standard mode has no held');
  assert.strictEqual(T.typeOf(it.finding), 'simple');
});

test('info items go to the notes missions only, in batches of 5 per district', async () => {
  const T = await load();
  const ms = T.groupMissions(bigDoc(), { mode: 'standard' });
  const notes = ms.filter((m) => m.type === 'notes');
  assert.deepStrictEqual(notes.map((m) => m.items.length), [5, 2]);
  assert.ok(notes.every((m) => m.notes === true && m.district === 'engine-room'));
  assert.ok(ms.filter((m) => m.type !== 'notes').every((m) => m.items.every((i) => i.severity !== 'info')));
  assert.strictEqual(ms[ms.length - 1].type, 'notes', 'notes come after the to-dos');
});

test('marked-as-yours items stay out unless their mark is stale', async () => {
  const T = await load();
  const doc = scan(mod('launch_agent_audit', [
    f('Mine', 'info', { plist: '/L/m.plist', marked_by_user: true, original_severity: 'warning' }),
    f('Stale', 'info', { plist: '/L/s.plist', marked_by_user: true, mark_stale: true, original_severity: 'warning' }),
    f('Changed since', 'warning', { plist: '/L/c.plist', mark_stale: true, known_item_id: 'k' }),
  ]));
  const titles = T.groupMissions(doc, { mode: 'standard' }).flatMap((m) => m.items.map((i) => i.finding.title));
  assert.ok(!titles.includes('Mine'));
  assert.ok(titles.includes('Stale') && titles.includes('Changed since'));
});

test('mission counts equal the list’s numbers (scanCounts.todo and .notes), in both modes', async () => {
  const T = await load();
  const doc = bigDoc();
  doc.modules.push(mod('keylogger_indicators', [f('Keyboard watcher', 'critical', { apps: ['/Applications/K.app'] }, { code: 'security.keylogger_indicators.known_keyloggers' })]));
  doc.modules.push(mod('launch_agent_audit_2', [f('Same thing', 'warning', { plist: '/L/a.plist' }, { same_key: 'k1' })]));
  doc.modules.push(mod('launchd_persistence_audit', [f('Same thing', 'warning', { plist: '/L/a.plist' }, { same_key: 'k1' })]));
  for (const mode of ['standard', 'city']) {
    const c = T.missionCounts(T.groupMissions(doc, { mode }));
    const s = NotChecked.scanCounts(doc, { mode });
    assert.strictEqual(c.todo, s.todo, mode);
    assert.strictEqual(c.notes, s.notes, mode);
  }
});

test('missions are one type within one district; the district is the check’s category', async () => {
  const T = await load();
  const ms = T.groupMissions(bigDoc(), { mode: 'standard' });
  const odd = ms.find((m) => m.type === 'simple');
  assert.strictEqual(odd.district, 'foundations');
  assert.ok(ms.every((m) => m.items.every((i) => T.typeOf(i.finding) === m.type || m.type === 'notes')));
});

test('firewall is split: "off" goes to Lock Run, rules and stealth to the Switchboard; baseline items by code', async () => {
  const T = await load();
  const fw = (code) => ({ module: 'firewall_audit', code, severity: 'warning' });
  assert.strictEqual(T.typeOf(fw('security.firewall_audit.global_state')), 'locks');
  assert.strictEqual(T.typeOf(fw('security.firewall_audit.global_state_unknown')), 'locks');
  assert.strictEqual(T.typeOf(fw('security.firewall_audit.stealth_mode')), 'switchboard');
  assert.strictEqual(T.typeOf({ module: 'firewall_rules_audit', code: 'security.firewall_rules_audit.alf_disabled', severity: 'warning' }), 'locks');
  assert.strictEqual(T.typeOf({ module: 'firewall_rules_audit', code: 'security.firewall_rules_audit.too_many_apps', severity: 'warning' }), 'switchboard');
  const sb = (code) => T.typeOf({ module: 'security_baseline_diff', code: `security.security_baseline_diff.${code}`, severity: 'warning' });
  assert.deepStrictEqual(['new_persistence', 'new_browser_extension', 'new_listening_port', 'protection_disabled'].map(sb),
    ['door', 'loadout', 'switchboard', 'locks']);
  assert.strictEqual(T.typeOf({ module: 'win_autoruns_audit', severity: 'warning' }), 'door', 'Windows equivalents are mapped');
  assert.strictEqual(T.typeOf({ module: 'nobody_knows_this', severity: 'warning' }), 'simple');
  assert.strictEqual(T.typeOf({ module: 'launch_agent_audit', severity: 'info' }), 'notes');
});

test('the base table claims nothing twice; a double claim is caught', async () => {
  const T = await load();
  assert.deepStrictEqual(T.doubleClaims(T.buildTable()), []);
  const bad = T.buildTable([
    { type: 'door', covers: [{ module: 'login_items' }] },
    { type: 'keyring', covers: [{ module: 'login_items' }] },
  ]);
  assert.ok(T.doubleClaims(bad).some((p) => /login_items/.test(p)));
  const overlap = T.buildTable([
    { type: 'door', covers: [{ module: 'x_mod', codes: ['security.x_mod.a'] }] },
    { type: 'seal', covers: [{ module: 'x_mod', codes: ['security.x_mod.a_b'] }] },
  ]);
  assert.ok(T.doubleClaims(overlap).some((p) => /x_mod/.test(p)));
});

test('a registered game’s covers replace its type’s entry', async () => {
  const T = await load();
  const table = T.buildTable([{ type: 'door', covers: [{ module: 'launch_agent_audit' }, { module: 'win_autorun' }] }]);
  assert.strictEqual(T.typeOf({ module: 'launch_agent_audit', severity: 'warning' }, table), 'door');
  assert.strictEqual(T.typeOf({ module: 'cron_jobs_audit', severity: 'warning' }, table), 'simple', 'no longer claimed by door');
  assert.strictEqual(T.typeOf({ module: 'app_permissions', severity: 'warning' }, table), 'keyring', 'other types keep the base');
});

// Every engine module that can warn on macOS is mapped, or listed as Odd Jobs on purpose.
test('every macOS module that can raise a warning is mapped or listed in ODD_JOBS', async () => {
  const T = await load();
  const root = path.join(__dirname, '..', '..', 'modules');
  const missing = [];
  for (const cat of fs.readdirSync(root)) {
    const dir = path.join(root, cat);
    if (!fs.statSync(dir).isDirectory()) continue;
    for (const name of fs.readdirSync(dir)) {
      const file = path.join(dir, name, '__init__.py');
      if (!fs.existsSync(file)) continue;
      const src = fs.readFileSync(file, 'utf8');
      if (!/^\s+platforms\s*=.*DARWIN/m.test(src) || !/Severity\.(CRITICAL|WARNING)/.test(src)) continue;
      if (T.typeOf({ module: name, severity: 'warning' }) === 'simple' && !T.ODD_JOBS.includes(name)) missing.push(name);
    }
  }
  assert.deepStrictEqual(missing, []);
  for (const name of T.ODD_JOBS) assert.strictEqual(T.typeOf({ module: name, severity: 'warning' }), 'simple', `${name} is listed but mapped`);
});

// Rulings from the game tracks (contract.js header).
test('R2: an item from a check that didn’t finish carries unfinished: true', async () => {
  const T = await load();
  const doc = scan(mod('launch_agent_audit', [f('Agent', 'warning', { plist: '/L/a.plist' })], { complete: false }),
    mod('cron_jobs_audit', [f('Job', 'warning', { path: '/c' })]));
  const items = T.groupMissions(doc, { mode: 'standard' }).flatMap((m) => m.items);
  assert.strictEqual(items.find((i) => i.finding.title === 'Agent').unfinished, true);
  assert.strictEqual(items.find((i) => i.finding.title === 'Job').unfinished, false);
});

test('R4: keyring findings become one item per app, each with its keys; counts stay the list’s', async () => {
  const T = await load();
  const doc = scan(mod('app_permissions', [
    f('Camera access', 'warning', { service: 'kTCCServiceCamera', apps: ['/Applications/A.app', '/Applications/B.app'] }, { code: 'security.app_permissions.camera' }),
    f('Screen access', 'warning', { service: 'kTCCServiceScreenCapture', apps: ['/Applications/A.app'] }, { code: 'security.app_permissions.screen' }),
    f('Mic, nobody named', 'warning', {}, { code: 'security.app_permissions.mic' }),
  ]));
  const ms = T.groupMissions(doc, { mode: 'standard' }).filter((m) => m.type === 'keyring');
  const items = ms.flatMap((m) => m.items);
  const a = items.find((i) => i.app && i.app.subject === '/Applications/A.app');
  assert.deepStrictEqual(a.keys.map((k) => k.permission), ['kTCCServiceCamera', 'kTCCServiceScreenCapture']);
  assert.strictEqual(a.findings.length, 2, 'the original findings stay on the item');
  assert.ok(items.find((i) => i.app && i.app.subject === '/Applications/B.app'));
  assert.ok(items.find((i) => !i.app && i.finding.title === 'Mic, nobody named'));
  assert.strictEqual(T.missionCounts(ms).todo, NotChecked.scanCounts(doc, { mode: 'standard' }).todo);
});

test('notes: the wildcard cover is never a double claim; odd notes become items of their type', async () => {
  const T = await load();
  const table = T.buildTable([{ type: 'notes', covers: [{ module: '*', severities: ['info'] }] }, { type: 'door', covers: [{ module: 'launch_agent_audit' }] }]);
  assert.deepStrictEqual(T.doubleClaims(table), []);
  const doc = scan(mod('launch_agent_audit', [f('Quiet agent', 'info', { plist: '/L/q.plist' }), f('Other', 'info', { plist: '/L/o.plist' })]));
  const key = NotChecked.displayItems(doc).info[0].key;
  const ms = T.groupMissions(doc, { mode: 'standard', table, odd: new Set([key]) });
  assert.strictEqual(ms.find((m) => m.type === 'door').items[0].finding.title, 'Quiet agent');
  assert.strictEqual(ms.find((m) => m.type === 'notes').items.length, 1);
  const c = T.missionCounts(ms);
  assert.deepStrictEqual(c, { todo: 0, notes: 2 }, 'an odd note still counts as a note');
  const batched = T.groupMissions(doc, { mode: 'standard', batchNotes: (items) => [{ area: 'gatehouse', part: 1, parts: 1, items }] });
  assert.strictEqual(batched.find((m) => m.type === 'notes').items.length, 2, 'the notes game’s own batches are used');
});

test('R8: a Lock Run check that couldn’t check is a Lock Run item, not a note', async () => {
  const T = await load();
  const doc = scan(mod('firewall_audit', [f('Firewall state unknown', 'info', {}, { code: 'security.firewall_audit.global_state_unknown' })]));
  const ms = T.groupMissions(doc, { mode: 'standard' });
  assert.deepStrictEqual(ms.map((m) => m.type), ['locks']);
  assert.strictEqual(T.missionCounts(ms).notes, NotChecked.scanCounts(doc).notes);
});

test('R9: a cover can narrow by data.check for a module with no codes', async () => {
  const T = await load();
  const table = T.buildTable([{ type: 'seal', covers: [{ module: 'win_driver_check', checks: ['unsigned_drivers'] }] }]);
  assert.strictEqual(T.typeOf({ module: 'win_driver_check', severity: 'warning', data: { check: 'unsigned_drivers' } }, table), 'seal');
  assert.strictEqual(T.typeOf({ module: 'win_driver_check', severity: 'warning', data: { check: 'old_driver' } }, table), 'simple');
  assert.ok(T.doubleClaims(T.buildTable([{ type: 'seal', covers: [{ module: 'm', checks: ['a'] }] }, { type: 'door', covers: [{ module: 'm', checks: ['a'] }] }])).length);
});
