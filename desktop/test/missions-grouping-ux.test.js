'use strict';
// Little missions, UX audit group C: the alerting rule, where items land,
// and the district's mission list (missions/types.js, game/views/district.js).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
require('../renderer/not-checked.js');

const imp = (...rel) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', ...rel)).href);
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}.`, severity, data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });

test('an item warns exactly when contract.js isAlertingItem says so', async () => {
  const T = await imp('missions', 'types.js');
  const C = await imp('missions', 'contract.js');
  const doc = scan(
    mod('stalkerware_scan', [f('Watcher', 'critical', { path: '/L/w' })]),
    mod('chrome_extensions', [f('Ext flagged', 'warning', { extension_id: 'a'.repeat(32) }, { removal_alert: true }),
      f('Ext plain', 'warning', { extension_id: 'b'.repeat(32) })]),
    mod('launch_agent_audit', [f('Agent with note', 'warning', { plist: '/L/n.plist' }, { remediation: { safety_note: 'Careful.' } }),
      f('Agent plain', 'warning', { plist: '/L/p.plist' })]),
  );
  const items = T.groupMissions(doc, { mode: 'standard' }).flatMap((m) => m.items);
  assert.ok(items.length >= 5);
  for (const i of items) assert.strictEqual(i.removal_alert, C.isAlertingItem({ ...i, removal_alert: undefined }), i.finding.title);
  const by = (t) => items.find((i) => i.finding.title === t).removal_alert;
  assert.deepStrictEqual(['Watcher', 'Ext flagged', 'Ext plain', 'Agent with note', 'Agent plain'].map(by), [true, true, false, true, false]);
});

// UX audit P3: items in the wrong mission.
async function liveTable() {
  const T = await imp('missions', 'types.js');
  const I = await imp('missions', 'games', 'index.js');
  const reg = await I.loadGames();
  assert.deepStrictEqual(reg.problems, [], 'every game loads and nothing is claimed twice');
  return { T, table: T.buildTable(I.ownGames(reg)) };
}

test('a mining line in the hosts file is a Switchboard line; the mining add-on stays in the Loadout', async () => {
  const { T, table } = await liveTable();
  assert.deepStrictEqual(T.doubleClaims(table), []);
  const w = (data) => T.typeOf({ module: 'browser_cryptojacking_check', severity: 'critical', data }, table);
  assert.strictEqual(w({ check: 'mining_hosts_entry', hostname: 'pool.example', address: '203.0.113.9' }), 'switchboard');
  assert.strictEqual(w({ check: 'mining_extension', name: 'Coin thing' }), 'loadout');
  assert.strictEqual(w({}), 'loadout');
  // The base table (no games registered) says the same.
  assert.strictEqual(T.typeOf({ module: 'browser_cryptojacking_check', severity: 'critical', data: { check: 'mining_hosts_entry' } }), 'switchboard');
});

test('sleep, screen-off and Power Nap leave the Junkyard (whatever its covers say)', async () => {
  const { T, table } = await liveTable();
  for (const m of ['energy_saver_check', 'energy_settings', 'power_settings']) {
    assert.strictEqual(T.typeOf({ module: m, severity: 'warning', data: { setting: 'sleep' } }, table), 'simple', m);
    assert.strictEqual(T.typeOf({ module: m, severity: 'warning' }), 'simple', `${m} (base table)`);
    assert.ok(T.ODD_JOBS.includes(m), `${m} is in Odd Jobs on purpose`);
    assert.ok(!Object.values(table).flat().some((c) => c.module === m), `${m} is claimed by no game`);
  }
  assert.strictEqual(T.typeOf({ module: 'storage_cleanup', severity: 'warning' }, table), 'junkyard', 'the Junkyard keeps its piles');
  // A game claiming a moved module gives it up in the table: no double claim from a move.
  const t2 = T.buildTable([{ type: 'junkyard', covers: [{ module: 'energy_settings' }, { module: 'trash_cleanup' }] }]);
  assert.deepStrictEqual(t2.junkyard, [{ module: 'trash_cleanup' }]);
});

test('“ClamAV isn’t installed” is a note, still counted as a to-do; a broken ClamAV stays a lock', async () => {
  const { T, table } = await liveTable();
  const NC = globalThis.NotChecked;
  const doc = scan(
    mod('clamav_scanner', [f('You don’t have ClamAV antivirus installed', 'warning', { check: 'clamav_not_installed' }, { code: 'security.clamav_scanner.clamav_not_installed' })]),
    mod('automatic_updates', [f('Updates off', 'warning', {}, { code: 'security.automatic_updates.automatic_check' })]),
    mod('launch_agent_audit', [f('Quiet agent', 'info', { plist: '/L/q.plist' })]),
  );
  const ms = T.groupMissions(doc, { mode: 'standard', table });
  assert.deepStrictEqual(ms.filter((m) => !m.notes).flatMap((m) => m.items.map((i) => i.finding.title)), ['Updates off']);
  const notes = ms.filter((m) => m.notes).flatMap((m) => m.items);
  const clam = notes.find((i) => /ClamAV/.test(i.finding.title));
  assert.ok(clam, 'with the notes');
  assert.strictEqual(clam.severity, 'info');
  assert.strictEqual(clam.listSeverity, 'warning');
  for (const mode of ['standard', 'city']) {
    const c = T.missionCounts(T.groupMissions(doc, { mode, table }));
    const s = NC.scanCounts(doc, { mode });
    assert.deepStrictEqual([c.todo, c.notes], [s.todo, s.notes], mode);
  }
  assert.strictEqual(T.typeOf({ module: 'clamav_scanner', code: 'security.clamav_scanner.clamd_not_running', severity: 'warning' }, table), 'locks');
});

// UX audit P1-4: a big scan is still a short list.
// 41 apps with Accessibility (11 Keyring parts), 6 agents, 3 add-ons, 2 locks, 23 notes, in one district.
function bigGatehouse() {
  const apps = Array.from({ length: 41 }, (_, i) => `/Applications/App${i}.app`);
  return scan(
    mod('accessibility_permissions', [f('Apps that can control your computer', 'warning', { service: 'kTCCServiceAccessibility', apps }, { code: 'security.accessibility_permissions.granted' })]),
    mod('launch_agent_audit', Array.from({ length: 6 }, (_, i) => f(`Agent ${i}`, 'warning', { plist: `/Library/LaunchAgents/a${i}.plist` }, { code: 'security.launch_agent_audit.unsigned' }))),
    mod('chrome_extensions', Array.from({ length: 3 }, (_, i) => f(`Ext ${i}`, 'warning', { extension_id: String(i).repeat(32) }, { code: 'security.chrome_extensions.broad' }))),
    mod('automatic_updates', [f('Updates off', 'warning', {}, { code: 'security.automatic_updates.automatic_check' })]),
    mod('screen_lock_check', [f('No lock', 'warning', {}, { code: 'security.screen_lock_check.off' })]),
    mod('code_signature_audit', [f('Broken seal', 'critical', { path: '/Applications/X.app' }, { code: 'security.code_signature_audit.invalid' })]),
    mod('launchd_persistence_audit', Array.from({ length: 23 }, (_, i) => f(`Quiet ${i}`, 'info', { plist: `/L/q${i}.plist` }))),
  );
}

test('order: a type’s parts don’t push every other type down; worst first, then by IMPORTANCE', async () => {
  const T = await imp('missions', 'types.js');
  const ms = T.groupMissions(bigGatehouse(), { mode: 'standard' }).filter((m) => !m.notes);
  assert.strictEqual(ms[0].type, 'seal', 'the critical one leads');
  const firstOf = (t) => ms.findIndex((m) => m.type === t);
  assert.ok(firstOf('door') < firstOf('keyring'), 'what starts on its own before powerful access');
  // Each type's parts stay in order, so the next part follows the one before.
  for (const t of ['keyring', 'door']) {
    const parts = ms.filter((m) => m.type === t).map((m) => m.part);
    assert.deepStrictEqual(parts, [...parts].sort((a, b) => a - b), t);
  }
  assert.strictEqual(ms.filter((m) => m.type === 'keyring').length, 11);
  assert.ok(T.IMPORTANCE.indexOf('locker') < T.IMPORTANCE.indexOf('keyring'));
});

test('missionRows: a type’s parts are one row, a district’s notes batches are one row', async () => {
  const T = await imp('missions', 'types.js');
  const ms = T.groupMissions(bigGatehouse(), { mode: 'standard' });
  const rows = T.missionRows(ms);
  assert.deepStrictEqual(rows.map((r) => r.type), ['seal', 'door', 'keyring', 'loadout', 'locks', 'notes']);
  const key = rows.find((r) => r.type === 'keyring');
  assert.deepStrictEqual([key.missions.length, key.items, key.apps], [11, 41, 41]);
  const notes = rows.find((r) => r.notes);
  assert.deepStrictEqual([notes.missions.length, notes.items], [5, 23]);
  assert.strictEqual(rows.reduce((n, r) => n + r.missions.length, 0), ms.length, 'every mission is in one row');
  assert.ok(rows.every((r) => r.missions.every((m) => m.type === r.type && m.district === r.district)));
  // Parts at another severity are their own row.
  const two = T.missionRows([
    { id: 'door:g:1', type: 'door', district: 'g', severity: 'critical', items: [{}], title: { standard: 'D', city: 'D' } },
    { id: 'door:g:2', type: 'door', district: 'g', severity: 'warning', items: [{}], title: { standard: 'D', city: 'D' } },
  ]);
  assert.strictEqual(two.length, 2);
});

test('the district list: short on a big scan, says how many parts, opens the first part not done', async () => {
  const T = await imp('missions', 'types.js');
  const V = await imp('game', 'views', 'district.js');
  const C = await imp('missions', 'contract.js');
  const ms = T.groupMissions(bigGatehouse(), { mode: 'standard' });
  const done = new Set(['keyring:gatehouse:1', 'keyring:gatehouse:2']);
  const status = (m) => ({ done: done.has(m.id), decided: done.has(m.id) ? m.items.length : 0 });
  const html = V.renderMissionList(ms, { mode: 'standard', status });
  assert.strictEqual((html.match(/<li class="mx-row/g) || []).length, 6);
  const text = html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  assert.match(text, /Apps with powerful access 11 parts · 41 apps · 2 of 11 done/);
  assert.match(text, /Good to know 5 batches · 23 notes/);
  assert.match(text, /GOOD TO KNOW \(OPTIONAL\)/);
  assert.strictEqual((text.match(/GOOD TO KNOW/g) || []).length, 1, 'the notes row has no badge repeating its heading');
  assert.match(html, /data-go="mx:keyring:gatehouse:3"/, 'opens the first part not done');
  assert.match(html, /data-go="mx:notes:gatehouse:1"/);
  assert.match(text, /Browser add-ons 3 items/);
  assert.doesNotMatch(text, /PART \d+ OF/);
  // Every part done: ticked, DONE, opens the first part.
  const all = V.renderMissionList(ms.filter((m) => m.type === 'door'), { status: () => ({ done: true, decided: 1 }) });
  assert.match(all, /mx-done/);
  assert.match(all, /checked/);
  assert.match(all, /data-go="mx:door:gatehouse:1"/);
  // City words, and nothing live from a hostile title.
  const city = V.renderMissionList(ms, { mode: 'city', status });
  assert.match(city, /The Keyring/);
  assert.match(city, /SIGNAL OR NOISE \(OPTIONAL\)/);
  assert.deepStrictEqual(C.checkCityWords(city.replace(/<[^>]+>/g, ' ')), []);
  const hostile = V.renderMissionList([{ id: 'door:"x', type: 'door', district: 'g', severity: 'warning',
    items: [{}], title: { standard: '<img src=x onerror=alert(1)><script>x</script>', city: 'x' } }]);
  assert.deepStrictEqual(C.checkInert(hostile), []);
  assert.match(hostile, /data-go="mx:door:&quot;x"/);
  assert.strictEqual(V.renderMissionList([]), '');
});

test('one part in progress says how many items are decided', async () => {
  const V = await imp('game', 'views', 'district.js');
  const m = { id: 'locks:g:1', type: 'locks', district: 'g', severity: 'warning', items: [{}, {}, {}], title: { standard: 'Settings and locks', city: 'Lock Run' } };
  const text = V.renderMissionList([m], { status: () => ({ done: false, decided: 1 }) }).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
  assert.match(text, /Settings and locks 3 items · 1 of 3 decided/);
});
