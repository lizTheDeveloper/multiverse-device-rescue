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
