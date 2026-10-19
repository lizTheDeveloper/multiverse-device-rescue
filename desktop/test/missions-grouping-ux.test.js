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
