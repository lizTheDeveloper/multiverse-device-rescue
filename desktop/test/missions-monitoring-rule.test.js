'use strict';
// The one monitoring rule (missions/contract.js isMonitoringFinding / isAlertingItem), run on the
// engine's REAL serialized monitoring findings (scripts/monitoring_findings_fixture.py): the
// monitoring checks' own findings carry no removal_alert or safety note, and must still warn.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
require('../renderer/not-checked.js');
const REAL = require('./fixtures/monitoring-findings.json');

const M = path.join(__dirname, '..', 'renderer', 'missions');
const imp = (rel) => import(pathToFileURL(path.join(M, rel)).href);
const doc = (...names) => ({ schema_version: 1, platform: 'darwin', modules: names.map((n) => JSON.parse(JSON.stringify(REAL[n]))) });

test('the fixture is the engine’s own shape: no removal_alert, no safety note on the stalkerware finding', () => {
  const f = REAL.stalkerware_scan.findings[0];
  assert.strictEqual(f.code, 'security.stalkerware_scan.monitoring_software_found');
  assert.ok(!f.removal_alert);
  assert.ok(!(f.remediation && f.remediation.safety_note));
});

test('one rule: the monitoring set, removal_alert, or a safety note', async () => {
  const C = await imp('contract.js');
  for (const m of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) assert.ok(C.MONITORING_MODULES.has(m), m);
  assert.ok(C.isMonitoringFinding({ module: 'stalkerware_scan' }));
  assert.ok(C.isMonitoringFinding({ module: 'x', removal_alert: true }));
  assert.ok(C.isMonitoringFinding({ module: 'x', remediation: { safety_note: 'Careful.' } }));
  assert.ok(!C.isMonitoringFinding({ module: 'x', remediation: {} }));
  assert.ok(C.isAlertingItem({ finding: { module: 'x' }, findings: [{ module: 'x' }, { module: 'keylogger_indicators' }] }), 'any finding on the item');
  assert.ok(!C.isAlertingItem({ finding: { module: 'x' }, findings: [{ module: 'x' }] }));
});

test('standard mode: the real stalkerware finding warns before removal; a removing decision never leads', async () => {
  const T = await imp('types.js');
  const R = await imp('runner.js');
  const C = await imp('contract.js');
  const simple = (await imp('games/simple.js')).default;
  const ms = T.groupMissions(doc('stalkerware_scan'), { mode: 'standard' });
  assert.strictEqual(ms.length, 1);
  const item = ms[0].items[0];
  assert.strictEqual(item.finding.module, 'stalkerware_scan');
  assert.strictEqual(item.removal_alert, true, 'the item carries the alert');
  const ctx = C.testContext({ mode: 'standard' });
  const v = R.viewFor(R.startRun(ms[0]), simple, ctx, {});
  assert.strictEqual(v.warning, R.REMOVAL_WARNING);
  assert.deepStrictEqual(R.fixOptions(item, 'standard'), { watched: false, safety: R.REMOVAL_WARNING });
  // A game that puts a fix first: the contract flags it, the runner moves it.
  const fixFirst = { ...simple, decisions: () => [
    { id: 'rm', label: { standard: 'Remove it', city: 'Remove it' }, effect: { kind: 'fix' } },
    { id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } }] };
  assert.ok(C.checkDecisions(fixFirst.decisions(), item).some((p) => /removal warning/.test(p)));
  assert.strictEqual(R.decisionsFor(null, fixFirst, item, ctx)[0].id, 'later');
});

test('the real keylogger finding warns too (no synthetic alert)', async () => {
  const T = await imp('types.js');
  const R = await imp('runner.js');
  const ms = T.groupMissions(doc('keylogger_indicators'), { mode: 'standard' });
  const items = ms.flatMap((m) => m.items);
  assert.ok(items.length >= 1);
  for (const i of items) assert.ok(R.alerting(i), i.key);
});
