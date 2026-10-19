// One count of the scan for both views (renderer/not-checked.js scanCounts):
// LAST SWEEP's checks, the critical/warning chips (held left out in city),
// didn't-finish per district and in total, and the number of items. The
// fixtures are the recorded audit replays (full: a real Mac scan; held: the
// same plus monitoring software found).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const NC = require('../renderer/not-checked.js');

const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', f), 'utf8'));

test('every check is counted once; couldn’t-run, didn’t-finish and not-started never overlap', async () => {
  const { districtIdFor } = await import('../renderer/game/findings-to-city.js');
  for (const file of ['replay-full.json', 'replay-errors.json', 'replay-held.json']) {
    const doc = load(file);
    const sum = NC.notCheckedSummary(doc);
    for (const mode of ['standard', 'city']) {
      const c = NC.scanCounts(doc, { mode, districtOf: districtIdFor });
      assert.strictEqual(c.checks, doc.modules.length, `${file} ${mode}: one per check, the iPhone scan once`);
      assert.strictEqual(c.ran, c.checks - c.couldntRun - c.notStarted);
      assert.deepStrictEqual([c.couldntRun, c.unfinished, c.notStarted, c.partly],
        [sum.couldntRun, sum.unfinished, sum.notStarted, sum.partly], 'the same parts as the top line');
      assert.strictEqual(c.didntFinish, c.couldntRun + c.unfinished);
      const d = Object.values(c.byDistrict);
      const total = (k) => d.reduce((n, x) => n + x[k], 0);
      for (const k of ['couldntRun', 'unfinished', 'notStarted', 'critical', 'warning', 'items']) {
        assert.strictEqual(total(k), c[k], `${file} ${mode}: districts add up (${k})`);
      }
      assert.strictEqual(total('notFully'), c.notFully, 'each not-fully-checked check in one district');
      assert.ok(c.notFully <= c.couldntRun + c.unfinished + c.notStarted + c.partly);
      assert.ok(c.items <= c.critical + c.warning);
    }
  }
});

test('a held monitoring finding is counted in Plain and left out of every city number', () => {
  const doc = load('replay-held.json');
  const plain = NC.scanCounts(doc);
  const city = NC.scanCounts(doc, { mode: 'city' });
  assert.ok(plain.held > 0 && city.held === plain.held);
  const heldSev = { critical: 0, warning: 0, info: 0 };
  for (const m of doc.modules) for (const f of m.findings || []) if (NC.isHeld(f, m.name)) heldSev[NC.shownSeverity(f)] += 1;
  for (const k of ['critical', 'warning', 'info']) assert.strictEqual(plain[k] - city[k], heldSev[k], k);
  // Without the held finding, both views give the same numbers.
  const without = { ...doc, modules: doc.modules.map((m) => ({ ...m, findings: (m.findings || []).filter((f) => !NC.isHeld(f, m.name)) })) };
  const a = NC.scanCounts(without);
  const b = NC.scanCounts(without, { mode: 'city' });
  assert.deepStrictEqual(a, b);
  // ...and the city's numbers with it are those numbers.
  for (const k of ['critical', 'warning', 'info', 'items', 'checks', 'couldntRun', 'unfinished', 'notStarted']) {
    assert.strictEqual(city[k], b[k], k);
  }
});

test('one thing seen by several checks is one item (same_key); monitoring findings never merge', () => {
  const mod = (name, findings, category = 'performance') => ({ name, category, status: 'ok', supported: true, findings });
  const vol = (t) => ({ title: t, severity: 'warning', category: 'performance', same_key: 'audio:volume_zero', data: {} });
  const doc = { modules: [
    mod('audio_config', [vol('Your volume is set very low (0%)')]),
    mod('audio_troubleshoot', [vol('Your Mac’s volume is set to zero')]),
    mod('firewall_audit', [{ title: 'Your Mac responds to network pings', severity: 'warning', category: 'network', data: { check: 'stealth_mode' } }], 'network'),
    mod('stalkerware_scan', [
      { title: 'mSpy is on this computer', severity: 'critical', category: 'security', code: 'security.stalkerware_scan.found', data: { name: 'mSpy' } },
      { title: 'FlexiSpy is on this computer', severity: 'critical', category: 'security', code: 'security.stalkerware_scan.found', data: { name: 'FlexiSpy' } },
    ], 'security'),
    mod('disk_space', [{ title: 'Disk almost full', severity: 'critical', category: 'performance', data: {} }]),
  ] };
  const c = NC.scanCounts(doc);
  assert.strictEqual(c.warning, 3 + 1, 'a non-alarm critical shows as a warning (the list’s rule)');
  assert.strictEqual(c.critical, 2);
  assert.strictEqual(c.items, 1 + 1 + 2 + 1);
  assert.strictEqual(NC.itemKey(vol('a'), 'audio_config'), NC.itemKey(vol('b'), 'audio_troubleshoot'));
  const city = NC.scanCounts(doc, { mode: 'city' });
  assert.strictEqual(city.critical, 0, 'held criticals never reach a city count');
  assert.strictEqual(city.items, 3);
  assert.strictEqual(city.held, 2);
});

test('a scan without modules counts nothing and never throws', () => {
  for (const doc of [null, {}, { modules: null }, { modules: [null, { name: 'x' }] }]) {
    const c = NC.scanCounts(doc);
    assert.strictEqual(c.critical + c.warning + c.items, 0);
  }
});
