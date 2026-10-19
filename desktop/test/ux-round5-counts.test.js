// UX round 5 (C5): one count source for Plain and the city. The fixtures are
// synthetic scans shaped like the round-4 audit's replays (ux6: the full scan, the same with monitoring
// software, an errors scan and a nearly clean one; fixtures/make-ux6-fixtures.py), with same_key
// and titles from the current engine.
//
// What each number means (NotChecked.scanCounts):
//   todo          items to look at: critical + warning, duplicates merged
//                 (displayItems). Never counts checks.
//   notes         good-to-know items (info), duplicates merged.
//   markedItems   items marked as yours.  heldItems  held monitoring items.
//   couldntCheck  checks that checked nothing: couldn't run, never reached
//                 (a stopped checkup), or waiting for the go-ahead.
//   unfinished    checks that ran but didn't finish ("didn't finish").
//   notChecked    couldntCheck + unfinished.  partly  part-checked notes.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const NC = require('../renderer/not-checked.js');

const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', f), 'utf8'));
const FIXTURES = ['ux6-full.json', 'ux6-held.json', 'ux6-errors.json', 'ux6-clean.json'];
const BUCKETS = ['critical', 'warning', 'info', 'marked', 'held'];
const titles = (item) => item.findings.map((f) => f.title);

test('every finding is in exactly one item, and the counts are the lists’ lengths', async () => {
  const { districtIdFor } = await import('../renderer/game/findings-to-city.js');
  for (const file of FIXTURES) {
    const doc = load(file);
    for (const mode of ['standard', 'city']) {
      const list = NC.displayItems(doc, { mode });
      const c = NC.scanCounts(doc, { mode, districtOf: districtIdFor });
      const findings = doc.modules.flatMap((m) => (m.findings || []).filter((f) => !NC.isPartlyChecked(f)));
      assert.strictEqual(BUCKETS.reduce((n, b) => n + list[b].reduce((k, it) => k + it.findings.length, 0), 0), findings.length, `${file} ${mode}`);
      const keys = BUCKETS.flatMap((b) => list[b].map((it) => it.key));
      assert.strictEqual(new Set(keys).size, keys.length, 'one item per key');
      assert.strictEqual(c.todo, list.critical.length + list.warning.length);
      assert.strictEqual(c.notes, list.info.length);
      assert.strictEqual(c.markedItems, list.marked.length);
      if (mode === 'standard') assert.strictEqual(list.held.length, 0, 'Plain shows held items in their severity');
      assert.strictEqual(c.couldntCheck, c.couldntRun + c.notReached + c.notStarted);
      assert.strictEqual(c.notChecked, c.couldntCheck + c.unfinished);
      const d = Object.values(c.byDistrict);
      for (const k of ['todo', 'notes', 'couldntCheck', 'notChecked', 'unfinished', 'notReached']) {
        assert.strictEqual(d.reduce((n, x) => n + x[k], 0), c[k], `${file} ${mode}: districts add up (${k})`);
      }
    }
  }
});

test('Plain and city get the same numbers; held items are the only difference', () => {
  for (const file of FIXTURES) {
    const doc = load(file);
    const { byDistrict: _a, ...p } = NC.scanCounts(doc, { mode: 'standard' });
    const { byDistrict: _b, ...c } = NC.scanCounts(doc, { mode: 'city' });
    const plain = NC.displayItems(doc);
    const heldBy = (sev) => plain[sev].filter((x) => x.held).length;
    assert.strictEqual(p.todo - c.todo, heldBy('critical') + heldBy('warning'), file);
    assert.strictEqual(p.notes - c.notes, heldBy('info'), file);
    assert.strictEqual(p.heldItems, c.heldItems, file);
    for (const k of ['checks', 'ran', 'couldntRun', 'notReached', 'unfinished', 'notStarted', 'partly', 'couldntCheck', 'notChecked']) {
      assert.strictEqual(p[k], c[k], `${file}: ${k}`);
    }
  }
  // The audit's case: 4 checks didn't finish and the phone backup waits. The
  // couldn't-check number is the phone; didn't finish is the 4, never hidden.
  const c = NC.scanCounts(load('ux6-full.json'), { mode: 'city' });
  assert.deepStrictEqual([c.couldntCheck, c.unfinished, c.notChecked], [1, 4, 5]);
  // The errors scan: 5 to do, never 5 + the 5 checks that couldn't run.
  const e = NC.scanCounts(load('ux6-errors.json'), { mode: 'city' });
  assert.deepStrictEqual([e.todo, e.couldntCheck], [5, 5]);
});

test('the audit’s near-duplicates are one item each (same_key); different extensions stay apart', () => {
  const list = NC.displayItems(load('ux6-full.json'));
  const todo = [...list.critical, ...list.warning];
  const find = (re) => todo.filter((it) => titles(it).some((t) => re.test(t)));
  for (const [re, n] of [
    [/never sleep/, 3], [/screen (?:is set to )?never turns? off/, 2], [/can control your Mac/, 3],
    [/errors/, 2], [/start automatically/, 2], [/back(?:ing)? ?up|Time Machine/, 3], [/exampled/, 2],
  ]) {
    const hit = find(re);
    assert.strictEqual(hit.length, 1, `${re}: one item, got ${hit.map((it) => it.finding.title)}`);
    assert.strictEqual(hit[0].findings.length, n, `${re}: ${titles(hit[0])}`);
  }
  // The list someone may not recognise (it can be marked) leads the accessibility item.
  assert.match(find(/can control your Mac/)[0].finding.title, /may not recognize/);
  const ext = todo.filter((it) => it.finding.code === 'security.chrome_extensions.broad_permissions');
  assert.strictEqual(ext.length, 4, 'four different extensions are four items');
});

test('mergeKey: same_key first, then the thing named, then the title; monitoring never merges', () => {
  const a = { title: 'Extension with broad permissions: OneTab', code: 'x.y.z', data: { extension: 'OneTab' } };
  const b = { title: 'Extension with broad permissions: LastPass', code: 'x.y.z', data: { extension: 'LastPass' } };
  assert.notStrictEqual(NC.mergeKey(a, 'chrome_extensions'), NC.mergeKey(b, 'chrome_extensions'));
  const c = { title: 'AI-related program running: /a', code: 'p.q', data: {} };
  const d = { title: 'AI-related program running: /b', code: 'p.q', data: {} };
  assert.notStrictEqual(NC.mergeKey(c, 'm'), NC.mergeKey(d, 'm'));
  assert.strictEqual(NC.mergeKey({ title: 'Many apps (11)', code: 'k', data: {} }, 'm'), NC.mergeKey({ title: 'Many apps (14)', code: 'k', data: {} }, 'm'));
  assert.strictEqual(NC.mergeKey({ same_key: 's', title: 'a' }, 'm1'), NC.mergeKey({ same_key: 's', title: 'b' }, 'm2'));
  const spy = (name) => ({ title: 'Monitoring software found', severity: 'critical', category: 'security', code: 'security.stalkerware_scan.monitoring_software_found', data: {} });
  const doc = { modules: [{ name: 'stalkerware_scan', category: 'security', status: 'ok', findings: [spy('a'), spy('b')] }] };
  assert.strictEqual(NC.displayItems(doc).critical.length, 2);
});

test('a to-do never merges with a note; marked items are listed apart, at their old severity', () => {
  const mod = (name, findings) => ({ name, category: 'security', status: 'ok', findings });
  const w = { title: 'X', severity: 'warning', category: 'security', same_key: 'k', data: {} };
  const i = { title: 'X', severity: 'info', category: 'security', same_key: 'k', data: {} };
  const marked = { title: 'Y', severity: 'info', category: 'security', same_key: 'j', data: { marked_by_user: true, original_severity: 'warning' } };
  const twin = { title: 'Y', severity: 'info', category: 'security', same_key: 'j', data: { marked_by_user: true, original_severity: 'warning' } };
  const list = NC.displayItems({ modules: [mod('a', [w, marked]), mod('b', [i, twin])] });
  assert.strictEqual(list.warning.length, 1);
  assert.strictEqual(list.info.length, 1);
  assert.strictEqual(list.marked.length, 1);
  assert.strictEqual(list.marked[0].severity, 'warning');
  assert.strictEqual(list.marked[0].findings.length, 2);
  // Plain's card shape.
  const card = NC.asCard(list.warning[0]);
  assert.deepStrictEqual([card.title, card.seen_in, card.also], ['X', ['a'], []]);
});

test('the lead: the worst, then the one that can be fixed or marked', () => {
  const mod = (name, findings) => ({ name, category: 'security', status: 'ok', findings });
  const plainF = { title: 'Count', severity: 'warning', category: 'security', same_key: 'k', data: {} };
  const markF = { title: 'List', severity: 'warning', category: 'security', same_key: 'k', data: {}, markable: { id: 'm1', kind: 'apps' } };
  const crit = { title: 'Worst', severity: 'critical', category: 'security', same_key: 'k', data: {} };
  let it = NC.displayItems({ modules: [mod('a', [plainF]), mod('b', [markF])] }).warning[0];
  assert.deepStrictEqual([it.finding.title, it.seen_in], ['List', ['b', 'a']]);
  it = NC.displayItems({ modules: [mod('a', [plainF]), mod('b', [markF]), mod('c', [crit])] }).critical[0];
  assert.deepStrictEqual([it.finding.title, it.findings.length], ['Worst', 3]);
});

test('a stopped checkup: checks never reached are their own count, and their names fold past five', () => {
  const ran = { name: 'disk_space', category: 'performance', status: 'ok', findings: [] };
  const never = (i) => ({ name: `check_${i}`, category: 'security', status: 'error', error: 'The checkup stopped before this check ran.',
    error_kind: 'stopped', complete: false, findings: [] });
  const doc = { modules: [ran, ...Array.from({ length: 106 }, (_, i) => never(i))], stopped: { stage: 'early', done: 1, total: 107 } };
  const c = NC.scanCounts(doc);
  assert.deepStrictEqual([c.notReached, c.couldntRun, c.couldntCheck, c.ran], [106, 0, 106, 1]);
  const line = NC.notCheckedLine(NC.notCheckedSummary(doc));
  assert.strictEqual(line, '106 checks didn’t get to run because the checkup stopped, so this isn’t a clean bill of health.');
  const names = NC.namesLine(NC.notCheckedParts(doc).notReached.map((x) => x.name));
  assert.deepStrictEqual([names.inline, names.count, names.folded, names.all.length], ['', 106, true, 106]);
  assert.deepStrictEqual(NC.namesLine(['A', 'B', 'C']), { inline: 'A, B and C', count: 3, all: ['A', 'B', 'C'], folded: false });
  assert.strictEqual(NC.namesLine(['A']).inline, 'A');
  assert.strictEqual(NC.fmt(4837), '4,837');
});

// The views render from displayItems / scanCounts (groups A5 and B5).
test('Plain’s list (app.plainCards, from NotChecked.displayItems) has scanCounts.todo cards and scanCounts.notes notes', () => {
  const app = require('../renderer/app.js');
  for (const file of FIXTURES) {
    const doc = load(file);
    for (const mode of ['standard', 'city']) {
      const g = app.plainCards(doc, mode);
      const c = NC.scanCounts(doc, { mode });
      const unmarked = (list) => list.filter((x) => !(x.data && x.data.marked_by_user === true));
      // City mode: held cards stay on the list, out of every number.
      const out = (list) => (mode === 'city' ? list.filter((x) => !NC.isHeld(x, x.module)) : list);
      assert.strictEqual(out(unmarked([...g.critical, ...g.warning])).length, c.todo, `${file} ${mode}`);
      assert.strictEqual(out(unmarked(g.info)).length, c.notes, `${file} ${mode}`);
    }
  }
});

test('the city’s missions are scanCounts.todo items (plus the ones marked as yours)', async () => {
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  for (const file of FIXTURES) {
    const doc = load(file);
    const city = findingsToCity(doc);
    const missions = city.districts.flatMap((d) => d.missions);
    assert.strictEqual(missions.length, NC.scanCounts(doc).todo + NC.scanCounts(doc).markedItems, file);
    assert.strictEqual(new Set(missions.map((m) => m.id)).size, missions.length, `${file}: one id per mission`);
    // Held missions are left out of the city's numbers: what's left is the city's todo.
    const shown = missions.filter((m) => !m.marked && !m.findings.some((f) => NC.isHeld(f, f.module)));
    assert.strictEqual(shown.length, NC.scanCounts(doc, { mode: 'city' }).todo, file);
    const ext = missions.filter((m) => m.code === 'security.chrome_extensions.broad_permissions');
    if (file === 'ux6-full.json') assert.strictEqual(ext.length, 4, 'four different extensions are four missions');
  }
});
