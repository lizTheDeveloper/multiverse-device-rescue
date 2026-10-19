const test = require('node:test');
const assert = require('node:assert');
const { mergeModuleResult, handleRecheck } = require('../recheck');

const LAST = { schema_version: 1, platform: 'darwin', modules: [
  { name: 'a_mod', category: 'security', status: 'ok', supported: true, findings: [{ title: 'old a' }] },
  { name: 'b_mod', category: 'network', status: 'ok', supported: true, findings: [{ title: 'old b' }] },
] };
const PARTIAL = { schema_version: 1, platform: 'darwin', modules: [
  { name: 'a_mod', category: 'security', status: 'ok', supported: true, findings: [] },
] };

test('mergeModuleResult swaps only the re-checked module and keeps order', () => {
  const { doc, module } = mergeModuleResult(LAST, PARTIAL, 'a_mod');
  assert.deepStrictEqual(doc.modules.map((m) => m.name), ['a_mod', 'b_mod']);
  assert.deepStrictEqual(doc.modules[0].findings, []);
  assert.strictEqual(doc.modules[1], LAST.modules[1]);
  assert.strictEqual(module, PARTIAL.modules[0]);
  assert.strictEqual(LAST.modules[0].findings.length, 1, 'input not mutated');
});

test('mergeModuleResult reports a module missing from the partial result', () => {
  const { doc, module } = mergeModuleResult(LAST, { modules: [] }, 'a_mod');
  assert.strictEqual(module, null);
  assert.strictEqual(doc, LAST);
});

function deps(over = {}) {
  let last = LAST;
  const remembered = [];
  return {
    remembered,
    get last() { return last; },
    d: {
      getLastDoc: () => last,
      setLastDoc: (d) => { last = d; },
      runRecheck: async () => PARTIAL,
      policies: [{ remember: (d) => remembered.push(['fix', d]) }, { remember: (d) => remembered.push(['mark', d]) }],
      ...over,
    },
  };
}

test('handleRecheck merges, stores, and re-arms both policies from the merged scan', async () => {
  const t = deps();
  const r = await handleRecheck('a_mod', t.d);
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.doc.modules.map((m) => m.name), ['a_mod', 'b_mod']);
  assert.strictEqual(t.last, r.doc);
  assert.deepStrictEqual(t.remembered.map(([k]) => k), ['fix', 'mark']);
  assert.strictEqual(t.remembered[0][1], r.doc);
});

test('handleRecheck refuses names that are not plain identifiers or not in the last scan', async () => {
  for (const name of ['../x', 'A_MOD', '', null, 'c_mod']) {
    let ran = false;
    const t = deps({ runRecheck: async () => { ran = true; return PARTIAL; } });
    const r = await handleRecheck(name, t.d);
    assert.strictEqual(r.ok, false, String(name));
    assert.strictEqual(r.error, 'not_allowed');
    assert.strictEqual(ran, false);
  }
});

test('handleRecheck with no scan yet', async () => {
  const t = deps({ getLastDoc: () => null });
  const r = await handleRecheck('a_mod', t.d);
  assert.deepStrictEqual([r.ok, r.error], [false, 'no_scan']);
});

test('engine failure and a missing module are not credited and change nothing', async () => {
  for (const [run, error] of [
    [async () => ({ engine_error: 'timeout', message: 'x' }), 'engine_error'],
    [async () => { throw new Error('boom'); }, 'engine_error'],
    [async () => ({ schema_version: 1, modules: [] }), 'not_rechecked'],
  ]) {
    const t = deps({ runRecheck: run });
    const r = await handleRecheck('a_mod', t.d);
    assert.deepStrictEqual([r.ok, r.error], [false, error]);
    assert.strictEqual(t.last, LAST);
    assert.strictEqual(t.remembered.length, 0);
  }
});

test('a module that errored or is unsupported is not re-checked, never "gone"', async () => {
  for (const flags of [{ status: 'error', error: 'crashed' }, { supported: false, unsupported_reason: 'not here' }]) {
    const partial = { modules: [{ name: 'a_mod', category: 'security', status: 'ok', supported: true, findings: [], ...flags }] };
    const t = deps({ runRecheck: async () => partial });
    const r = await handleRecheck('a_mod', t.d);
    assert.deepStrictEqual([r.ok, r.error], [false, 'not_rechecked']);
    assert.strictEqual(t.last, LAST);
    assert.strictEqual(t.remembered.length, 0);
  }
});

test('a full scan that lands during the re-check wins: the stale result is not merged or stored', async () => {
  const NEWER = { schema_version: 1, platform: 'darwin', modules: [{ name: 'a_mod', category: 'security', status: 'ok', supported: true, findings: [{ title: 'new a' }] }] };
  const t = deps();
  t.d.runRecheck = async () => { t.d.setLastDoc(NEWER); return PARTIAL; };
  const r = await handleRecheck('a_mod', t.d);
  assert.deepStrictEqual([r.ok, r.error], [false, 'not_rechecked']);
  assert.strictEqual(r.message, 'That check couldn’t run just now.');
  assert.strictEqual(t.last, NEWER);
  assert.strictEqual(t.remembered.length, 0);
});

// ---------------------------------------------------------------------------
// The optional iPhone backup sweep joins the last full scan (main.js run-scan).
// ---------------------------------------------------------------------------
const { applyScanResult, joinsLastScan } = require('../recheck');
const { createFixPolicy } = require('../fix-policy');
const { createMarkPolicy } = require('../mark-policy');
const { createExecLog } = require('../engine-runner');

const FIXABLE = { will_change: 'Turns on the firewall.', how_to_undo: ['Open Settings.'] };
const FULL = { schema_version: 1, platform: 'darwin', modules: [
  { name: 'firewall_audit', category: 'security', status: 'ok', supported: true, findings: [{ title: 'Firewall is off', fixable: FIXABLE }] },
  { name: 'mvt_spyware_scan', category: 'security', status: 'ok', supported: true, not_started: true, findings: [{ title: 'backup found', severity: 'info' }] },
] };
const PHONE = { schema_version: 1, platform: 'darwin', modules: [
  { name: 'mvt_spyware_scan', category: 'security', status: 'ok', supported: true, findings: [{ title: 'No known spyware found', severity: 'info' }] },
] };
const policies = () => { const fix = createFixPolicy(); const mark = createMarkPolicy(); return { fix, mark, list: [fix, mark] }; };

test('the phone sweep replaces only its own module in the last scan and keeps the rest', () => {
  const p = policies();
  p.fix.remember(FULL);
  const next = applyScanResult({ profile: 'iphone_spyware_check', lastDoc: FULL, doc: PHONE, policies: p.list });
  assert.deepStrictEqual(next.modules.map((m) => m.name), ['firewall_audit', 'mvt_spyware_scan']);
  assert.strictEqual(next.modules[0], FULL.modules[0]);
  assert.strictEqual(next.modules[1].findings[0].title, 'No known spyware found');
  assert.strictEqual(FULL.modules[1].findings[0].title, 'backup found', 'input not mutated');
});

test('after the phone sweep, a fix for another check is still allowed', () => {
  const p = policies();
  p.fix.remember(FULL);
  assert.strictEqual(p.fix.isAllowed('firewall_audit'), true);
  applyScanResult({ profile: 'iphone_spyware_check', lastDoc: FULL, doc: PHONE, policies: p.list });
  assert.strictEqual(p.fix.isAllowed('firewall_audit'), true);
  // Without merging (the old behaviour) it would have been refused.
  const old = createFixPolicy();
  old.remember(PHONE);
  assert.strictEqual(old.isAllowed('firewall_audit'), false);
});

test('a stopped phone sweep never arms a policy and leaves the last full scan alone', () => {
  const p = policies();
  p.fix.remember(FULL);
  const stopped = { ...PHONE, stopped: { stage: 'early', reason: 'exit' }, partial: { done: 0, total: 1, stopped: 'early' } };
  const next = applyScanResult({ profile: 'iphone_spyware_check', lastDoc: FULL, doc: stopped, policies: p.list });
  assert.strictEqual(next, FULL);
  assert.strictEqual(p.fix.isAllowed('firewall_audit'), true, 'the full scan’s allowance stands');
  // A stopped doc that does replace the last scan (a full sweep) arms nothing.
  const fullStopped = { ...FULL, stopped: { stage: 'assembly', reason: 'exit' } };
  const after = applyScanResult({ profile: null, lastDoc: FULL, doc: fullStopped, policies: p.list });
  assert.strictEqual(after, fullStopped);
  assert.strictEqual(p.fix.isAllowed('firewall_audit'), false);
});

test('with no full last scan, or a full sweep, the result replaces the last scan as before', () => {
  const p = policies();
  assert.strictEqual(joinsLastScan('iphone_spyware_check', null), false);
  assert.strictEqual(applyScanResult({ profile: 'iphone_spyware_check', lastDoc: null, doc: PHONE, policies: p.list }), PHONE);
  assert.strictEqual(applyScanResult({ profile: 'iphone_spyware_check', lastDoc: { ...FULL, stopped: {} }, doc: PHONE, policies: p.list }), PHONE);
  assert.strictEqual(applyScanResult({ profile: null, lastDoc: FULL, doc: PHONE, policies: p.list }), PHONE);
});

test('the commands log forgets one check without touching the others', () => {
  const log = createExecLog();
  log.add({ type: 'exec', module: 'firewall_audit', argv: ['ls'] });
  log.add({ type: 'exec', module: 'mvt_spyware_scan', argv: ['mvt'] });
  log.resetModule('mvt_spyware_scan');
  assert.strictEqual(log.get('mvt_spyware_scan').length, 0);
  assert.strictEqual(log.get('firewall_audit').length, 1);
});
