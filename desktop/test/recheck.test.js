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
