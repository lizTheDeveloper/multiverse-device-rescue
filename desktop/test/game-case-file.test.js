const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/case-file.js');

const sig = (over = {}) => ({ id: 'x', kind: 'real', severity: 'warning', title: 'T', districtId: 'outskirts',
  module: 'some_check', finding: {}, tag: null, ...over });

test('a critical program is an UNIDENTIFIED lead, high risk if not yours, never "critical" on its own', async () => {
  const { caseOf, caseLine } = await load();
  const c = caseOf(sig({ severity: 'critical', module: 'suspicious_connections' }));
  assert.deepStrictEqual([c.type, c.status, c.priority, c.open], ['lead', 'unidentified', 'high', true]);
  assert.strictEqual(caseLine(c), 'UNIDENTIFIED · HIGH RISK IF NOT YOURS');
});

test('a program kind or a markable block makes a lead, whatever the module', async () => {
  const { caseOf } = await load();
  assert.strictEqual(caseOf(sig(), { kinds: ['starts'] }).type, 'lead');
  assert.strictEqual(caseOf(sig({ finding: { markable: { kind: 'app_permissions' } } })).type, 'lead');
});

test('a verified maker lowers a lead by one step; a door is not lowered', async () => {
  const { caseOf } = await load();
  const made = { made_by: [{ name: 'Google LLC', verified: true }] };
  assert.strictEqual(caseOf(sig({ severity: 'critical', module: 'kext_audit', finding: made })).priority, 'medium');
  assert.strictEqual(caseOf(sig({ module: 'kext_audit', finding: made })).priority, 'low');
  assert.strictEqual(caseOf(sig({ module: 'kext_audit', finding: { made_by: [{ verified: true }, { verified: false }] } })).priority, 'medium');
  assert.strictEqual(caseOf(sig({ severity: 'critical', module: 'time_machine_check', finding: made })).priority, 'high');
});

test('settings in the Gatehouse and the Wires, and backups and updates anywhere, are OPEN DOORs', async () => {
  const { caseOf } = await load();
  assert.strictEqual(caseOf(sig({ module: 'firewall_audit', districtId: 'gatehouse' })).type, 'door');
  assert.strictEqual(caseOf(sig({ module: 'time_machine_check', districtId: 'foundations' })).type, 'door');
  assert.strictEqual(caseOf(sig({ module: 'disk_space', districtId: 'engine-room' })).type, 'upkeep');
});

test('"I back up another way" keeps the backup warning a door, kept on purpose once answered', async () => {
  const { caseOf } = await load();
  const backup = sig({ module: 'time_machine_check', districtId: 'foundations',
    finding: { markable: { kind: 'backup_elsewhere' } } });
  assert.strictEqual(caseOf(backup).type, 'door');
  assert.strictEqual(caseOf({ ...backup, tag: 'mine' }).status, 'kept');
});

test('tags move a case: mine is YOURS for a lead and KEPT ON PURPOSE for a door', async () => {
  const { caseOf } = await load();
  const lead = sig({ module: 'kext_audit' });
  assert.strictEqual(caseOf({ ...lead, tag: 'mine' }).status, 'yours');
  assert.strictEqual(caseOf({ ...lead, tag: 'closer' }).status, 'investigating');
  assert.strictEqual(caseOf({ ...lead, tag: 'threat' }).status, 'threat');
  const door = sig({ module: 'firewall_audit', districtId: 'gatehouse', tag: 'mine' });
  assert.deepStrictEqual([caseOf(door).status, caseOf(door).open], ['kept', false]);
  assert.strictEqual(caseOf({ ...door, tag: null }, { closed: true }).status, 'closed');
});

test('held is SAFETY FIRST and high, and no tag or fix moves it', async () => {
  const { caseOf } = await load();
  for (const tag of [null, 'mine', 'threat', 'closer']) {
    const c = caseOf(sig({ module: 'kext_audit', tag }), { held: true, closed: true });
    assert.deepStrictEqual([c.status, c.priority, c.open], ['held', 'high', true]);
  }
});

test('blind spots and notes stay out of the open count once noted', async () => {
  const { caseOf } = await load();
  assert.strictEqual(caseOf(sig({ kind: 'couldnt', severity: 'couldnt' })).type, 'blind');
  assert.strictEqual(caseOf(sig({ severity: 'info', tag: 'noted' })).status, 'noted');
});

test('the same door said by several checks is one case; leads never merge', async () => {
  const { caseOf, mergeEchoes } = await load();
  const withCase = (s) => ({ ...s, case: caseOf(s) });
  const items = [
    withCase(sig({ id: 'a', title: 'Your Mac is set to never sleep', module: 'energy_saver_check', districtId: 'engine-room' })),
    withCase(sig({ id: 'b', title: 'Your Mac is set to  never sleep', module: 'power_settings', districtId: 'engine-room' })),
    withCase(sig({ id: 'c', title: 'Script downloads and runs code: setup.sh', module: 'ai_worm_filesystem' })),
    withCase(sig({ id: 'd', title: 'Script downloads and runs code: setup.sh', module: 'ai_worm_filesystem' })),
  ];
  const out = mergeEchoes(items);
  assert.deepStrictEqual(out.map((x) => x.id), ['a', 'c', 'd']);
  assert.deepStrictEqual(out[0].also.map((x) => x.id), ['b']);
});

test('the report counts open and closed cases, and puts held and threats first', async () => {
  const { caseOf, caseReport, compareCases } = await load();
  const items = [
    sig({ id: 'u', module: 'kext_audit' }),
    sig({ id: 'y', module: 'kext_audit', tag: 'mine' }),
    sig({ id: 't', module: 'kext_audit', tag: 'threat' }),
    sig({ id: 'd', module: 'firewall_audit', districtId: 'gatehouse' }),
    sig({ id: 'n', severity: 'info' }),
  ].map((s) => ({ ...s, case: caseOf(s, { held: s.id === 'h' }) }));
  items.push({ ...sig({ id: 'h' }), case: caseOf(sig(), { held: true }) });
  const r = caseReport(items);
  assert.deepStrictEqual([r.leads, r.unidentified, r.identified, r.threats, r.held, r.doorsOpen, r.open, r.closed], [4, 1, 1, 1, 1, 1, 4, 1]);
  assert.deepStrictEqual(items.sort(compareCases).map((x) => x.id), ['h', 't', 'u', 'd', 'n', 'y']);
});

test('a MINE tag keeps what it is for, from the fixed list only, and survives a save', async () => {
  const { setTag, award, POINTS } = await import('../renderer/game/ledger.js');
  const { emptyDeck, cleanDeck } = await import('../renderer/game/progress.js');
  const { radarOf, suggestCategory } = await import('../renderer/game/own-categories.js');
  let d = setTag(emptyDeck(), 'm|a|path=/x', 'mine', 'fp', 'now', 'dev');
  d = setTag(d, 'm|b|path=/y', 'mine', 'fp', 'now', 'a name someone typed');
  d = setTag(d, 'm|c|path=/z', 'threat', 'fp', 'now', 'dev');
  assert.strictEqual(d.tags['m|a|path=/x'].cat, 'dev');
  assert.strictEqual(d.tags['m|b|path=/y'].cat, undefined);
  assert.strictEqual(d.tags['m|c|path=/z'].cat, undefined);
  assert.deepStrictEqual(cleanDeck(d).tags['m|a|path=/x'], { tag: 'mine', at: 'now', fp: 'fp', cat: 'dev' });
  assert.strictEqual(cleanDeck({ ...d, tags: { k: { tag: 'threat', at: 'n', fp: 'f', cat: 'dev' } } }), null);
  assert.strictEqual(radarOf(d).dev, 1);
  const once = award(d, 'identify', 'm|a|path=/x');
  assert.strictEqual(once.points, POINTS.identify);
  assert.strictEqual(award(once.deck, 'identify', 'm|a|path=/x').points, 0);
  assert.strictEqual(award(d, 'identify', 'stalkerware_scan|x').points, 0);
  assert.strictEqual(suggestCategory({ made_by: [{ name: 'Zoom Video Communications' }] }), 'chat');
  assert.strictEqual(suggestCategory({ data: { program: 'ssh' } }), 'dev');
  assert.strictEqual(suggestCategory({}, ['extension']), 'browser');
  assert.strictEqual(suggestCategory({}), null);
});
