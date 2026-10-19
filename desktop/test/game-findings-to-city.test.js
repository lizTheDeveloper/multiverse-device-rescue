const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/findings-to-city.js');

const mod = (name, category, findings, extra = {}) => ({ name, category, status: 'ok', error: null, supported: true, unsupported_reason: null, findings, ...extra });
const f = (severity, extra = {}) => ({ title: `${severity} thing`, description: 'Something.', severity, code: 'security.m.x', data: {}, ...extra });

test('findings land in districts by category; info goes to notes', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [
    mod('launch_agent_audit', 'security', [f('critical', { data: { plist: '/a.plist' } }), f('info')]),
    mod('disk_space', 'performance', [f('warning', { code: 'performance.disk_space.low' })]),
  ] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.missions.length, 1);
  assert.strictEqual(gate.missions[0].severity, 'critical');
  assert.strictEqual(gate.notes.length, 1);
  assert.strictEqual(gate.status, 'hot');
  assert.strictEqual(city.districts.find((d) => d.id === 'engine-room').status, 'warn');
  assert.deepStrictEqual(city.totals, { critical: 1, warning: 1, info: 1, fog: 0 });
});

test('a category we do not know goes to The Outskirts instead of disappearing', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('odd', 'test', [f('warning')]), mod('nocat', undefined, [f('critical')])] });
  const out = city.districts.find((d) => d.id === 'outskirts');
  assert.ok(out, 'outskirts present when used');
  assert.strictEqual(out.missions.length, 2);
});

test('The Outskirts is left out when nothing goes there', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [])] });
  assert.ok(!city.districts.some((d) => d.id === 'outskirts'));
  assert.strictEqual(city.districts.length, 5);
});

test('unknown severity is treated as info, like the list view', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [f('weird')])] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.missions.length, 0);
  assert.strictEqual(gate.notes.length, 1);
});

test('fog for unsupported and errored checks; a district of only failed checks is fog, never clear', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [
    mod('wifi_security_audit', 'network', [], { supported: false, unsupported_reason: 'Needs Location Services.' }),
    mod('router_security_audit', 'network', [], { status: 'error', error: 'timed out' }),
    mod('update_checker', 'integrity', []),
    mod('dns_config', 'integrity', [], { status: 'error', error: 'boom' }),
  ] });
  const wires = city.districts.find((d) => d.id === 'wires');
  assert.strictEqual(wires.status, 'fog');
  assert.deepStrictEqual(wires.fog.map((x) => x.reason), ['Needs Location Services.', 'timed out']);
  assert.strictEqual(city.districts.find((d) => d.id === 'foundations').status, 'partial');
  assert.strictEqual(city.totals.fog, 3);
});

test('a district where no checks ran at all says none, not clear', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [])] });
  assert.strictEqual(city.districts.find((d) => d.id === 'junkyard').status, 'none');
  assert.strictEqual(city.districts.find((d) => d.id === 'gatehouse').status, 'clear');
});

test('steps come from the walkthrough, and fall back to What to do, then to the description', async () => {
  const { missionSteps } = await load();
  const steps = [{ number: 1, title: 'Remove high-risk background tasks', body: 'Body.' }];
  assert.deepStrictEqual(missionSteps(f('critical', { remediation: { title: 'T', steps } })), steps);
  assert.deepStrictEqual(
    missionSteps(f('warning', { description: 'Your disk is full.\n\nWhat to do:\n1. Empty the Trash.\n2. Delete old downloads.' })).map((s) => s.title),
    ['Empty the Trash.', 'Delete old downloads.'],
  );
  assert.deepStrictEqual(missionSteps(f('warning', { description: 'Just this.' })).map((s) => s.title), ['Just this.']);
});

test('identity is stable across scans and comes from what the finding is about', async () => {
  const { findingIdentity } = await load();
  const a = { ...f('critical', { data: { plist: '/x.plist', pid: 1 } }), module: 'm' };
  const b = { ...f('critical', { data: { plist: '/x.plist', pid: 2 } }), module: 'm' };
  assert.strictEqual(findingIdentity(a), findingIdentity(b));
  assert.strictEqual(findingIdentity(a), 'm|security.m.x|plist=/x.plist');
});

test('identity keeps two instances of one network code apart by data.target', async () => {
  const { findingIdentity } = await load();
  const dev = (target) => ({ ...f('warning', { code: 'network.lan_device_inventory.unrecognised_device', data: { target } }), module: 'lan_device_inventory' });
  assert.notStrictEqual(findingIdentity(dev('192.168.1.20')), findingIdentity(dev('192.168.1.21')));
  assert.strictEqual(findingIdentity(dev('192.168.1.20')), findingIdentity(dev('192.168.1.20')));
});

test('identity ignores the mark id, which changes when the program changes', async () => {
  // rescue/known_items.py hashes content_sha256 and arguments_sha256 into the
  // mark id. Same plist with a new program must stay the same mission, or the
  // old one would be credited as reclaimed while the engine still reports it.
  const { findingIdentity } = await load();
  const before = { ...f('warning', { markable: { id: 'id-old' }, data: { plist: '/x.plist', content_sha256: 'aaa' } }), module: 'launch_agent_audit' };
  const after = { ...f('warning', { markable: { id: 'id-new' }, data: { plist: '/x.plist', content_sha256: 'bbb' } }), module: 'launch_agent_audit' };
  assert.strictEqual(findingIdentity(before), findingIdentity(after));
  // Marked and unmarked: the engine retitles and lowers a marked finding but keeps code and plist.
  const marked = { ...f('info', { title: 'Marked as yours: ai.example',
    data: { plist: '/x.plist', known_item_id: 'id-old', marked_by_user: true, original_severity: 'warning' } }), module: 'launch_agent_audit' };
  assert.strictEqual(findingIdentity(marked), findingIdentity(before));
});

test('two findings about one thing become one mission that lists both, at the higher severity', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [f('warning', { title: 'one', data: { plist: '/x.plist' } }), f('critical', { title: 'two', data: { plist: '/x.plist' } })])] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.missions.length, 1);
  assert.strictEqual(gate.missions[0].severity, 'critical');
  assert.strictEqual(gate.missions[0].findings.length, 2);
});

test('one code, different things named (four extensions): four missions, each with its own id (NotChecked.displayItems)', async () => {
  const { findingsToCity } = await load();
  const ext = (name) => f('warning', { code: 'security.chrome_extensions.broad_permissions', title: `Extension with broad permissions: ${name}`, data: { extension: name } });
  const city = findingsToCity({ modules: [mod('chrome_extensions', 'security', ['OneTab', 'LastPass', 'Honey', 'Grammarly'].map(ext))] });
  const missions = city.districts.find((d) => d.id === 'gatehouse').missions;
  assert.strictEqual(missions.length, 4);
  assert.strictEqual(new Set(missions.map((m) => m.id)).size, 4, 'mission ids never collide');
});

test('mission flags: fixable, markable, marked', async () => {
  const { findingsToCity } = await load();
  const fixable = { will_change: 'x', how_to_undo: ['y'] };
  const city = findingsToCity({ modules: [mod('a', 'security', [
    f('warning', { fixable, markable: { id: 'm1' }, data: { plist: '/1' } }),
    f('warning', { data: { known_item_id: 'm2', marked_by_user: true } }),
  ])] });
  const [m1, m2] = city.districts.find((d) => d.id === 'gatehouse').missions;
  assert.deepStrictEqual([m1.fixable, m1.markable, m1.marked], [true, true, false]);
  assert.strictEqual(m2.marked, true);
});

test('a finding the person marked stays a mission even though the engine lowered it to info', async () => {
  // rescue/known_items.py sets severity INFO on a marked finding and keeps the
  // old one in data.original_severity. If it became a note, the mission would
  // vanish and the next scan would count it as reclaimed: never allowed.
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('launch_agent_audit', 'security', [
    f('info', { title: 'Marked as yours: ai.example', data: { plist: '/ai.plist', known_item_id: 'abc', marked_by_user: true, original_severity: 'warning' } }),
  ])] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.notes.length, 0);
  assert.strictEqual(gate.missions.length, 1);
  assert.deepStrictEqual([gate.missions[0].id, gate.missions[0].severity, gate.missions[0].marked], ['launch_agent_audit|security.m.x|plist=/ai.plist', 'warning', true]);
});

test('garbage in does not throw', async () => {
  const { findingsToCity } = await load();
  for (const doc of [null, {}, { modules: null }, { modules: [null, { name: 'x' }, { name: 'y', findings: [null] }] }]) {
    const city = findingsToCity(doc);
    assert.ok(Array.isArray(city.districts));
  }
});

test('a check that ran but didn’t finish makes its district partial, never clear, and never secured', async () => {
  const { findingsToCity } = await load();
  const { cityIntegrity } = await import('../renderer/game/signals.js');
  const { districtLine, districtBadges } = await import('../renderer/game/views/map.js');
  const { districtComplete } = await import('../renderer/game/views/milestone.js');
  const city = findingsToCity({ modules: [
    mod('update_checker', 'integrity', [f('info', { code: null })], { complete: false }),
    mod('disk_space', 'performance', [], { complete: true }),
  ] });
  const found = city.districts.find((d) => d.id === 'foundations');
  assert.strictEqual(found.status, 'partial');
  assert.deepStrictEqual(found.unfinished, [{ module: 'update_checker' }]);
  assert.strictEqual(found.checksRan, 1);
  assert.match(districtLine(found), /didn’t finish/);
  assert.doesNotMatch(districtBadges(found) + districtLine(found), /NOTHING FOUND|Nothing found/);
  assert.match(districtBadges(found), /1 DIDN’T FINISH/);
  assert.strictEqual(city.districts.find((d) => d.id === 'engine-room').status, 'clear');
  const integ = cityIntegrity(city, []);
  assert.ok(integ.checkedIds.has('foundations'));
  assert.ok(!integ.securedIds.has('foundations'));
  const progress = { missions: { a: { status: 'reclaimed', module: 'update_checker', districtId: 'foundations', title: 'A' } } };
  assert.strictEqual(districtComplete(found, progress), false);
});
