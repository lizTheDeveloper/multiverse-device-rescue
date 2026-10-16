const test = require('node:test');
const assert = require('node:assert');
const { loadRcFromDisk } = require('./rc-from-disk.js');

const FC = 'device_security-fortify-computer';
const ok = (name, findings = []) => ({ name, status: 'ok', supported: true, findings });
// Positive evidence for every Mac step of Harden Your Computer (see verified-missions.js).
const allMac = { platform: 'darwin', modules: [
  ok('encryption_check'),
  ok('filevault_recovery', [{ severity: 'info', data: { check: 'fv_status' } }]),
  ok('screen_lock_check', [{ severity: 'info', data: { check: 'screen_lock_required', value: 'enabled' } }]),
  ok('lock_screen_check'),
  ok('find_my_mac_check', [{ severity: 'info', code: 'security.find_my_mac_check.configured_ok', data: {} }]),
] };
const brokenMac = { platform: 'darwin', modules: [ok('encryption_check', [{ title: 'FileVault is off', severity: 'warning', data: {} }]), ...allMac.modules.slice(1)] };
// Every module ran fine, but none said anything: no evidence, nothing confirmed.
const silentMac = { platform: 'darwin', modules: allMac.modules.map((m) => ok(m.name)) };
const setup = async () => ({ ...(await import('../renderer/game/one-city.js')), rc: await loadRcFromDisk() });

test('focus follows the worry, like the Reclaim City link', async () => {
  const { focusFor } = await setup();
  assert.strictEqual(focusFor({ id: 'hacked' }), 'master-keys');
  assert.strictEqual(focusFor({ id: 'identity' }), 'reclamation');
  for (const id of ['wifi', 'sketchy', 'helping', 'unsure']) assert.strictEqual(focusFor({ id }), 'computer');
  assert.strictEqual(focusFor(null), 'computer');
});

test('confirmed and reported are counted apart; yours is never counted', async () => {
  const { countConfirmedAndReported, rc } = await setup();
  const progress = { version: 1, missions: { a: { status: 'reclaimed' }, b: { status: 'reclaimed' }, c: { status: 'yours' }, d: { status: 'open' } } };
  const rcState = { missions: { [FC]: { status: 'completed' }, 'gmail-recon-breach': { status: 'completed' }, 'x-later': { status: 'skipped' } } };
  const scanConfirmed = { version: 1, missions: { [FC]: { at: '2026-10-16T00:00:00Z' } } };
  assert.deepStrictEqual(countConfirmedAndReported({ rc, progress, rcState, scanConfirmed, doc: allMac }), { confirmed: 3, reported: 1 });
});

test('a scan-confirmed mission the scan no longer confirms counts as reported, not confirmed', async () => {
  const { countConfirmedAndReported, rc } = await setup();
  const rcState = { missions: { [FC]: { status: 'completed' } } };
  const scanConfirmed = { version: 1, missions: { [FC]: { at: 'x' } } };
  const empty = { version: 1, missions: {} };
  assert.deepStrictEqual(countConfirmedAndReported({ rc, progress: empty, rcState, scanConfirmed, doc: brokenMac }), { confirmed: 0, reported: 1 });
  assert.deepStrictEqual(countConfirmedAndReported({ rc, progress: empty, rcState, scanConfirmed, doc: silentMac }), { confirmed: 0, reported: 1 },
    'checks that ran but gave no evidence confirm nothing');
});

test('a mission is only confirmed if it was finished from the scan, and only with the game data to count its steps', async () => {
  const { countConfirmedAndReported, rc } = await setup();
  const rcState = { missions: { [FC]: { status: 'completed' } } };
  const empty = { version: 1, missions: {} };
  assert.deepStrictEqual(countConfirmedAndReported({ rc, progress: empty, rcState, scanConfirmed: empty, doc: allMac }), { confirmed: 0, reported: 1 },
    'filed by the person, never finished from the scan');
  assert.deepStrictEqual(countConfirmedAndReported({ progress: empty, rcState, scanConfirmed: { version: 1, missions: { [FC]: { at: 'x' } } }, doc: allMac }), { confirmed: 0, reported: 1 },
    'without the game data the step count is unknown, so nothing is confirmed');
});

test('counting never changes the game state', async () => {
  const { countConfirmedAndReported, rc } = await setup();
  const rcState = { missions: { [FC]: { status: 'completed', completedAt: 't' } } };
  const before = JSON.stringify(rcState);
  countConfirmedAndReported({ rc, progress: { version: 1, missions: {} }, rcState, scanConfirmed: { version: 1, missions: { [FC]: { at: 'x' } } }, doc: brokenMac });
  assert.strictEqual(JSON.stringify(rcState), before);
});

test('account district cards: every game district, in chapter order, with check-again where reports disagree', async () => {
  const { accountDistrictCards, rc } = await setup();
  const st = rc.createInitialState();
  st.missions[FC] = { status: 'completed', completedAt: '2026-10-09T00:00:00Z' };
  const before = JSON.stringify(st);
  const cards = accountDistrictCards({ rc, rcState: st, doc: brokenMac });
  assert.deepStrictEqual(cards.map((c) => c.id), [...rc.DISTRICTS].sort((a, b) => a.chapter - b.chapter).map((d) => d.id));
  assert.strictEqual(cards.find((c) => c.id === 'perimeter').checkAgain, true);
  assert.strictEqual(cards.find((c) => c.id === 'vault').checkAgain, false);
  assert.ok(cards.every((c) => typeof c.percent === 'number'));
  assert.strictEqual(JSON.stringify(st), before);
  const fine = accountDistrictCards({ rc, rcState: st, doc: allMac });
  assert.strictEqual(fine.find((c) => c.id === 'perimeter').checkAgain, false);
});

test('deviceMissionFor finds the device mission for a module', async () => {
  const { deviceMissionFor } = await setup();
  const city = { districts: [{ missions: [{ id: 'm1', module: 'encryption_check' }] }] };
  assert.strictEqual(deviceMissionFor(city, ['filevault_recovery', 'encryption_check']).id, 'm1');
  assert.strictEqual(deviceMissionFor(city, ['find_my_mac_check']), null);
  assert.strictEqual(deviceMissionFor(null, ['encryption_check']), null);
});

test('account district cards still build when there is no game state yet', async () => {
  const { accountDistrictCards, rc } = await setup();
  const cards = accountDistrictCards({ rc, rcState: null, doc: brokenMac });
  assert.strictEqual(cards.length, rc.DISTRICTS.length);
  assert.ok(cards.every((c) => c.completed === 0 && c.checkAgain === false));
});
