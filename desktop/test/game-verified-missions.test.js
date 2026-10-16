const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { loadRcFromDisk } = require('./rc-from-disk.js');

const ROOT = path.join(__dirname, '..', '..');
const load = () => import('../renderer/game/verified-missions.js');
const ok = (name, findings = []) => ({ name, status: 'ok', supported: true, findings });
const mac = (...modules) => ({ platform: 'darwin', modules });
const warn = (extra = {}) => ({ title: 'x', severity: 'warning', data: {}, ...extra });
const E = (check, extra = {}) => ({ severity: 'info', data: { check, ...(extra.data || {}) }, ...extra, data: { check, ...(extra.data || {}) } });
const FV = ok('filevault_recovery', [E('fv_status')]);
const LOCK = ok('screen_lock_check', [E('screen_lock_required', { data: { value: 'enabled' } })]);
const FMM = ok('find_my_mac_check', [{ severity: 'info', code: 'security.find_my_mac_check.configured_ok', data: {} }]);
const BL = ok('win_bitlocker_check', [{ severity: 'info', code: 'security.win_bitlocker_check.status_info', data: {} }]);
const stepsOf = async (id) => (await loadRcFromDisk()).MISSIONS.find((m) => m.id === id).steps.length;
const FC = 'device_security-fortify-computer';

function moduleDir(name) {
  for (const cat of fs.readdirSync(path.join(ROOT, 'modules'))) {
    const p = path.join(ROOT, 'modules', cat, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

const SUBJECT = {
  [`${'device_security-fortify-computer'}:0`]: /FileVault/i, [`${'device_security-fortify-computer'}:1`]: /BitLocker/i,
  [`${'device_security-fortify-computer'}:2`]: /encrypt|BitLocker/i, [`${'device_security-fortify-computer'}:3`]: /encrypt|LUKS/i,
  [`${'device_security-fortify-computer'}:4`]: /lock|password|screen/i, [`${'device_security-fortify-computer'}:5`]: /Find My/i,
};

test('every row names a real game mission step, a real module, and platforms that module runs on', async () => {
  const ALL = ['darwin', 'win32', 'linux'];
  const { VERIFIED_MISSIONS } = await load();
  const { MISSIONS } = await loadRcFromDisk();
  const PLAT = { darwin: 'DARWIN', win32: 'WIN32', linux: 'LINUX' };
  for (const [id, rows] of Object.entries(VERIFIED_MISSIONS)) {
    const m = MISSIONS.find((x) => x.id === id);
    assert.ok(m, `mission gone upstream: ${id}`);
    for (const row of rows) {
      assert.ok(row.appliesTo.length && row.appliesTo.every((p) => ALL.includes(p)), `${id} step ${row.step} appliesTo`);
      assert.ok(row.checkedOn.length && row.checkedOn.every((p) => row.appliesTo.includes(p)), `${id} step ${row.step} is checked only where it applies`);
      assert.ok(row.step >= 0 && row.step < m.steps.length, `${id} step ${row.step}`);
      assert.match(JSON.stringify(m.steps[row.step]), SUBJECT[`${id}:${row.step}`], `${id} step ${row.step} is about something else now`);
      for (const mod of row.modules) {
        const dir = moduleDir(mod);
        assert.ok(dir, `module missing: ${mod}`);
        const src = fs.readFileSync(path.join(dir, '__init__.py'), 'utf8');
        const decl = src.split('\n').find((l) => /^\s*platforms\s*=/.test(l)) || '';
        for (const p of row.checkedOn) assert.match(decl, new RegExp(`Platform\\.${PLAT[p]}\\b`), `${mod} declares ${p}`);
      }
    }
  }
});

test('DONE matches the game', async () => {
  const { DONE } = await load();
  const { DONE_STATUSES } = await loadRcFromDisk();
  assert.deepStrictEqual([...DONE].sort(), [...DONE_STATUSES].sort());
});

test('Harden Your Computer on a Mac: confirmed, problem, couldnt, other platform', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check'), FV, ok('find_my_mac_check', [warn({ severity: 'critical' })])), 6);
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.strictEqual(by[0], 'confirmed');
  assert.strictEqual(by[1], 'other-platform');
  assert.strictEqual(by[2], 'other-platform');
  assert.strictEqual(by[3], 'other-platform');
  assert.strictEqual(by[4], 'couldnt', 'screen_lock_check and lock_screen_check were not in this scan');
  assert.strictEqual(by[5], 'problem');
  assert.strictEqual(v.steps.find((s) => s.step === 5).problems[0].module, 'find_my_mac_check');
  assert.strictEqual(v.allConfirmed, false);
});

test('a module that errored or could not run never confirms', async () => {
  const { verifyMission } = await load();
  for (const bad of [{ name: 'encryption_check', status: 'error', error: 'x', findings: [] }, { name: 'encryption_check', status: 'ok', supported: false, findings: [] }]) {
    const v = verifyMission(FC, mac(bad, FV), 6);
    assert.strictEqual(v.steps.find((s) => s.step === 0).status, 'couldnt');
  }
});

test('all Mac steps confirmed means the mission can be finished from the scan', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check'), FV, LOCK, ok('lock_screen_check'), FMM), 6);
  assert.strictEqual(v.allConfirmed, true);
  assert.strictEqual(v.partial, false);
  assert.strictEqual(verifyMission(FC, mac(ok('encryption_check'), FV, LOCK, ok('lock_screen_check'), FMM)).allConfirmed, false, 'unknown step count never finishes a mission');
});

test('Windows uses the BitLocker steps; the all-platform steps are the person\'s, so it never finishes', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, { platform: 'win32', modules: [BL] }, 6);
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.deepStrictEqual([by[0], by[1], by[2], by[3], by[4], by[5]], ['other-platform', 'confirmed', 'confirmed', 'other-platform', 'yours', 'yours'],
    'password after sleep (all platforms) and Find My (Mac and Windows) apply on Windows, but nothing here checks them');
  assert.deepStrictEqual(v.steps.find((s) => s.step === 0).appliesTo, ['darwin']);
  assert.strictEqual(v.allConfirmed, false, 'BitLocker alone never finishes Harden Your Computer');
  assert.strictEqual(v.partial, true);
});

test('Linux never finishes Harden Your Computer from the scan', async () => {
  const { verifyMission } = await load();
  const LUKS = ok('linux_disk_encryption_check', [E('encrypted', { data: { mount_points: ['/'] } })]);
  const v = verifyMission(FC, { platform: 'linux', modules: [LUKS] }, 6);
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.deepStrictEqual([by[0], by[1], by[2], by[3], by[4], by[5]], ['other-platform', 'other-platform', 'other-platform', 'confirmed', 'yours', 'other-platform'],
    'Find My is for Mac and Windows; the screen lock step is for every computer');
  assert.deepStrictEqual(v.steps.find((s) => s.step === 5).appliesTo, ['darwin', 'win32']);
  assert.strictEqual(v.allConfirmed, false);
  assert.strictEqual(v.partial, true);
});

test('a mission with no rows (the router) is not verified', async () => {
  const { verifyMission, VERIFIED_MISSIONS } = await load();
  assert.strictEqual(VERIFIED_MISSIONS['smart_network-recon-router'], undefined,
    'router_manual_review only means one SSDP packet got no reply; it proves nothing about UPnP');
  assert.strictEqual(verifyMission('smart_network-recon-router', mac(ok('router_security_audit', [E('router_manual_review')])), 6), null);
});

test('a finding the person marked as theirs is still a problem, so the step never confirms', async () => {
  const { verifyMission } = await load();
  const marked = { title: 'Marked as yours', severity: 'info', code: 'security.encryption_check.os_drive_not_encrypted', data: { marked_by_user: true } };
  const v = verifyMission(FC, mac(ok('encryption_check', [marked]), FV, LOCK, ok('lock_screen_check'), FMM), 6);
  const s0 = v.steps.find((s) => s.step === 0);
  assert.strictEqual(s0.status, 'problem');
  assert.strictEqual(s0.problems[0].title, 'Marked as yours');
  assert.strictEqual(v.allConfirmed, false);
  const markedLock = { title: 'm', severity: 'info', data: { check: 'screen_lock_required', value: 'enabled', marked_by_user: true } };
  const lockOnly = verifyMission(FC, mac(ok('screen_lock_check', [markedLock]), ok('lock_screen_check')), 6);
  assert.strictEqual(lockOnly.steps.find((s) => s.step === 4).status, 'problem', 'a marked finding is never read as evidence it is fine');
});

test('a module that ran and said nothing does not confirm a step that needs evidence', async () => {
  const { verifyMission } = await load();
  const by = (doc) => Object.fromEntries(verifyMission(FC, doc, 6).steps.map((s) => [s.step, s.status]));
  const silent = by(mac(ok('encryption_check'), ok('filevault_recovery'), ok('screen_lock_check'), ok('lock_screen_check'), ok('find_my_mac_check')));
  assert.deepStrictEqual([silent[0], silent[4], silent[5]], ['couldnt', 'couldnt', 'couldnt']);
  assert.strictEqual(by({ platform: 'win32', modules: [ok('win_bitlocker_check')] })[1], 'couldnt');
  const lin = (findings) => by({ platform: 'linux', modules: [ok('linux_disk_encryption_check', findings)] })[3];
  assert.strictEqual(lin([]), 'couldnt');
  assert.strictEqual(lin([E('encryption_undetermined')]), 'couldnt');
  assert.strictEqual(lin([E('encrypted', { data: { mount_points: ['/home'] } })]), 'couldnt', 'only /home is not the main drive');
  assert.strictEqual(lin([E('encrypted', { data: { mount_points: ['/'] } })]), 'confirmed');
  assert.strictEqual(by(mac(ok('encryption_check'), ok('filevault_recovery', [E('fv_disabled')])))[0], 'couldnt', 'FileVault off is not proof it is on');
  assert.strictEqual(by(mac(ok('screen_lock_check', [E('screen_lock_required', { data: { value: 'disabled' } })])))[4], 'couldnt');
});

test('a mission with no row, or no scan, is not verified', async () => {
  const { verifyMission } = await load();
  assert.strictEqual(verifyMission('gmail-recon-breach', mac()), null);
  assert.strictEqual(verifyMission(FC, null, 6).steps.every((s) => s.status === 'couldnt'), true);
});

test('a disagreement shows both sides and never changes the record', async () => {
  const { verifyMission, disagreement } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check', [warn({ title: 'FileVault is off' })]), FV), 6);
  const record = Object.freeze({ status: 'completed', action: 'completed', completedAt: '2026-10-09T10:00:00Z' });
  const before = JSON.stringify(record);
  const d = disagreement(record, v);
  assert.strictEqual(d.reportedAt, '2026-10-09T10:00:00Z');
  assert.strictEqual(d.problems[0].title, 'FileVault is off');
  assert.strictEqual(JSON.stringify(record), before);
  assert.strictEqual(disagreement({ status: 'skipped' }, v), null, 'not reported done: nothing to disagree with');
  assert.strictEqual(disagreement(undefined, v), null);
  assert.strictEqual(disagreement(record, verifyMission(FC, mac(ok('encryption_check'), FV), 6)), null);
});

test('the scan-confirmed store survives junk and blocked storage', async () => {
  const { loadScanConfirmed, saveScanConfirmed, markScanConfirmed, SCAN_CONFIRMED_KEY } = await load();
  const mem = {}; const s = { getItem: (k) => mem[k] ?? null, setItem: (k, v) => { mem[k] = v; } };
  const store = markScanConfirmed(loadScanConfirmed(s), FC, '2026-10-16T00:00:00Z');
  assert.strictEqual(saveScanConfirmed(s, store), true);
  assert.deepStrictEqual(loadScanConfirmed(s).missions[FC], { at: '2026-10-16T00:00:00Z' });
  const empty = { version: 1, missions: {} };
  assert.deepStrictEqual(loadScanConfirmed({ getItem: () => '{nope' }), empty);
  assert.deepStrictEqual(loadScanConfirmed({ getItem: () => '{"version":2,"missions":{}}' }), empty);
  assert.deepStrictEqual(loadScanConfirmed({ getItem() { throw new Error('x'); } }), empty);
  assert.strictEqual(saveScanConfirmed({ setItem() { throw new Error('x'); } }, store), false);
  assert.ok(SCAN_CONFIRMED_KEY.startsWith('device-rescue.game.'));
});
