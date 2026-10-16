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
const ROUTER = 'smart_network-recon-router';

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
  [`${'smart_network-recon-router'}:3`]: /UPnP/i,
};

test('every row names a real game mission step, a real module, and platforms that module runs on', async () => {
  const { VERIFIED_MISSIONS } = await load();
  const { MISSIONS } = await loadRcFromDisk();
  const PLAT = { darwin: 'DARWIN', win32: 'WIN32', linux: 'LINUX' };
  for (const [id, rows] of Object.entries(VERIFIED_MISSIONS)) {
    const m = MISSIONS.find((x) => x.id === id);
    assert.ok(m, `mission gone upstream: ${id}`);
    for (const row of rows) {
      assert.ok(row.step >= 0 && row.step < m.steps.length, `${id} step ${row.step}`);
      assert.match(JSON.stringify(m.steps[row.step]), SUBJECT[`${id}:${row.step}`], `${id} step ${row.step} is about something else now`);
      for (const mod of row.modules) {
        const dir = moduleDir(mod);
        assert.ok(dir, `module missing: ${mod}`);
        const src = fs.readFileSync(path.join(dir, '__init__.py'), 'utf8');
        const decl = src.split('\n').find((l) => /^\s*platforms\s*=/.test(l)) || '';
        for (const p of row.platforms) assert.match(decl, new RegExp(`Platform\\.${PLAT[p]}\\b`), `${mod} declares ${p}`);
        if (row.dataCheck) assert.ok(src.includes(`"${row.dataCheck}"`), `${mod} never emits check ${row.dataCheck}`);
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

test('Windows uses the BitLocker steps and leaves the Mac ones alone', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, { platform: 'win32', modules: [BL] }, 6);
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.deepStrictEqual([by[0], by[1], by[2], by[4], by[5]], ['other-platform', 'confirmed', 'confirmed', 'other-platform', 'other-platform']);
  assert.deepStrictEqual(v.steps.find((s) => s.step === 0).platforms, ['darwin']);
});

test('the router step only looks at the UPnP finding', async () => {
  const { verifyMission } = await load();
  const REMINDER = E('router_manual_review');
  const upnp = verifyMission(ROUTER, mac(ok('router_security_audit', [warn({ data: { check: 'upnp_enabled' } }), REMINDER])), 6);
  assert.strictEqual(upnp.steps[0].status, 'problem');
  const admin = verifyMission(ROUTER, mac(ok('router_security_audit', [warn({ data: { check: 'admin_service_open' } }), REMINDER])), 6);
  assert.strictEqual(admin.steps[0].status, 'confirmed');
  assert.strictEqual(verifyMission(ROUTER, mac(), 6).steps[0].status, 'couldnt');
});

test('a clean UPnP probe alone does not finish the six-step router mission', async () => {
  const { verifyMission } = await load();
  const n = await stepsOf(ROUTER);
  assert.strictEqual(n, 6);
  const v = verifyMission(ROUTER, mac(ok('router_security_audit', [E('router_manual_review')])), n);
  assert.strictEqual(v.steps[0].status, 'confirmed');
  assert.strictEqual(v.allConfirmed, false);
  assert.strictEqual(v.partial, true);
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
  assert.strictEqual(verifyMission(FC, null, 6).steps.every((s) => s.status === 'couldnt' || s.status === 'other-platform'), true);
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
