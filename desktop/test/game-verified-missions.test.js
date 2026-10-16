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
const FC = 'device_security-fortify-computer';
const ROUTER = 'smart_network-recon-router';

function moduleDir(name) {
  for (const cat of fs.readdirSync(path.join(ROOT, 'modules'))) {
    const p = path.join(ROOT, 'modules', cat, name);
    if (fs.existsSync(p)) return p;
  }
  return null;
}

test('every row names a real game mission step, a real module, and platforms that module runs on', async () => {
  const { VERIFIED_MISSIONS } = await load();
  const { MISSIONS } = await loadRcFromDisk();
  const PLAT = { darwin: 'DARWIN', win32: 'WIN32', linux: 'LINUX' };
  for (const [id, rows] of Object.entries(VERIFIED_MISSIONS)) {
    const m = MISSIONS.find((x) => x.id === id);
    assert.ok(m, `mission gone upstream: ${id}`);
    for (const row of rows) {
      assert.ok(row.step >= 0 && row.step < m.steps.length, `${id} step ${row.step}`);
      for (const mod of row.modules) {
        const dir = moduleDir(mod);
        assert.ok(dir, `module missing: ${mod}`);
        const src = fs.readFileSync(path.join(dir, '__init__.py'), 'utf8');
        for (const p of row.platforms) assert.match(src, new RegExp(`Platform\\.${PLAT[p]}`), `${mod} on ${p}`);
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
  const v = verifyMission(FC, mac(ok('encryption_check'), ok('filevault_recovery'), ok('find_my_mac_check', [warn({ severity: 'critical' })])));
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
    const v = verifyMission(FC, mac(bad, ok('filevault_recovery')));
    assert.strictEqual(v.steps.find((s) => s.step === 0).status, 'couldnt');
  }
});

test('all Mac steps confirmed means the mission can be finished from the scan', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check'), ok('filevault_recovery'), ok('screen_lock_check'), ok('lock_screen_check'), ok('find_my_mac_check', [{ severity: 'info', data: {} }])));
  assert.strictEqual(v.allConfirmed, true);
});

test('Windows uses the BitLocker steps and leaves the Mac ones alone', async () => {
  const { verifyMission } = await load();
  const v = verifyMission(FC, { platform: 'win32', modules: [ok('win_bitlocker_check')] });
  const by = Object.fromEntries(v.steps.map((s) => [s.step, s.status]));
  assert.deepStrictEqual([by[0], by[1], by[2], by[4], by[5]], ['other-platform', 'confirmed', 'confirmed', 'other-platform', 'other-platform']);
});

test('the router step only looks at the UPnP finding', async () => {
  const { verifyMission } = await load();
  const upnp = verifyMission(ROUTER, mac(ok('router_security_audit', [warn({ data: { check: 'upnp_enabled' } })])));
  assert.strictEqual(upnp.steps[0].status, 'problem');
  const admin = verifyMission(ROUTER, mac(ok('router_security_audit', [warn({ data: { check: 'admin_service_open' } })])));
  assert.strictEqual(admin.steps[0].status, 'confirmed');
  assert.strictEqual(verifyMission(ROUTER, mac()).steps[0].status, 'couldnt');
});

test('a mission with no row, or no scan, is not verified', async () => {
  const { verifyMission } = await load();
  assert.strictEqual(verifyMission('gmail-recon-breach', mac()), null);
  assert.strictEqual(verifyMission(FC, null).steps.every((s) => s.status === 'couldnt' || s.status === 'other-platform'), true);
});

test('a disagreement shows both sides and never changes the record', async () => {
  const { verifyMission, disagreement } = await load();
  const v = verifyMission(FC, mac(ok('encryption_check', [warn({ title: 'FileVault is off' })]), ok('filevault_recovery')));
  const record = Object.freeze({ status: 'completed', action: 'completed', completedAt: '2026-10-09T10:00:00Z' });
  const before = JSON.stringify(record);
  const d = disagreement(record, v);
  assert.strictEqual(d.reportedAt, '2026-10-09T10:00:00Z');
  assert.strictEqual(d.problems[0].title, 'FileVault is off');
  assert.strictEqual(JSON.stringify(record), before);
  assert.strictEqual(disagreement({ status: 'skipped' }, v), null, 'not reported done: nothing to disagree with');
  assert.strictEqual(disagreement(undefined, v), null);
  assert.strictEqual(disagreement(record, verifyMission(FC, mac(ok('encryption_check'), ok('filevault_recovery')))), null);
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
