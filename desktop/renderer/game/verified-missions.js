// Steps of Reclaim City missions that a check on this computer can confirm.
// Each row is one step of one game mission (its index in mission.steps), the
// platforms the game says that step is for (appliesTo, from the step's own
// text), the platforms where its Device Rescue modules run (checkedOn), and the
// modules that look at it. A test proves every mission, step, module and
// platform here is real.
//
// A step for another kind of computer is 'other-platform'. A step that applies
// here but that no module checks here is 'yours': the person's to check, never
// settled, never confirmed.
//
// requires: positive evidence. Several modules say nothing when they can't read
// a setting (or find nothing to read), so "no problem reported" alone proves
// nothing. A step is confirmed only if each requirement matches a finding of any
// severity in that module: by data.check and/or code, and optionally
// data[includes.key] containing a value, or data[equals.key] equal to one.
// Left out on purpose: App Permission Audit (phone-only steps), encrypted DNS
// (phone/browser/router steps; the scan reads this computer's system DNS), and
// the router's UPnP step (router_security_audit's reminder only means one probe
// got no reply). See the spec's "Changes made during planning".
const ALL = ['darwin', 'win32', 'linux'];
export const VERIFIED_MISSIONS = {
  'device_security-fortify-computer': [
    { step: 0, appliesTo: ['darwin'], checkedOn: ['darwin'], modules: ['encryption_check', 'filevault_recovery'], requires: [{ module: 'filevault_recovery', check: 'fv_status' }], claim: 'FileVault is on' },
    { step: 1, appliesTo: ['win32'], checkedOn: ['win32'], modules: ['win_bitlocker_check'], requires: [{ module: 'win_bitlocker_check', code: 'security.win_bitlocker_check.status_info' }], claim: 'BitLocker is on for your drives' },
    { step: 2, appliesTo: ['win32'], checkedOn: ['win32'], modules: ['win_bitlocker_check'], requires: [{ module: 'win_bitlocker_check', code: 'security.win_bitlocker_check.status_info' }], claim: 'Your drive is encrypted' },
    { step: 3, appliesTo: ['linux'], checkedOn: ['linux'], modules: ['linux_disk_encryption_check'], requires: [{ module: 'linux_disk_encryption_check', check: 'encrypted', includes: { key: 'mount_points', value: '/' } }], claim: 'Your disk is encrypted' },
    // "All platforms: …password after sleep/screen saver"
    { step: 4, appliesTo: ALL, checkedOn: ['darwin'], modules: ['screen_lock_check', 'lock_screen_check'], requires: [{ module: 'screen_lock_check', check: 'screen_lock_required', equals: { key: 'value', value: 'enabled' } }], claim: 'A password is needed after sleep or the screen saver' },
    // "Enable Find My: Mac → … Windows → …"
    { step: 5, appliesTo: ['darwin', 'win32'], checkedOn: ['darwin'], modules: ['find_my_mac_check'], requires: [{ module: 'find_my_mac_check', code: 'security.find_my_mac_check.configured_ok' }], claim: 'Find My Mac is on' },
  ],
};
export const DONE = new Set(['completed', 'not-needed']);
export const SCAN_CONFIRMED_KEY = 'device-rescue.game.scan-confirmed.v1';
const SERIOUS = new Set(['warning', 'critical']);

function moduleIn(doc, name) {
  return (doc && Array.isArray(doc.modules) ? doc.modules : []).find((m) => m && m.name === name) || null;
}

// A finding the person marked as theirs is lowered to info by the engine, but
// it is still there, so it still counts as a problem.
const isProblem = (f) => !!f && (SERIOUS.has(f.severity) || !!(f.data && f.data.marked_by_user === true));

export function problemFindings(doc, row) {
  const out = [];
  for (const name of row.modules) {
    const mod = moduleIn(doc, name);
    for (const f of (mod && Array.isArray(mod.findings) ? mod.findings : [])) {
      if (!isProblem(f)) continue;
      out.push({ ...f, module: name });
    }
  }
  return out;
}

function hasEvidence(doc, req) {
  const mod = moduleIn(doc, req.module);
  return !!mod && Array.isArray(mod.findings) && mod.findings.some((f) => {
    if (!f || isProblem(f)) return false;
    const d = f.data || {};
    if (req.check && d.check !== req.check) return false;
    if (req.code && f.code !== req.code) return false;
    if (req.includes && !(Array.isArray(d[req.includes.key]) && d[req.includes.key].includes(req.includes.value))) return false;
    if (req.equals && d[req.equals.key] !== req.equals.value) return false;
    return true;
  });
}

export function stepStatus(doc, row) {
  if (!doc) return 'couldnt';
  if (!row.appliesTo.includes(doc.platform)) return 'other-platform';
  if (!row.checkedOn.includes(doc.platform)) return 'yours';
  for (const name of row.modules) {
    const mod = moduleIn(doc, name);
    if (!mod || mod.status !== 'ok' || mod.supported !== true) return 'couldnt';
  }
  if (problemFindings(doc, row).length) return 'problem';
  return (row.requires || []).every((r) => hasEvidence(doc, r)) ? 'confirmed' : 'couldnt';
}

export function verifyMission(missionId, doc, stepCount) {
  const rows = VERIFIED_MISSIONS[missionId];
  if (!rows) return null;
  const steps = rows.map((row) => {
    const status = stepStatus(doc, row);
    return { step: row.step, status, claim: row.claim, appliesTo: row.appliesTo, modules: row.modules, problems: status === 'problem' ? problemFindings(doc, row) : [] };
  });
  const anyConfirmed = steps.some((s) => s.status === 'confirmed');
  const covered = Number.isInteger(stepCount) && Array.from({ length: stepCount }, (_, i) => rows.some((r) => r.step === i)).every(Boolean);
  const settled = steps.every((s) => s.status === 'confirmed' || s.status === 'other-platform');
  const allConfirmed = covered && settled && anyConfirmed;
  return { steps, allConfirmed, partial: anyConfirmed && !allConfirmed };
}

export function disagreement(record, verification) {
  if (!record || !DONE.has(record.status) || !verification) return null;
  const problems = verification.steps.flatMap((s) => s.problems);
  return problems.length ? { reportedAt: record.completedAt || null, problems } : null;
}

const emptyStore = () => ({ version: 1, missions: {} });

export function loadScanConfirmed(storage) {
  try {
    const raw = storage ? storage.getItem(SCAN_CONFIRMED_KEY) : null;
    if (!raw) return emptyStore();
    const p = JSON.parse(raw);
    const ok = p && p.version === 1 && p.missions && typeof p.missions === 'object' && !Array.isArray(p.missions)
      && Object.values(p.missions).every((r) => r && typeof r.at === 'string');
    return ok ? p : emptyStore();
  } catch (_) {
    return emptyStore();
  }
}

export function saveScanConfirmed(storage, store) {
  try {
    storage.setItem(SCAN_CONFIRMED_KEY, JSON.stringify(store));
    return true;
  } catch (_) {
    return false;
  }
}

export function markScanConfirmed(store, id, now) {
  return { version: 1, missions: { ...store.missions, [id]: { at: now } } };
}
