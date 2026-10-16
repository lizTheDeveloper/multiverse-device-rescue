// Steps of Reclaim City missions that a check on this computer can confirm.
// Each row is one step of one game mission (its index in mission.steps), the
// platforms it applies to, and the Device Rescue modules that look at it. A row
// with dataCheck only counts findings whose data.check matches (the network
// modules give no finding codes). A test proves every mission, step, module,
// platform and data.check here is real.
//
// Left out on purpose: App Permission Audit (phone-only steps) and encrypted DNS
// (phone/browser/router steps; the scan reads this computer's system DNS). See
// the spec's "Changes made during planning".
export const VERIFIED_MISSIONS = {
  'device_security-fortify-computer': [
    { step: 0, platforms: ['darwin'], modules: ['encryption_check', 'filevault_recovery'], claim: 'FileVault is on' },
    { step: 1, platforms: ['win32'], modules: ['win_bitlocker_check'], claim: 'BitLocker is on for your drives' },
    { step: 2, platforms: ['win32'], modules: ['win_bitlocker_check'], claim: 'Your drive is encrypted' },
    { step: 3, platforms: ['linux'], modules: ['linux_disk_encryption_check'], claim: 'Your disk is encrypted' },
    { step: 4, platforms: ['darwin'], modules: ['screen_lock_check', 'lock_screen_check'], claim: 'A password is needed after sleep or the screen saver' },
    { step: 5, platforms: ['darwin'], modules: ['find_my_mac_check'], claim: 'Find My Mac is on' },
  ],
  'smart_network-recon-router': [
    { step: 3, platforms: ['darwin', 'win32', 'linux'], modules: ['router_security_audit'], dataCheck: 'upnp_enabled', claim: 'Your router didn’t answer UPnP requests from this computer' },
  ],
};
export const DONE = new Set(['completed', 'not-needed']);
export const SCAN_CONFIRMED_KEY = 'device-rescue.game.scan-confirmed.v1';
const SERIOUS = new Set(['warning', 'critical']);

function moduleIn(doc, name) {
  return (doc && Array.isArray(doc.modules) ? doc.modules : []).find((m) => m && m.name === name) || null;
}

export function problemFindings(doc, row) {
  const out = [];
  for (const name of row.modules) {
    const mod = moduleIn(doc, name);
    for (const f of (mod && Array.isArray(mod.findings) ? mod.findings : [])) {
      if (!f || !SERIOUS.has(f.severity)) continue;
      if (row.dataCheck && !(f.data && f.data.check === row.dataCheck)) continue;
      out.push({ ...f, module: name });
    }
  }
  return out;
}

export function stepStatus(doc, row) {
  if (!doc || !row.platforms.includes(doc.platform)) return doc ? 'other-platform' : 'couldnt';
  for (const name of row.modules) {
    const mod = moduleIn(doc, name);
    if (!mod || mod.status !== 'ok' || mod.supported !== true) return 'couldnt';
  }
  return problemFindings(doc, row).length ? 'problem' : 'confirmed';
}

export function verifyMission(missionId, doc) {
  const rows = VERIFIED_MISSIONS[missionId];
  if (!rows) return null;
  const steps = rows.map((row) => {
    const status = stepStatus(doc, row);
    return { step: row.step, status, claim: row.claim, modules: row.modules, problems: status === 'problem' ? problemFindings(doc, row) : [] };
  });
  const relevant = steps.filter((s) => s.status !== 'other-platform');
  return { steps, allConfirmed: relevant.length > 0 && relevant.every((s) => s.status === 'confirmed') };
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
