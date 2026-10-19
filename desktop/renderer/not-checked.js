'use strict';

/*
 * What a scan didn't fully check, by one rule for the Plain list and the city,
 * so the two can never count it differently:
 *
 *   couldntRun  checks that couldn't run (status "error", "supported": false),
 *               and monitoring checks that couldn't look (no iPhone backup, no
 *               scanner, a scan that wasn't run) and found nothing;
 *   unfinished  checks that ran but stopped before the end ("complete": false);
 *   partly      notes that say part of a check couldn't look ("We couldn't
 *               list your USB devices", "Checked 16 of 110 app signatures").
 *
 *   notStarted  opt-in checks that can run here but weren't started (an iPhone
 *               backup is on this computer; its long spyware scan asks first):
 *               neither "couldn't run" nor clean. The engine says
 *               "not_started": true; older scans are read by the
 *               mvt_scan_available note. (The city still shows it as fog:
 *               couldntLook stays true for it.)
 *
 *   NotChecked.isPartlyChecked(finding) -> boolean
 *   NotChecked.couldntLook(module) -> boolean
 *   NotChecked.notStarted(module) -> boolean
 *   NotChecked.notCheckedParts(doc) -> { couldntRun: [{name, error}], unfinished: [{name}],
 *       notStarted: [{name}], partly: [{name, title}] }
 *   NotChecked.notCheckedSummary(doc) -> { checks, couldntRun, unfinished, notStarted, partly, count }
 *   NotChecked.notCheckedLine(summary) -> the top line, '' when everything was checked
 *
 * One count for both views (so LAST SWEEP, the chips, the district badges,
 * the Plain list and its progress can never disagree):
 *
 *   NotChecked.shownSeverity(finding) -> 'critical' | 'warning' | 'info'
 *       (critical only for security and network; the Plain list's rule)
 *   NotChecked.isHeld(finding, module) -> boolean   (game/held.js's rule)
 *   NotChecked.itemKey(finding, module) -> string   one key per item: the
 *       engine's same_key (one thing seen by several checks), else the check,
 *       the finding's code (or title) and the thing it names. Monitoring
 *       findings never share a key.
 *   NotChecked.scanCounts(doc, { mode, districtOf }) -> {
 *       checks,        every check in the scan (each counted once)
 *       ran,           checks that ran (checks - couldntRun - notStarted)
 *       couldntRun, unfinished, notStarted, partly,   as notCheckedSummary
 *       didntFinish,   couldntRun + unfinished: "N COULDN'T RUN OR DIDN'T FINISH"
 *       notFully,      checks not fully checked, each once (any of the four)
 *       critical, warning, info,   findings by shownSeverity
 *       items,         distinct critical + warning items (itemKey)
 *       marked,        findings the person marked as theirs
 *       held,          held monitoring findings; in mode 'city' they are left
 *                      out of critical/warning/info/items (never shown there)
 *       byDistrict: { [districtOf(category)]: { couldntRun, unfinished,
 *                      notStarted, partly, notFully, critical, warning, items } }
 *     }
 *     `districtOf(category)` maps a check's category to a district id (the
 *     city passes findings-to-city's districtIdFor); default: the category.
 *
 * Loaded as a plain script (global `NotChecked`, also on window/globalThis);
 * the game's ES modules `import '../not-checked.js'` and read globalThis.NotChecked;
 * tested from Node.
 */
const NotChecked = (function () {
  // The same three checks as app.js's ALWAYS_SAFETY_MODULES and game/held.js.
  const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

  // What those checks say when they found nothing or couldn't look
  // (QuietNotes' NOT_DETECTIONS; a test keeps them equal).
  const NOT_DETECTIONS = new Set([
    'security.mvt_spyware_scan.mvt_requires_wsl',
    'security.mvt_spyware_scan.no_backups_found',
    'security.mvt_spyware_scan.mvt_not_installed',
    'security.mvt_spyware_scan.mvt_scan_available',
    'security.mvt_spyware_scan.mvt_backup_too_large',
    'security.mvt_spyware_scan.mvt_clean_scan',
    'security.keylogger_indicators.input_monitoring_access',
  ]);
  // Of those, the lines that mean the check couldn't look at all.
  const COULDNT_LOOK = new Set([
    'security.mvt_spyware_scan.mvt_requires_wsl',
    'security.mvt_spyware_scan.no_backups_found',
    'security.mvt_spyware_scan.mvt_not_installed',
    'security.mvt_spyware_scan.mvt_scan_available',
    'security.mvt_spyware_scan.mvt_backup_too_large',
  ]);
  const COULDNT_LOOK_REASON = 'This check couldn’t look here.';

  const COULDNT_TITLE = /^(?:we\s+)?(?:couldn[’']t|could\s+not)\s+(?:check|list|read|see|tell|find\s+out)\b/i;

  function isPartlyChecked(finding) {
    if (!finding || finding.severity !== 'info') return false;
    const title = String(finding.title || '');
    if (COULDNT_TITLE.test(title)) return true;
    return !!(finding.data && finding.data.incomplete) && /^checked\s+\d+\s+of\s+\d+/i.test(title);
  }

  // A monitoring finding that says software is there (QuietNotes.isDetection).
  function isDetection(f) {
    if (!f) return false;
    if (f.code) return !NOT_DETECTIONS.has(f.code);
    return f.severity !== 'info';
  }

  // A monitoring check that ran but couldn't look, and found nothing: never clear.
  function couldntLook(mod) {
    if (!mod || !MONITORING_MODULES.has(mod.name) || mod.status === 'error' || mod.supported === false) return false;
    const fs = Array.isArray(mod.findings) ? mod.findings.filter(Boolean) : [];
    return fs.some((f) => COULDNT_LOOK.has(f.code)) && !fs.some(isDetection);
  }

  const NOT_STARTED_CODE = 'security.mvt_spyware_scan.mvt_scan_available';

  // An opt-in check that can run here but wasn't started, and found nothing.
  function notStarted(mod) {
    if (!mod || mod.status === 'error' || mod.supported === false) return false;
    const fs = Array.isArray(mod.findings) ? mod.findings.filter(Boolean) : [];
    if (MONITORING_MODULES.has(mod.name) && fs.some(isDetection)) return false;
    if (mod.not_started === true) return true;
    return mod.name === 'mvt_spyware_scan' && fs.some((f) => f.code === NOT_STARTED_CODE);
  }

  function notCheckedParts(doc) {
    const couldntRun = [];
    const unfinished = [];
    const started = [];
    const partly = [];
    const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
    for (const mod of modules) {
      if (!mod) continue;
      if (mod.status === 'error') couldntRun.push({ name: mod.name, error: mod.error || null });
      else if (mod.supported === false) couldntRun.push({ name: mod.name, error: mod.unsupported_reason || null });
      else if (notStarted(mod)) started.push({ name: mod.name });
      else if (couldntLook(mod)) couldntRun.push({ name: mod.name, error: COULDNT_LOOK_REASON });
      else if (mod.complete === false) unfinished.push({ name: mod.name });
      for (const f of Array.isArray(mod.findings) ? mod.findings : []) {
        if (isPartlyChecked(f)) partly.push({ name: mod.name, title: String(f.title || '') });
      }
    }
    return { couldntRun, unfinished, notStarted: started, partly };
  }

  function notCheckedSummary(doc) {
    const p = notCheckedParts(doc);
    const checks = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean).length : 0;
    return {
      checks,
      couldntRun: p.couldntRun.length,
      unfinished: p.unfinished.length,
      notStarted: p.notStarted.length,
      partly: p.partly.length,
      count: p.couldntRun.length + p.unfinished.length + p.notStarted.length + p.partly.length,
    };
  }

  // The top line when something wasn't fully checked. Never an all-clear.
  function notCheckedLine(sum) {
    const s = sum || {};
    const ran = (s.couldntRun || 0) + (s.unfinished || 0);
    const how = s.couldntRun && s.unfinished ? 'couldn’t run or didn’t finish' : s.couldntRun ? 'couldn’t run' : 'didn’t finish';
    const parts = [];
    if (ran) parts.push(`${ran} ${ran === 1 ? 'check' : 'checks'} ${how}`);
    if (s.notStarted) parts.push(`${s.notStarted} ${s.notStarted === 1 ? 'check waits' : 'checks wait'} for your go-ahead`);
    if (s.partly) parts.push(`${s.partly} ${s.partly === 1 ? 'thing was' : 'things were'} only partly checked`);
    if (!parts.length) return '';
    return `${parts.join(', and ')}, so this isn’t a clean bill of health.`;
  }

  // The Plain list's severity rule: critical only where it is an alarm.
  const ALARM_CATEGORIES = new Set(['security', 'network']);
  const SEVERITIES = new Set(['critical', 'warning', 'info']);
  function shownSeverity(f) {
    const sev = f && SEVERITIES.has(f.severity) ? f.severity : 'info';
    return sev === 'critical' && !ALARM_CATEGORIES.has(f.category) ? 'warning' : sev;
  }

  // game/held.js's rule, here so the counts can leave held findings out.
  const FAMILIAR_CODE = 'security.keylogger_indicators.suspicious_input_monitoring';
  const FAMILIAR_CHECK = 'claimed_vendor_input_monitoring';
  // A full path: the file attribution checked. A bundle id is not one: it is
  // the name a TCC row's client reports about itself, and the signature of
  // whichever app declares that id says nothing about the program holding the
  // access (rescue/serialize.py _app_subject says the same).
  const isPathSubject = (a) => typeof a === 'string' && (/^[/~]/.test(a) || /^[A-Za-z]:[\\/]/.test(a));
  function familiarVerified(f, module = f && f.module) {
    if (!f || f.severity !== 'info' || f.code !== FAMILIAR_CODE || module !== 'keylogger_indicators') return false;
    if (f.makers_verified === false) return false;
    const d = f.data && typeof f.data === 'object' ? f.data : {};
    const apps = Array.isArray(d.apps) ? d.apps : [];
    if (!apps.every(isPathSubject)) return false;
    const mb = Array.isArray(f.made_by) ? f.made_by.filter(Boolean) : [];
    const known = (m) => m.verified === true && typeof m.what === 'string' && m.what.trim() !== ''
      && typeof m.name === 'string' && m.name.trim() !== '';
    return d.check === FAMILIAR_CHECK && apps.length > 0 && mb.length > 0 && mb.every(known)
      && apps.every((a) => mb.some((m) => m.subject === a));
  }
  function isHeld(f, module = f && f.module) {
    return !!f && MONITORING_MODULES.has(module) && isDetection(f) && !familiarVerified(f, module);
  }

  const SUBJECT_KEYS = ['label', 'plist', 'path', 'program', 'bundle_id', 'extension_id', 'name', 'target', 'id'];
  const norm = (t) => String(t || '').toLowerCase().replace(/\(\d+(?: of \d+)?\)/g, ' ').replace(/[^a-z0-9]+/g, ' ').trim();
  function itemKey(f, module = f && f.module) {
    const fd = f || {};
    const data = fd.data && typeof fd.data === 'object' ? fd.data : {};
    let subject = '';
    for (const k of SUBJECT_KEYS) if (typeof data[k] === 'string' && data[k] !== '') { subject = `${k}=${data[k]}`; break; }
    const what = fd.code || norm(fd.title);
    if (MONITORING_MODULES.has(module)) return `m|${module}|${what}|${norm(fd.title)}|${subject}`;
    if (typeof fd.same_key === 'string' && fd.same_key) return `same|${fd.same_key}`;
    return `${module}|${what}|${subject}`;
  }

  function scanCounts(doc, { mode = 'standard', districtOf = (c) => c || 'other' } = {}) {
    const city = mode === 'city';
    const modules = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean) : [];
    const p = notCheckedParts(doc);
    const cats = new Map(modules.map((m) => [m.name, m.category]));
    const out = {
      checks: modules.length, ran: 0,
      couldntRun: p.couldntRun.length, unfinished: p.unfinished.length,
      notStarted: p.notStarted.length, partly: p.partly.length,
      didntFinish: p.couldntRun.length + p.unfinished.length, notFully: 0,
      critical: 0, warning: 0, info: 0, items: 0, marked: 0, held: 0, byDistrict: {},
    };
    out.ran = out.checks - out.couldntRun - out.notStarted;
    const district = (name) => {
      const id = districtOf(cats.get(name) || null);
      if (!out.byDistrict[id]) out.byDistrict[id] = { couldntRun: 0, unfinished: 0, notStarted: 0, partly: 0, notFully: 0, critical: 0, warning: 0, items: 0 };
      return out.byDistrict[id];
    };
    const notFully = new Set();
    for (const [part, list] of [['couldntRun', p.couldntRun], ['unfinished', p.unfinished], ['notStarted', p.notStarted]]) {
      for (const x of list) { district(x.name)[part] += 1; notFully.add(x.name); }
    }
    const partlyMods = new Set(p.partly.map((x) => x.name));
    for (const name of partlyMods) { district(name).partly += 1; notFully.add(name); }
    for (const name of notFully) district(name).notFully += 1;
    out.notFully = notFully.size;

    const keys = new Map(); // itemKey -> district id
    for (const mod of modules) {
      for (const f of Array.isArray(mod.findings) ? mod.findings : []) {
        if (!f || typeof f !== 'object' || isPartlyChecked(f)) continue;
        if (isHeld(f, mod.name)) {
          out.held += 1;
          if (city) continue;
        }
        if (f.data && f.data.marked_by_user === true) out.marked += 1;
        const sev = shownSeverity(f);
        out[sev] += 1;
        if (sev === 'info') continue;
        district(mod.name)[sev] += 1;
        const key = itemKey(f, mod.name);
        if (!keys.has(key)) keys.set(key, mod.name);
      }
    }
    out.items = keys.size;
    for (const name of keys.values()) district(name).items += 1;
    return out;
  }

  return {
    MONITORING_MODULES, NOT_DETECTIONS, COULDNT_LOOK, COULDNT_LOOK_REASON, NOT_STARTED_CODE,
    isPartlyChecked, isDetection, couldntLook, notStarted, notCheckedParts, notCheckedSummary, notCheckedLine,
    shownSeverity, familiarVerified, isPathSubject, isHeld, itemKey, scanCounts,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = NotChecked;
}
// A top-level const isn't a window property. The game's ES modules import this
// file for its side effect and read it from globalThis (window in the app).
if (typeof globalThis !== 'undefined') {
  globalThis.NotChecked = NotChecked;
}
