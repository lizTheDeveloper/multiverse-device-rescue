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
 *   NotChecked.isPartlyChecked(finding) -> boolean
 *   NotChecked.couldntLook(module) -> boolean
 *   NotChecked.notCheckedParts(doc) -> { couldntRun: [{name, error}], unfinished: [{name}], partly: [{name, title}] }
 *   NotChecked.notCheckedSummary(doc) -> { checks, couldntRun, unfinished, partly, count }
 *   NotChecked.notCheckedLine(summary) -> the top line, '' when everything was checked
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

  function notCheckedParts(doc) {
    const couldntRun = [];
    const unfinished = [];
    const partly = [];
    const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
    for (const mod of modules) {
      if (!mod) continue;
      if (mod.status === 'error') couldntRun.push({ name: mod.name, error: mod.error || null });
      else if (mod.supported === false) couldntRun.push({ name: mod.name, error: mod.unsupported_reason || null });
      else if (couldntLook(mod)) couldntRun.push({ name: mod.name, error: COULDNT_LOOK_REASON });
      else if (mod.complete === false) unfinished.push({ name: mod.name });
      for (const f of Array.isArray(mod.findings) ? mod.findings : []) {
        if (isPartlyChecked(f)) partly.push({ name: mod.name, title: String(f.title || '') });
      }
    }
    return { couldntRun, unfinished, partly };
  }

  function notCheckedSummary(doc) {
    const p = notCheckedParts(doc);
    const checks = doc && Array.isArray(doc.modules) ? doc.modules.filter(Boolean).length : 0;
    return {
      checks,
      couldntRun: p.couldntRun.length,
      unfinished: p.unfinished.length,
      partly: p.partly.length,
      count: p.couldntRun.length + p.unfinished.length + p.partly.length,
    };
  }

  // The top line when something wasn't fully checked. Never an all-clear.
  function notCheckedLine(sum) {
    const s = sum || {};
    const ran = (s.couldntRun || 0) + (s.unfinished || 0);
    const how = s.couldntRun && s.unfinished ? 'couldn’t run or didn’t finish' : s.couldntRun ? 'couldn’t run' : 'didn’t finish';
    const parts = [];
    if (ran) parts.push(`${ran} ${ran === 1 ? 'check' : 'checks'} ${how}`);
    if (s.partly) parts.push(`${s.partly} ${s.partly === 1 ? 'thing was' : 'things were'} only partly checked`);
    if (!parts.length) return '';
    return `${parts.join(', and ')}, so this isn’t a clean bill of health.`;
  }

  return {
    MONITORING_MODULES, NOT_DETECTIONS, COULDNT_LOOK, COULDNT_LOOK_REASON,
    isPartlyChecked, isDetection, couldntLook, notCheckedParts, notCheckedSummary, notCheckedLine,
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
