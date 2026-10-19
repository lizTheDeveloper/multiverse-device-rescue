// Findings from the checks that look for monitoring software. The game never
// turns them into missions or signals, so nothing about them is scored or
// stored: in 'city' they wait in the generated district (memory only), and
// in 'standard' the list shows them with the one line. The same three checks
// as app.js's ALWAYS_SAFETY_MODULES; a test keeps them equal.
import { esc } from './escape.js';

export const HELD_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

// What those checks say when they found nothing or couldn't look (QuietNotes'
// NOT_DETECTIONS; a test keeps them equal). Never held: no software was found.
export const NOT_DETECTIONS = new Set([
  'security.mvt_spyware_scan.mvt_requires_wsl',
  'security.mvt_spyware_scan.no_backups_found',
  'security.mvt_spyware_scan.mvt_not_installed',
  'security.mvt_spyware_scan.mvt_scan_available',
  'security.mvt_spyware_scan.mvt_backup_too_large',
  'security.mvt_spyware_scan.mvt_clean_scan',
  'security.keylogger_indicators.input_monitoring_access',
]);

// Of those, the lines that mean the check couldn't look at all: no backups,
// no scanner, no Linux layer, a backup too large to read, or a scan that
// wasn't run. A check that couldn't look is never "clear": its module goes to
// the city as COULDN'T CHECK (fog), the same as a check that couldn't run.
export const COULDNT_LOOK = new Set([
  'security.mvt_spyware_scan.mvt_requires_wsl',
  'security.mvt_spyware_scan.no_backups_found',
  'security.mvt_spyware_scan.mvt_not_installed',
  'security.mvt_spyware_scan.mvt_scan_available',
  'security.mvt_spyware_scan.mvt_backup_too_large',
]);
// What the city says about it: plain, the same words as any check that couldn't run.
export const COULDNT_LOOK_REASON = 'This check couldn’t look here.';

// The same rule as QuietNotes.isDetection, for a finding of a held module.
export function isDetection(f) {
  if (!f) return false;
  if (f.code) return !NOT_DETECTIONS.has(f.code);
  return f.severity !== 'info';
}

// The one finding that may leave the help district: keyboard access for
// apps with familiar names (keylogger_indicators' claimed_vendor check), at
// info, when every app in it is a KNOWN program whose signed identity was
// verified. The engine gives `what` only then (rescue/attribution.py), so
// each app needs a made_by entry with verified === true and a `what`. A
// signature alone is cheap, so a signed but unknown maker stays held, and so
// does anything from the other monitoring checks, at any severity.
export const FAMILIAR_CODE = 'security.keylogger_indicators.suspicious_input_monitoring';
export const FAMILIAR_CHECK = 'claimed_vendor_input_monitoring';
export function familiarVerified(f, module = f && f.module) {
  if (!f || f.severity !== 'info' || f.code !== FAMILIAR_CODE || module !== 'keylogger_indicators') return false;
  const d = f.data && typeof f.data === 'object' ? f.data : {};
  const apps = Array.isArray(d.apps) ? d.apps : [];
  const mb = Array.isArray(f.made_by) ? f.made_by.filter(Boolean) : [];
  const known = (m) => m.verified === true && typeof m.what === 'string' && m.what.trim() !== ''
    && typeof m.name === 'string' && m.name.trim() !== '';
  return d.check === FAMILIAR_CHECK && apps.length > 0 && mb.length > 0 && mb.every(known)
    && apps.every((a) => mb.some((m) => m.subject === a));
}
const holds = (f, module) => !!f && isDetection(f) && !familiarVerified(f, module);

// What the help district shows about a held finding, so it can be written
// down: the name, where it was found, how it was found, and who made it. From
// the finding's own evidence; memory only, never stored.
export function heldEvidence(f) {
  const d = f && f.data && typeof f.data === 'object' ? f.data : {};
  const str = (v) => (typeof v === 'string' && v.trim() ? v.trim() : '');
  const list = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.trim()).join(', ') : '');
  const mb = Array.isArray(f && f.made_by) ? f.made_by.filter(Boolean) : [];
  const maker = mb.length ? mb.map((m) => `${str(m.name) || 'Unknown maker'}${m.verified === true ? ' (verified)' : ' (not verified)'}`)
    .filter((x, i, a) => a.indexOf(x) === i).join('; ') : '';
  const out = {
    name: str(d.stalkerware_name) || str(d.name) || str(d.label) || list(d.apps),
    where: str(d.location) || str(d.path) || str(d.plist) || str(d.program),
    how: str(d.detected_as),
    maker,
  };
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v));
}

// `doc` without those findings (their checks still count as having run), and
// the detections they held, at any severity (an info-level product such as
// remote-support software is still software on this computer). The scan
// itself is never changed.
export function splitHeld(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.modules)) return { doc, held: [] };
  const held = [];
  const modules = doc.modules.map((m) => {
    if (!m || !HELD_MODULES.has(m.name)) return m;
    const fs = Array.isArray(m.findings) ? m.findings : [];
    let found = false;
    for (const f of fs) {
      if (holds(f, m.name)) { held.push({ module: m.name, title: String(f.title || ''), ...heldEvidence(f) }); found = true; }
    }
    // Nothing found, and it couldn't look: fog, never clear. (With a
    // detection the check did look, and its district stays open for it.)
    if (!found && fs.some((f) => f && COULDNT_LOOK.has(f.code))) {
      return { ...m, findings: [], supported: false, unsupported_reason: COULDNT_LOOK_REASON };
    }
    // A familiar app with a verified maker stays, as an ordinary note.
    return { ...m, findings: m.name === 'keylogger_indicators' ? fs.filter((f) => f && isDetection(f) && familiarVerified(f, m.name)) : [] };
  });
  return { doc: { ...doc, modules }, held };
}

// `doc` with only those findings: what integrity still counts as open. Kept
// in memory by the controller, never stored or scored. A "found nothing" line
// (NOT_DETECTIONS) isn't held, so it doesn't hold its district open either.
export function heldOnly(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.modules)) return doc;
  return { ...doc, modules: doc.modules.filter((m) => m && HELD_MODULES.has(m.name))
    .map((m) => (Array.isArray(m.findings) ? { ...m, findings: m.findings.filter((f) => !f || holds(f, m.name)) } : m)) };
}

// What a briefing says about a finding that is monitoring software, from the
// list's own QuietNotes (`Q`). 'held' (city): the hold line and the help, and
// nothing to act on. 'line' (standard): the one line with the full note
// behind it. Anything else: nothing, and the briefing is as before.
// `description` is what a held briefing says the software is, in place of the
// engine's own text (which says how to remove it).
export function briefingNote(Q, mode, finding) {
  if (!Q || !finding) return { kind: 'none', html: '', description: '' };
  const card = Q.cardText(mode, finding);
  const full = typeof Q.fullHtml === 'function' ? Q.fullHtml(card, esc) : '';
  return { kind: card.note, html: Q.lineHtml(card, esc) + full + Q.heldHtml(card, esc, { more: false }), description: card.description };
}

// The map's note while something is held, so the city always says it and
// always shows where help is. Task 8's district takes this place in 'city'.
// In 'city' it is plain on its face: a neutral label, and the hold line and
// help closed behind it, so a glance at the map gives nothing away. In
// 'standard' it names what was found, with the one line. Never stored.
export const HELD_LABEL = 'Something the checkup found';
export const HELD_OPEN = 'Read this before you change anything';
export function heldPanelHtml({ held, mode, Q }) {
  if (!Q || !Array.isArray(held) || !held.length) return '';
  const card = Q.cardText(mode, { module: held[0].module });
  const list = '<button type="button" class="btn-t" data-act="list">SEE IT IN THE LIST</button>';
  if (card.note === 'held') {
    return `<div class="panel held"><div class="label">${esc(HELD_LABEL.toUpperCase())}</div>
    <details class="held-more"><summary>${esc(HELD_OPEN)}</summary>${Q.heldHtml(card, esc, { more: false, open: true })}</details>
    ${list}</div>`;
  }
  const titles = held.map((h) => `<li>${esc(h.title || HELD_LABEL)}</li>`).join('');
  return `<div class="panel held" role="note"><div class="label">SOMETHING TO KNOW</div>
    <ul class="notes">${titles}</ul>${Q.lineHtml(card, esc)}
    ${list}</div>`;
}
