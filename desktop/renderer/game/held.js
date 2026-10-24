// Findings from the checks that look for monitoring software. The game never
// turns them into missions or signals, so nothing about them is scored or
// stored: in 'city' they wait in the generated district (memory only), and
// in 'standard' the list shows them with the one line. The same three checks
// as app.js's ALWAYS_SAFETY_MODULES; a test keeps them equal.
import { esc } from './escape.js';
import { remoteFacts } from '../missions/remote-facts.js';
// Sets globalThis.NotChecked (a plain script the list loads too).
import '../not-checked.js';

export const HELD_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
// What city mode holds besides: remote-access tools (NotChecked.HELD_IN_CITY;
// app.js CITY_HELD_MODULES; a test keeps the three equal). In city mode they
// wait here like monitoring software (no mission, signal, points or stored
// answer). In standard mode they are ordinary findings: only the monitoring
// checks are held there, as before.
export const REMOTE_TOOLS = 'remote_access_tools';
export const CITY_HELD_MODULES = new Set([...HELD_MODULES, REMOTE_TOOLS]);
const heldSet = (mode) => (mode === 'standard' ? HELD_MODULES : CITY_HELD_MODULES);

// What those checks say when they found nothing or couldn't look (QuietNotes'
// NOT_DETECTIONS; a test keeps them equal), and of those, the lines that mean
// the check couldn't look at all: no backups, no scanner, no Linux layer, a
// backup too large to read, or a scan that wasn't run. A check that couldn't
// look is never "clear": its module goes to the city as COULDN'T CHECK (fog),
// the same as a check that couldn't run, and the list counts it the same way
// (renderer/not-checked.js owns the rule).
const NC = globalThis.NotChecked;
export const NOT_DETECTIONS = NC.NOT_DETECTIONS;
export const COULDNT_LOOK = NC.COULDNT_LOOK;
// What the city says about it: plain, the same words as any check that couldn't run.
export const COULDNT_LOOK_REASON = NC.COULDNT_LOOK_REASON;

// The same rule as QuietNotes.isDetection, for a finding of a held module.
export const isDetection = NC.isDetection;

// The one finding that may leave the help district: keyboard access for
// apps with familiar names (keylogger_indicators' claimed_vendor check), at
// info, when every app in it is a KNOWN program whose signed identity was
// verified. The engine gives `what` only then (rescue/attribution.py), so
// each app needs a made_by entry with verified === true and a `what`. A
// signature alone is cheap, so a signed but unknown maker stays held, and so
// does anything from the other monitoring checks, at any severity. An app
// named only by bundle id (a TCC row's client) counts only on the engine's
// own proof that macOS's permission record pins the expected company's Team
// ID for it (data.verified_apps plus a made_by entry whose `how` is the code
// requirement's); never by its name.
export const FAMILIAR_CODE = 'security.keylogger_indicators.suspicious_input_monitoring';
export const FAMILIAR_CHECK = 'claimed_vendor_input_monitoring';
// The rule itself lives in not-checked.js, so the counts leave out exactly
// what is held here.
export const familiarVerified = NC.familiarVerified;
export const isHeld = NC.isHeld;
const holds = (f, module, mode = 'city') => !!f && heldSet(mode).has(module) && NC.isHeld(f, module);

// What the help district shows about a held finding, so it can be written
// down: the name, where it was found, how it was found, and who made it. From
// the finding's own evidence; memory only, never stored. A remote-access
// tool adds what the person needs to think back with: when it was added, when
// it last let someone in, whether it can without a click, and whether it's
// running (`running_now` true puts "go offline first" at the top). Missing
// evidence says "Couldn't tell", never "no". `locale` goes to remoteFacts'
// dates ('en-US': written by hand, for the photo record); default the computer's.
export function heldEvidence(f, module = f && f.module, { locale } = {}) {
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
  if (module === REMOTE_TOOLS) {
    out.name = str(d.tool) || out.name;
    // The Guest Book's card says the same facts in the same words.
    Object.assign(out, remoteFacts(d, { locale }));
  }
  return Object.fromEntries(Object.entries(out).filter(([, v]) => v !== '' && v != null));
}



// `doc` without those findings (their checks still count as having run), and
// the detections they held, at any severity (an info-level product such as
// remote-support software is still software on this computer). The scan
// itself is never changed.
// `mode`: 'city' (the default) also holds remote-access tools; 'standard' only the monitoring checks.
// `locale`: for heldEvidence's dates (the photo record passes 'en-US').
export function splitHeld(doc, { mode = 'city', locale } = {}) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.modules)) return { doc, held: [] };
  const held = [];
  const set = heldSet(mode);
  const modules = doc.modules.map((m) => {
    if (!m || !set.has(m.name)) return m;
    const fs = Array.isArray(m.findings) ? m.findings : [];
    let found = false;
    for (const f of fs) {
      // The whole finding rides along (memory only) so the help district can
      // show its evidence rows (Evidence.evidenceRows, held).
      if (holds(f, m.name, mode)) { held.push({ module: m.name, title: String(f.title || ''), ...heldEvidence(f, m.name, { locale }), finding: { ...f, module: m.name } }); found = true; }
    }
    // Nothing found, and it couldn't look: fog, never clear. (With a
    // detection the check did look, and its district stays open for it.)
    // A check waiting for a go-ahead (the iPhone backup scan) is fog too, and
    // keeps `not_started` so the city offers it, never as "couldn't run".
    if (!found && NC.couldntLook(m)) {
      return { ...m, findings: [], supported: false, unsupported_reason: COULDNT_LOOK_REASON, ...(NC.notStarted(m) ? { not_started: true } : {}) };
    }
    // A familiar app with a verified maker stays, as an ordinary note.
    return { ...m, findings: m.name === 'keylogger_indicators' ? fs.filter((f) => f && isDetection(f) && familiarVerified(f, m.name)) : [] };
  });
  return { doc: { ...doc, modules }, held };
}

// `doc` with only those findings: what integrity still counts as open. Kept
// in memory by the controller, never stored or scored. A "found nothing" line
// (NOT_DETECTIONS) isn't held, so it doesn't hold its district open either.
export function heldOnly(doc, { mode = 'city' } = {}) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.modules)) return doc;
  const set = heldSet(mode);
  return { ...doc, modules: doc.modules.filter((m) => m && set.has(m.name))
    .map((m) => (Array.isArray(m.findings) ? { ...m, findings: m.findings.filter((f) => !f || holds(f, m.name, mode)) } : m)) };
}

// What a briefing says about a finding that is monitoring software, from the
// list's own QuietNotes (`Q`). 'held' (city): the hold line and the help, and
// nothing to act on. 'line' (standard): the one line with the full note
// behind it. Anything else: nothing, and the briefing is as before.
// `description` is what a held briefing says the software is, in place of the
// engine's own text (which says how to remove it).
// `place` (standard mode): the help district's name, behind the line in place of the full note.
export function briefingNote(Q, mode, finding, { place = '' } = {}) {
  if (!Q || !finding) return { kind: 'none', html: '', description: '' };
  const card = Q.cardText(mode, finding);
  const full = typeof Q.fullHtml === 'function' ? Q.fullHtml(card, esc) : '';
  return { kind: card.note, html: Q.lineHtml(card, esc, { place }) + full + Q.heldHtml(card, esc, { more: false }), description: card.description };
}

// The map's note while something is held, so the city always says it and
// always shows where help is. Task 8's district takes this place in 'city'.
// In 'city' it is plain on its face: a neutral label, and the hold line and
// help closed behind it, so a glance at the map gives nothing away. In
// 'standard' it names what was found, with the one line. Never stored.
export const HELD_LABEL = 'Something the checkup found';
export const HELD_OPEN = 'Read this before you change anything';
export function heldPanelHtml({ held, mode, Q, place = '' }) {
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
    <ul class="notes">${titles}</ul>${Q.lineHtml(card, esc, { place })}
    ${list}</div>`;
}
