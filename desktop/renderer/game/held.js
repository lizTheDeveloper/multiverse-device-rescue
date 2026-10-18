// Findings from the checks that look for monitoring software. The game never
// turns them into missions or signals, so nothing about them is scored or
// stored: in 'city' they wait in the generated district (memory only), and
// in 'standard' the list shows them with the one line. The same three checks
// as app.js's ALWAYS_SAFETY_MODULES; a test keeps them equal.
import { esc } from './escape.js';

export const HELD_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

// `doc` without those findings (their checks still count as having run), and
// the warnings and criticals they held. The scan itself is never changed.
export function splitHeld(doc) {
  if (!doc || typeof doc !== 'object' || !Array.isArray(doc.modules)) return { doc, held: [] };
  const held = [];
  const modules = doc.modules.map((m) => {
    if (!m || !HELD_MODULES.has(m.name)) return m;
    for (const f of Array.isArray(m.findings) ? m.findings : []) {
      if (f && (f.severity === 'critical' || f.severity === 'warning')) held.push({ module: m.name, title: String(f.title || '') });
    }
    return { ...m, findings: [] };
  });
  return { doc: { ...doc, modules }, held };
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
  return { kind: card.note, html: Q.lineHtml(card, esc) + Q.heldHtml(card, esc, { more: false }), description: card.description };
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
