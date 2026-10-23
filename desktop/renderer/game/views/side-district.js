import { esc } from '../escape.js';
import { FIRST_STEPS, HELP, OPEN_NOTE, SIX_ROSES, LEAVING, HELD } from '../side-district.js';
// The list's evidence block (a plain script, not an ES module).
import * as evidenceModule from '../../evidence.js';
import { remoteFacts } from '../../missions/remote-facts.js';
import { dayWords, localIso } from '../../missions/day.js';

// In the page the script sets window.Evidence; in Node (tests) it is CommonJS.
const EV = globalThis.Evidence || evidenceModule.default;

// The district's tile, on the deck's city and on the Training Grounds. It names only the place.
// Never a bare button: a quiet label (ALSO IN TOWN) and the place's own
// greeting say what it is in the city's words, and nothing about what it holds.
export const TILE_LABEL = 'ALSO IN TOWN';
export function sideTileHtml(district, heldCount = 0) {
  const hello = district.voice && district.voice.hello ? district.voice.hello : '';
  return `<div class="side-tile look-${esc(district.look)}">
    <span class="label">${esc(TILE_LABEL)}</span>
    <button type="button" class="btn-s" data-go="side">${esc(district.name.toUpperCase())} ▶</button>${heldCount ? ' <span class="badge">NEW</span>' : ''}
    ${hello ? `<small class="side-say">${esc(hello)}</small>` : ''}</div>`;
}

// On the deck when the checkup found something that belongs there. Only the
// place again, and no second button: the tile (marked NEW) is the way there.
export function heldNoticeHtml(district) {
  return `<p class="link-notice" role="status">Something new in ${esc(district.name)}. Its tile on the city is marked NEW.</p>`;
}

// One held item as what to write down: the shared evidence block, held. That
// gives Name, Where found, How detected, Made by (verified or not) and the
// day it was found, drawn large with "Write this on paper or on another
// device." A remote-access tool's own facts (Added, Last let someone in, Can
// let someone in without a click, Running now) are rows in the same card,
// before "Found on", so each card says its own. No copy button and nothing on
// the clipboard: monitoring software can read it.
// `seen`: today (a Date); the block writes it as a plain day.
const isSeveral = (f) => (f && f.data && f.data.check === 'several_tools') || /\.several_tools$/.test(String((f && f.code) || ''));
function severalRows(data) {
  const tools = data && Array.isArray(data.tools) ? data.tools : [];
  const names = [...new Set(tools.map((t) => String(t == null ? '' : t).trim().slice(0, 80)).filter(Boolean))].slice(0, 6);
  return names.length ? [{ label: 'Tools', value: names.join(', '), mono: false }] : [];
}
export function heldBlockHtml(h, seen = new Date()) {
  const x = h || {};
  const f = x.finding || { module: x.module, title: x.title,
    data: { stalkerware_name: x.name || x.title, location: x.where, detected_as: x.how } };
  const rows = EV.evidenceRows(f, { mode: 'city', held: true, seen });
  if (x.module === 'remote_access_tools' && Array.isArray(rows) && rows.length) {
    // The engine's "several tools" finding is about the set, not one tool: it names them, and has no added day or
    // running state of its own (four "Couldn't tell" rows there would read as doubt about a tool the page calls running).
    const facts = isSeveral(f) ? severalRows(f.data)
      : remoteFacts(f.data, { today: seen, year: true }).rows.map((r) => ({ label: r.label, value: r.value, mono: false }));
    rows.splice(rows.length - 1, 0, ...facts);
  }
  // One date style on every held card (day.js, with the year: it may be copied onto paper), Found on included.
  const day = dayWords(seen instanceof Date ? localIso(seen) : seen, { year: true });
  if (day && Array.isArray(rows)) for (const r of rows) if (r && r.label === 'Found on') { r.value = day; r.copy = day; }
  return EV.renderEvidence(rows, { held: true, title: (h && h.title) || 'Write this down' });
}

// A remote-access tool that is running now may be showing this screen to someone: the first thing the district
// says is to go offline, naming the tools that are running (never one whose card says it isn't), with the network
// settings (the controller's side-offline act: research.js's network pane for this platform, through main's
// allowlist), before anything else.
export const OFFLINE_TAIL = 'To be safe, go offline first.';
const UNNAMED = 'A remote-access tool';
function namesInWords(names) {
  if (names.length <= 1) return names[0] || UNNAMED;
  return `${names.slice(0, -1).join(', ')} and ${names[names.length - 1]}`;
}
export function offlineLine(held) {
  const running = (Array.isArray(held) ? held : []).filter((h) => h && h.module === 'remote_access_tools' && h.running_now === true);
  if (!running.length) return '';
  const names = [...new Set(running.map((h) => String(h.name || '').trim().slice(0, 80) || UNNAMED))];
  return `${namesInWords(names)} ${names.length > 1 ? 'are' : 'is'} running now. ${OFFLINE_TAIL}`;
}
function offlineHtml(held) {
  const line = offlineLine(held);
  if (!line) return '';
  return `<p class="intel side-offline" role="alert"><b>${esc(line)}</b> Turn off Wi-Fi or unplug the network cable.
      <button type="button" class="btn-s" data-act="side-offline">NETWORK SETTINGS</button></p>`;
}

// `seen`: today, for the Found on row.
// `cityNotes`: "What this mode does" and "Something changed?" (city mode's; standard mode opens it from a warning).
export function renderSide({ district, held = [], notice = false, scout = () => '', seen = new Date(), cityNotes = true }) {
  const v = district.voice;
  const item = (h) => `<li class="held-item">${heldBlockHtml(h, seen)}</li>`;
  const heldHtml = held.length ? `
    <div class="panel active" role="note">${offlineHtml(held)}<h3 class="side-h">${esc(HELD.heading.text)}</h3>
      <ul class="held-items">${held.map(item).join('')}</ul>
      <ol class="side-steps">${HELD.steps.map((x) => `<li>${esc(x.text)}</li>`).join('')}</ol></div>` : '';
  const help = HELP.map((r) => `<li>${esc(r.text)}${r.url ? ` <code>${esc(r.url)}</code>` : ''}</li>`).join('');
  return `
  <section class="side look-${esc(district.look)}" aria-labelledby="side-title">
    <header class="hud side-top"><h2 class="hud-title" id="side-title" tabindex="-1">${esc(district.name.toUpperCase())}</h2>
      <button type="button" class="btn-p" data-act="side-back">BACK TO THE GAME</button></header>
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(v.hello)}</p></div>
    ${heldHtml}
    <div class="panel"><h3 class="side-h">Quiet first steps</h3>
      <ol class="side-steps">${FIRST_STEPS.map((x) => `<li><b>${esc(x.title)}</b> ${esc(x.text)}</li>`).join('')}</ol></div>
    <div class="panel"><h3 class="side-h">Who can help</h3><ul class="notes">${help}</ul>
      <p class="intel">${esc(OPEN_NOTE.text)}</p></div>
    <div class="panel"><h3 class="side-h">${esc(SIX_ROSES.name)}</h3>
      <p class="intel">${esc(SIX_ROSES.text)}</p><p class="intel">${esc(SIX_ROSES.note.text)}</p>
      <button type="button" class="btn-s" data-act="side-open-guide">OPEN IT IN YOUR BROWSER</button>
      ${notice ? `<p class="link-notice" role="status">${esc('It couldn’t be opened from here.')}</p>` : ''}</div>
    <div class="panel"><p class="intel"><b>${esc(LEAVING.text)}</b></p></div>
    <p class="say">${esc(v.bye)}</p>
    <p class="intel">Press Esc to go back to the game.</p>
    ${cityNotes ? `<p class="intel side-notes"><button type="button" class="btn-s" data-act="side-about-mode">WHAT THIS MODE DOES</button>
      <button type="button" class="btn-s" data-act="side-change">SOMETHING CHANGED?</button></p>` : ''}
  </section>`;
}
