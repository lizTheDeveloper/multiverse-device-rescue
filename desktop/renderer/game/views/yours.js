// "This is mine" on the deck, and the YOURS district. Pure: every string from
// the engine is escaped. Short text only; what the labels mean is a lesson
// (program-kinds.js KIND_LESSON).
import { esc } from '../escape.js';
import { kindChipsHtml, KIND_LESSON } from '../program-kinds.js';

// The confirmation's words: MarkFlow's own, in full, so nothing is softened.
const ONLY_IF_YOURS = 'Only do this if you set this up yourself. If you’re not sure, leave it as it is.';
const COULD_WATCH = 'Something like this can be used to watch or get into a computer.';

// One short inline question: no dialog, no new screen.
export function confirmHtml({ target, count = 1, watch = false }) {
  const what = count > 1 ? `Mark these ${count} as yours?` : 'Mark this as yours?';
  return `<div class="mine-confirm" role="group" aria-label="${esc(what)}">
    <p class="mine-confirm__q"><b>${esc(what)}</b> ${esc(ONLY_IF_YOURS)}</p>
    ${watch ? `<p class="mine-confirm__why">${esc(COULD_WATCH)}</p>` : ''}
    <div class="row"><button type="button" class="btn-p" data-act="mine-yes:${esc(target)}">YES, ${count > 1 ? 'THEY’RE' : 'IT’S'} MINE</button>
    <button type="button" class="btn-t" data-act="mine-no">CANCEL</button></div></div>`;
}

// The row's own controls in the queue: a checkbox (unticked) and MARK AS MINE ✓,
// both with their words on screen.
// `qm`: quickMarkOf(…). `state`: {picked, confirming, saving, watch}.
export function mineRowHtml(sig, qm, { picked = false, confirming = false, saving = false, watch = false } = {}) {
  if (!qm) return '';
  if (saving) return '<span class="mine-saving" role="status"><span aria-hidden="true">✓</span> SORTING…</span>';
  if (confirming) return confirmHtml({ target: sig.id, watch });
  return `<span class="mine-row">
    <label class="pick"><input type="checkbox" data-act="pick:${esc(sig.id)}"${picked ? ' checked' : ''} aria-label="${esc(`Select: ${sig.title}`)}"> <span aria-hidden="true">SELECT</span></label>
    <button type="button" class="btn-mine" data-act="mine:${esc(sig.id)}" aria-label="${esc(`Mark as mine: ${sig.title}`)}">MARK AS MINE ✓</button></span>`;
}

// The selection bar, above the queue, once something is ticked.
export function bulkBarHtml({ count, confirming = false, watch = false }) {
  if (!count) return '';
  if (confirming) return `<div class="mine-bulk">${confirmHtml({ target: '*', count, watch })}</div>`;
  return `<div class="mine-bulk" role="group" aria-label="Selected signals"><span>${esc(count)} SELECTED</span>
    <button type="button" class="btn-s lime" data-act="mine-picked">MARK ${esc(count)} AS MINE ✓</button>
    <button type="button" class="btn-t" data-act="pick-none">CLEAR</button></div>`;
}

// The small "done" moment: a line that says where it went, with Undo.
export function toastHtml(toast) {
  if (!toast) return '';
  if (toast.tone === 'error') {
    return `<div class="mine-toast error" role="status"><b>Not marked.</b> ${esc(toast.text)}</div>`;
  }
  const undo = toast.undo ? ' <button type="button" class="btn-t" data-act="mine-undo">UNDO</button>' : '';
  return `<div class="mine-toast${toast.allDone ? ' all-done' : ''}" role="status"><span class="tick" aria-hidden="true">✓</span> ${esc(toast.text)}${undo}</div>`;
}

// The district's tile on the city: the count, and a flag when one changed.
export function yoursTileHtml({ count, changed = 0, bump = false }) {
  if (!count && !changed) return '';
  return `<div class="yours-tile"><button type="button" class="btn-s yours-btn" data-go="yours">YOURS <b class="yours-count${bump ? ' bump' : ''}">${esc(count)}</b> ▶</button>${changed ? ` <span class="badge warn">${esc(changed)} CHANGED</span>` : ''}</div>`;
}

function makerHtml(m) {
  if (!m) return '<span class="y-maker unknown">Maker unknown</span>';
  return m.verified
    ? `<span class="y-maker ok">Made by ${esc(m.name)} <small>(verified)</small></span>`
    : `<span class="y-maker">Says it’s made by ${esc(m.name)} <small>(couldn’t verify)</small></span>`;
}

// `fold` (the "new" level, level.js): the path waits under DETAILS.
function itemRow(it, picked, act, pickable = true, fold = false) {
  const ev = !it.evidence ? '' : fold ? `<details class="raw"><summary>DETAILS</summary><code>${esc(it.evidence)}</code></details>` : ` <code>${esc(it.evidence)}</code>`;
  const pick = pickable ? `<label class="pick"><input type="checkbox" data-act="ypick:${esc(it.id)}"${picked ? ' checked' : ''} aria-label="${esc(`Select: ${it.name}`)}"></label>` : '';
  return `<li class="y-item${it.pending ? ' pending' : ''}${it.stale ? ' stale' : ''}">
    ${pick}
    <div class="y-body"><div class="y-name">${esc(it.name)}</div>${kindChipsHtml(it.kinds)}
      <div class="y-meta">${makerHtml(it.maker)}${ev}</div></div>
    ${act(it)}</li>`;
}

export function renderYours({ inv, picked = new Set(), scout = () => '', toast = null, fold = false }) {
  const back = (it) => `<button type="button" class="btn-t" data-act="unmine:${esc(it.id)}" aria-label="${esc(`Not mine: ${it.name}`)}">NOT MINE ↩</button>`;
  const look = (it) => `<button type="button" class="btn-s" data-go="signal:${esc(it.id)}">LOOK AGAIN ▶</button>`;
  const changed = inv.changed.length ? `
    <section class="panel y-changed" aria-label="Changed since you marked it"><h2 class="label"><span class="badge warn">CHANGED SINCE YOU MARKED IT</span> (${esc(inv.changed.length)})</h2>
      <p class="intel">Back in your queue until you look again.</p>
      <ul class="y-list">${inv.changed.map((it) => itemRow(it, false, look, false, fold)).join('')}</ul></section>` : '';
  const groups = inv.groups.map((g) => `
    <section class="panel y-group" aria-label="${esc(g.kind.label)}"><h2 class="label"><span aria-hidden="true">${esc(g.kind.icon)}</span> ${esc(g.kind.label.toUpperCase())} (${esc(g.items.length)})</h2>
      <ul class="y-list">${g.items.map((it) => itemRow(it, picked.has(it.id), back, true, fold)).join('')}</ul></section>`).join('');
  const n = [...picked].filter((id) => inv.items.some((it) => it.id === id)).length;
  const bar = n ? `<div class="mine-bulk"><span>${esc(n)} SELECTED</span>
    <button type="button" class="btn-s" data-act="unmine-picked">PUT ${esc(n)} BACK IN THE QUEUE</button>
    <button type="button" class="btn-t" data-act="ypick-none">CLEAR</button></div>` : '';
  const empty = !inv.count && !inv.changed.length ? '<p class="intel">Nothing here yet. Press MINE ✓ on a signal you set up yourself.</p>' : '';
  return `
  <section class="yours-screen" aria-labelledby="yours-title">
    <header class="hud"><h1 class="hud-title" id="yours-title" tabindex="-1">YOURS <small>${esc(inv.count)}</small></h1>
      <button type="button" class="btn-p" data-act="yours-back">BACK TO THE DECK</button></header>
    <div class="scout-row">${scout('happy', 54)}<p class="say">Your own programs and settings, and what they do. Still listed, not warned about.</p></div>
    <p class="intel"><button type="button" class="btn-t" data-go="lesson:${esc(KIND_LESSON)}">WHAT DO THE LABELS MEAN? ▶</button></p>
    ${toastHtml(toast)}${changed}${bar}${groups}${empty}
  </section>`;
}
