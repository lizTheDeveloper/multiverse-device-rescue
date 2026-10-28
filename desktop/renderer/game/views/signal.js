// The Signal or Noise panel: one finding (or one drill) over the deck. Pure.
// Clues stay locked until SCAN CLUE, and only clues the evidence supports are
// offered at all. Tags are game sorting only; a real change keeps its own OK.
import { esc } from '../escape.js';
import { SEV_BADGE, nextMoveHtml } from './deck.js';

export const TAG_NOTE = 'Tags are game sorting only. They change nothing on your computer.';
const TAG_BUTTONS = [['mine', 'MINE'], ['closer', 'LOOK CLOSER'], ['threat', 'THREAT']];

// A clue line is text, or { text, code: true } for a command or a raw value (copyable).
const clueLine = (l) => (l && typeof l === 'object'
  ? `<code class="clue-line code">${esc(l.text)}</code>` : `<p class="clue-line">${esc(l)}</p>`);

function clueItem(c, opened, sig) {
  if (!opened.includes(c.kind)) {
    return `<li><button type="button" class="clue locked" data-act="clue:${esc(c.kind)}">SCAN CLUE: ${esc(c.label)} ▶</button></li>`;
  }
  // tabindex -1: focus can land on a clue just opened when none is left locked.
  return `<li class="clue open" data-clue="${esc(c.kind)}" tabindex="-1"><div class="label">${esc(c.label)}</div>${c.lines.map(clueLine).join('')}
      ${c.reading ? `<p class="reading"><b>How to read this:</b> ${esc(c.reading.text)}</p>` : ''}${c.move && sig.kind === 'real' ? nextMoveHtml(sig) : ''}</li>`;
}

// Real findings pay for looking, so the points show with the clues, before any tag.
const cluePoints = (sig, points) => (sig.kind === 'real' && points > 0 ? `<p class="points">+${esc(points)} POINTS for looking at the clues</p>` : '');

export function renderSignalPanel({ signal: sig, districtName = '', clues = [], opened = [], tagged = null, right = false, read = '',
  points = 0, scout, mineHtml = '', range = null }) {
  const drill = sig.kind === 'drill';
  const couldnt = sig.kind === 'couldnt';
  const stamp = drill ? `<p class="drill-banner"><span class="badge drill-stamp">DRILL</span> Practice. This isn’t on your computer.</p>
    ${sig.drill && sig.drill.setup ? `<p class="intel">${esc(sig.drill.setup)}</p>` : ''}` : '';
  const notes = [
    sig.marked ? '<p class="intel"><span class="badge yours">MARKED</span> You told Reclaim City this is yours. It stays listed.</p>' : '',
    sig.stale ? '<p class="intel"><span class="badge warn">CHANGED SINCE YOU MARKED IT</span> It changed after you marked it, so it’s back in your queue.</p>' : '',
    sig.changed ? '<p class="intel"><span class="badge warn">CHANGED SINCE YOU TAGGED IT</span> It changed since you tagged it, so your old tag was set aside.</p>' : '',
  ].join('');
  let clueHtml;
  if (couldnt) {
    clueHtml = `<p class="intel">${esc(sig.description || 'This check couldn’t run.')}</p>
      <p class="intel">A check that couldn’t run checked nothing. That doesn’t mean it’s safe.</p>`;
  } else if (clues.length) {
    clueHtml = `<ul class="clues">${clues.map((c) => clueItem(c, opened, sig)).join('')}</ul>${cluePoints(sig, points)}`;
  } else {
    clueHtml = '<p class="intel">The scan recorded no clues for this one. Its title is all there is to go on.</p>';
  }
  const current = tagged || sig.tag;
  const call = couldnt
    ? `<div class="row tags"><button type="button" class="btn-s" data-act="tag:noted"${current === 'noted' ? ' aria-pressed="true"' : ''}>NOTED</button>
      <button type="button" class="btn-t" data-go="lesson:couldnt-check">WHAT “COULDN’T CHECK” MEANS ▶</button></div>`
    : `<div class="row tags">${TAG_BUTTONS.map(([t, label]) => `<button type="button" class="btn-s tag-${t}" data-act="tag:${t}"${current === t ? ' aria-pressed="true"' : ''}${drill && tagged ? ' aria-disabled="true" disabled' : ''}>${label}</button>`).join('')}</div>`;
  const after = !tagged ? '' : `
    ${read ? `<div class="scout-row">${scout(drill && !right ? 'thinkingA' : 'happy', 54)}<p class="say">${esc(read)}</p></div>` : ''}
    ${drill && points > 0 ? `<p class="points">+${esc(points)} POINTS</p>` : ''}
    ${!drill && tagged === 'mine' && mineHtml ? `<div class="panel"><div class="label">OPTIONAL: TELL RECLAIM CITY TOO</div>
      <p class="intel">The MINE pile is the game’s sorting. This asks Reclaim City itself to remember it’s yours, so it stops flagging it. It asks first, and you can undo it.</p>${mineHtml}</div>` : ''}
    ${!drill && tagged === 'threat' ? `<div class="panel"><div class="label">ON YOUR THREAT BOARD</div><p class="intel">Your next move:</p>${nextMoveHtml(sig)}</div>` : ''}
    ${!drill && tagged === 'closer' ? '<p class="intel">It stays in your queue. Open its clues again any time, or use LIST for every detail the scan recorded.</p>' : ''}`;
  const foot = range
    ? `<div class="row"><button type="button" class="btn-p" data-act="next-drill">NEXT DRILL ▶</button>
      <button type="button" class="btn-t" data-act="leave-range">${range.hasCity ? 'BACK TO THE DECK' : 'BACK TO THE TRAINING GROUNDS'}</button></div>`
    : '<button type="button" class="btn-t" data-act="close-signal">BACK TO THE DECK</button>';
  return `
  <section class="sig-panel${drill ? ' drill' : ''}" role="region" aria-labelledby="sig-title">
    ${stamp}
    <div class="sig-head">${SEV_BADGE[sig.severity] || ''} <small>${esc(districtName)}</small></div>
    <h2 class="m-title" id="sig-title" tabindex="-1">${esc(sig.title)}</h2>
    ${notes}
    <div class="label">CLUES</div>${clueHtml}
    <div class="label">YOUR CALL</div>${call}
    <p class="intel faint">${esc(drill ? 'Practice only. A drill never touches your computer.' : TAG_NOTE)}</p>
    ${after}
    ${foot}
  </section>`;
}

// The DRILL RANGE screen: more drills, any time, with or without a scan.
export function renderRange({ loaded, panelHtml = '', hasCity = false }) {
  const body = !loaded ? '<p class="intel">Getting the drills ready.</p>'
    : panelHtml || '<p class="intel">The drills couldn’t load. The checkup and the deck still work.</p>';
  return `
  <header class="hud"><span class="hud-title">THE DRILL RANGE</span>
    <span class="switch"><button type="button" data-act="leave-range">${hasCity ? 'BACK TO THE DECK' : 'BACK TO THE TRAINING GROUNDS'}</button></span></header>
  <section class="range" aria-label="The drill range">
    <p class="intel">Practice with made-up signals. None of this is on your computer, and nothing here changes it.</p>
    ${body}
  </section>`;
}
