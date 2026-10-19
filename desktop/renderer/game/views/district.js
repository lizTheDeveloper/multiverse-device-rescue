import { HELD_MODULES } from '../held.js';
import { esc } from '../escape.js';
import { skyline, districtLine } from './map.js';
import { reclaimedIn } from '../progress.js';

// A check's name for people, never its raw id; a monitoring check is never
// named on the city (held.js): just "A check".
export function checkWords(module) {
  if (HELD_MODULES.has(module)) return 'A check';
  const words = String(module || '').replace(/_/g, ' ').trim();
  return words ? words.charAt(0).toUpperCase() + words.slice(1) : 'A check';
}

const STATUS_BADGE = {
  open: '', later: '<span class="badge skip">LATER</span>',
  yours: '<span class="badge yours">YOURS</span>', reclaimed: '<span class="badge safe">RECLAIMED</span>',
};

// Each open mission has a checkbox, unticked, for the bulk moves below the
// list (I DID THESE MYSELF re-checks them; LATER saves them for later), and
// its row opens it. `message`: what the last bulk move found. `busy`: a bulk
// re-check is running; `scanRunning`: a sweep is, so nothing can be re-checked.
export const BULK_DID = 'I DID THESE MYSELF';
export const BULK_LATER = 'LATER';
export function bulkLabel(verb, n) { return n ? `${verb} (${n})` : verb; }
export function renderDistrict({ district: d, progress, scout, message = '', busy = false, scanRunning = false }) {
  const status = (id) => (progress.missions[id] && progress.missions[id].status) || 'open';
  const missions = d.missions.map((m, i) => `
      <li class="pick-row"><input type="checkbox" class="pick" id="pick-${i}" data-pick="${esc(m.id)}" aria-label="${esc(`Tick: ${m.title}`)}"${busy ? ' disabled' : ''}>
        <button type="button" class="mission-row" data-go="mission:${esc(m.id)}">
        <span class="badge ${m.severity === 'critical' ? 'crit' : 'warn'}">${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</span>
        <span class="mission-text">${esc(m.title)}</span>
        ${STATUS_BADGE[status(m.id)] || ''}
      </button></li>`).join('');
  const bulk = d.missions.length > 1 ? `
      <div class="row bulk" role="group" aria-label="With the ticked ones">
        <button type="button" class="btn-s" data-act="bulk-did" data-verb="${esc(BULK_DID)}" disabled${scanRunning ? ' data-scan-running' : ''}>${esc(BULK_DID)}</button>
        <button type="button" class="btn-t" data-act="bulk-later" data-verb="${esc(BULK_LATER)}" disabled>${esc(BULK_LATER)}</button>
        <span class="intel" data-pick-count aria-live="polite">None ticked</span></div>` : '';
  const said = busy ? '<p class="checking" role="status" aria-live="polite">Checking again… This only looks; it doesn’t change anything.</p>'
    : message ? `<p class="intel" role="status">${esc(message)}</p>` : '';
  // Reclaimed missions are no longer in the scan, so they come from progress.
  // There is nothing to open, so each is a lit row, not a button.
  const present = new Set(d.missions.map((m) => m.id));
  const all = reclaimedIn(progress, d);
  const earlier = all.filter((r) => r.earlier).length;
  const row = (text) => `
      <li><div class="mission-row lit">
        <span class="badge safe">RECLAIMED</span>
        <span class="mission-text">${esc(text)}</span>
      </div></li>`;
  // Missions folded into a count (to keep the profile small) show as one line.
  const reclaimed = all.filter((r) => !r.earlier && !present.has(r.id)).map((r) => row(r.title)).join('')
    + (earlier ? row(`${earlier} more reclaimed earlier`) : '');
  const rows = missions + reclaimed;
  const notes = d.notes.map((n) => `<li>${esc(n.title)}</li>`).join('');
  const fog = d.fog.map((x) => `<li><strong>${esc(checkWords(x.module))}</strong>: ${esc(x.reason)}</li>`).join('');
  // Ran, but stopped before the end (the engine's "complete": false).
  // Or a note said part of it couldn't look (`titles`, signals.js foldPartly).
  const unfinished = (d.unfinished || []).map((x) => `<li><strong>${esc(checkWords(x.module))}</strong>${
    Array.isArray(x.titles) && x.titles.length && !HELD_MODULES.has(x.module) ? `: ${esc(x.titles.join('; '))}` : ''}</li>`).join('');
  return `
  <section class="district-screen">
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <b>${esc(d.name)}</b></div>
    <h2 class="m-title">${esc(d.name)}</h2>
    ${skyline(d.status)}
    <p class="intel">${esc(districtLine(d, reclaimedIn(progress, d).length))}</p>
    ${rows ? `<div class="panel active"><div class="label">MISSIONS</div><ul class="missions">${rows}</ul>${bulk}${said}</div>` : ''}
    ${fog ? `<div class="panel fogged"><div class="label">COULDN’T CHECK HERE</div><p class="intel">That doesn’t mean it’s safe.</p><ul class="fog-list">${fog}</ul></div>` : ''}
    ${unfinished ? `<div class="panel fogged"><div class="label">DIDN’T FINISH HERE</div><p class="intel">These checks stopped before the end or couldn’t look at everything, so they may have missed something. That doesn’t mean it’s safe.</p><ul class="fog-list">${unfinished}</ul></div>` : ''}
    ${notes ? `<details class="panel"><summary class="label">NOTES (${d.notes.length})</summary><ul class="notes">${notes}</ul></details>` : ''}
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(d.missions.length ? 'Pick one. You can stop after any of them.' : 'Nothing to do here right now.')}</p></div>
  </section>`;
}
