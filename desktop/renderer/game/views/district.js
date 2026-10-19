import { HELD_MODULES } from '../held.js';
import { waitingId } from '../signals.js';
import { esc } from '../escape.js';
import { skyline, districtLine } from './map.js';
import { reclaimedIn } from '../progress.js';

// A check's name for people, never its raw id; a monitoring check is never
// named on the city (held.js): just "A check".
// `checkName`: the check's own name for people (the scan's check_name), as
// the list says it; the id's words only when there is none.
// What a monitoring check that couldn't run says in city mode (signals.js's
// COULDN'T CHECK row says the same).
export const MONITORING_FOG_REASON = 'This check couldn’t run.';

export function checkWords(module, checkName = null) {
  if (HELD_MODULES.has(module)) return 'A check';
  const words = String(checkName || module || '').replace(/_/g, ' ').trim();
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
// `detail(mission)`: one line of its evidence (a path, a name or an id), so
// rows with the same title can be told apart; '' for none.
// A district is a few little missions at a time: this many rows, then "AND N MORE".
export const DISTRICT_SHOWN = 10;
// `allOpen`: the person asked for every row. `waitingTitle`: what a check
// waiting for a go-ahead is called here (signals.js WAITING_TITLE).
export function renderDistrict({ district: d, progress, scout, message = '', busy = false, scanRunning = false, detail = () => '',
  allOpen = false, waitingTitle = 'A long sweep is waiting for your go-ahead', cover = false }) {
  const status = (id) => (progress.missions[id] && progress.missions[id].status) || 'open';
  // Two missions with one title and nothing to tell them apart are numbered.
  const titles = new Map();
  for (const m of d.missions) titles.set(m.title, (titles.get(m.title) || 0) + 1);
  const seen = new Map();
  // `detail` gives a string (a path or id, drawn as code) or { text, mono: false } (names).
  const rowLine = (m) => {
    let line = '';
    let mono = true;
    try {
      const got = detail(m);
      if (got && typeof got === 'object') { line = String(got.text || ''); mono = got.mono !== false; } else line = String(got || '');
    } catch (_) { line = ''; }
    const n = (seen.get(m.title) || 0) + 1;
    seen.set(m.title, n);
    const of = titles.get(m.title) > 1 && !line ? ` (${n} of ${titles.get(m.title)})` : '';
    return `${esc(of)}${line ? `<small class="mission-detail">${mono ? `<code>${esc(line)}</code>` : esc(line)}</small>` : ''}`;
  };
  const shownMissions = allOpen ? d.missions : d.missions.slice(0, DISTRICT_SHOWN);
  const moreRow = d.missions.length > DISTRICT_SHOWN ? `
      <li><button type="button" class="btn-t more-row" data-act="toggle-district" aria-expanded="${allOpen ? 'true' : 'false'}">${allOpen
    ? 'SHOW FEWER' : `AND ${d.missions.length - DISTRICT_SHOWN} MORE ▶`}</button></li>` : '';
  const missions = shownMissions.map((m, i) => `
      <li class="pick-row"><input type="checkbox" class="pick" id="pick-${i}" data-pick="${esc(m.id)}" aria-label="${esc(`Tick: ${m.title}`)}"${busy ? ' disabled' : ''}>
        <button type="button" class="mission-row" data-go="mission:${esc(m.id)}">
        <span class="badge ${m.severity === 'critical' ? 'crit' : 'warn'}">${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</span>
        <span class="mission-text">${esc(m.title)}${rowLine(m)}</span>
        ${STATUS_BADGE[status(m.id)] || ''}
      </button></li>`).join('') + moreRow;
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
  // City mode (`cover`): a monitoring check's own error text ("Stalkerware
  // indicator data could not be loaded") would say what it looks for, so its
  // reason is the queue's neutral words (signals.js).
  const fogReason = (x) => (cover && HELD_MODULES.has(x.module) ? MONITORING_FOG_REASON : x.reason);
  const fog = d.fog.filter((x) => !x.notStarted).map((x) => `<li><strong>${esc(checkWords(x.module, x.checkName))}</strong>: ${esc(fogReason(x))}</li>`).join('');
  // Waiting for the person's go-ahead (the long phone-backup sweep): offered, never "couldn't check".
  const waiting = d.fog.filter((x) => x.notStarted).map((x) => `<li><button type="button" class="btn-t" data-go="signal:${esc(waitingId(d.id, x.module))}">${esc(waitingTitle)} ▶</button></li>`).join('');
  // Ran, but stopped before the end (the engine's "complete": false).
  const unfinished = (d.unfinished || []).filter((x) => !(Array.isArray(x.titles) && x.titles.length))
    .map((x) => `<li><strong>${esc(checkWords(x.module, x.checkName))}</strong></li>`).join('');
  // A note said part of it couldn't look (`titles`, signals.js foldPartly).
  const partly = (d.unfinished || []).filter((x) => Array.isArray(x.titles) && x.titles.length)
    .map((x) => `<li><strong>${esc(checkWords(x.module, x.checkName))}</strong>${HELD_MODULES.has(x.module) ? '' : `: ${esc(x.titles.join('; '))}`}</li>`).join('');
  return `
  <section class="district-screen">
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <b>${esc(d.name)}</b></div>
    <h2 class="m-title">${esc(d.name)}</h2>
    ${skyline(d.status)}
    <p class="intel">${esc(districtLine(d, reclaimedIn(progress, d).length))}</p>
    ${rows ? `<div class="panel active"><div class="label">MISSIONS</div><ul class="missions">${rows}</ul>${bulk}${said}</div>` : ''}
    ${fog ? `<div class="panel fogged"><div class="label">COULDN’T CHECK HERE</div><p class="intel">That doesn’t mean it’s safe.</p><ul class="fog-list">${fog}</ul></div>` : ''}
    ${unfinished ? `<div class="panel fogged"><div class="label">DIDN’T FINISH HERE</div><p class="intel">These checks stopped before the end, so they may have missed something. That doesn’t mean it’s safe.</p><ul class="fog-list">${unfinished}</ul></div>` : ''}
    ${partly ? `<div class="panel fogged"><div class="label">ONLY PARTLY CHECKED HERE</div><p class="intel">These checks couldn’t look at everything. That doesn’t mean it’s safe.</p><ul class="fog-list">${partly}</ul></div>` : ''}
    ${waiting ? `<div class="panel"><div class="label">WAITING FOR YOUR GO-AHEAD</div><ul class="fog-list">${waiting}</ul></div>` : ''}
    ${notes ? `<details class="panel"><summary class="label">NOTES (${d.notes.length})</summary><ul class="notes">${notes}</ul></details>` : ''}
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(d.missions.length ? 'Pick one. You can stop after any of them.' : 'Nothing to do here right now.')}</p></div>
  </section>`;
}
