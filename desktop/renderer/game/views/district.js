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

// `missionsHtml`: the district's little missions (missions-city.js, by kind,
// a few items each); the mission flow is the only flow. `message`: what the
// last move here found. `busy`: a re-check is running.
// `waitingTitle`: what a check waiting for a go-ahead is called here (signals.js WAITING_TITLE).
export function renderDistrict({ district: d, progress, scout, message = '', busy = false,
  waitingTitle = 'A long sweep is waiting for your go-ahead', cover = false, missionsHtml = '' }) {
  const said = busy ? '<p class="checking" role="status" aria-live="polite">Checking again… This only looks; it doesn’t change anything.</p>'
    : message ? `<p class="intel" role="status">${esc(message)}</p>` : '';
  // Reclaimed missions are no longer in the scan, so they come from progress.
  // There is nothing to open, so each is a lit row, not a button.
  const present = new Set((d.missions || []).map((m) => m.id));
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
  const notes = d.notes.map((n) => `<li>${esc(n.title)}</li>`).join('');
  // City mode (`cover`): a monitoring check's own error text ("Stalkerware
  // indicator data could not be loaded") would say what it looks for, so its
  // reason is the queue's neutral words (signals.js).
  const fogReason = (x) => (cover && HELD_MODULES.has(x.module) ? MONITORING_FOG_REASON : x.reason);
  const fog = d.fog.filter((x) => !x.notStarted).map((x) => `<li><strong>${esc(checkWords(x.module, x.checkName))}</strong>: ${esc(fogReason(x))}</li>`).join('');
  // Waiting for the person's go-ahead (the long phone-backup sweep): offered, never "couldn't check".
  const waiting = d.fog.filter((x) => x.notStarted).map((x) => `<li><button type="button" class="btn-t" data-go="signal:${esc(waitingId(d.id, x.module))}">${esc(waitingTitle)} ▶</button></li>`).join('');
  // Ran, but stopped before the end (the engine's "complete": false).
  // `stoppedEarly`: NotChecked counts it as unfinished, even with a partly-checked note (its titles shown with it).
  const hasTitles = (x) => Array.isArray(x.titles) && x.titles.length > 0;
  const unfinished = (d.unfinished || []).filter((x) => !hasTitles(x) || x.stoppedEarly === true)
    .map((x) => `<li><strong>${esc(checkWords(x.module, x.checkName))}</strong>${hasTitles(x) && !HELD_MODULES.has(x.module) ? `: ${esc(x.titles.join('; '))}` : ''}</li>`).join('');
  // A note said part of it couldn't look (`titles`, signals.js foldPartly).
  const partly = (d.unfinished || []).filter((x) => hasTitles(x) && x.stoppedEarly !== true)
    .map((x) => `<li><strong>${esc(checkWords(x.module, x.checkName))}</strong>${HELD_MODULES.has(x.module) ? '' : `: ${esc(x.titles.join('; '))}`}</li>`).join('');
  return `
  <section class="district-screen">
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <b>${esc(d.name)}</b></div>
    <h2 class="m-title">${esc(d.name)}</h2>
    ${skyline(d.status)}
    <p class="intel">${esc(districtLine(d, reclaimedIn(progress, d).length))}</p>
    ${missionsHtml || reclaimed ? `<div class="panel active"><div class="label">MISSIONS</div>${missionsHtml || ''}${reclaimed ? `<ul class="missions">${reclaimed}</ul>` : ''}${said}</div>` : ''}
    ${fog ? `<div class="panel fogged"><div class="label">COULDN’T CHECK HERE</div><p class="intel">That doesn’t mean it’s safe.</p><ul class="fog-list">${fog}</ul></div>` : ''}
    ${unfinished ? `<div class="panel fogged"><div class="label">DIDN’T FINISH HERE</div><p class="intel">These checks stopped before the end, so they may have missed something. That doesn’t mean it’s safe.</p><ul class="fog-list">${unfinished}</ul></div>` : ''}
    ${partly ? `<div class="panel fogged"><div class="label">ONLY PARTLY CHECKED HERE</div><p class="intel">These checks couldn’t look at everything. That doesn’t mean it’s safe.</p><ul class="fog-list">${partly}</ul></div>` : ''}
    ${waiting ? `<div class="panel"><div class="label">WAITING FOR YOUR GO-AHEAD</div><ul class="fog-list">${waiting}</ul></div>` : ''}
    ${notes ? `<details class="panel"><summary class="label">NOTES (${d.notes.length})</summary><ul class="notes">${notes}</ul></details>` : ''}
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(missionsHtml ? 'Pick one. You can stop after any of them.' : 'Nothing to do here right now.')}</p></div>
  </section>`;
}
