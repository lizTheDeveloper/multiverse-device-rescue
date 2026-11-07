// One city, two rings: the computer's districts (from the checkup) and the
// accounts' districts (from the Reclaim City game, which the person reports).
import { esc } from '../escape.js';
import { reclaimedIn } from '../progress.js';
import { skyline, districtBadges, districtLine, heldView, mapLine } from './map.js';

// Account progress is reported, not proven, and a district the scan disagrees
// with is never drawn lit.
function accountSkyline(c) {
  const done = c.percent >= 100 && !c.checkAgain;
  const img = done ? 'iso_liberated' : c.percent > 0 ? 'iso_progress' : 'iso_occupied';
  const tone = done ? 'lit' : c.percent > 0 ? 'warm' : 'dark';
  return `<div class="skyline" aria-hidden="true"><img class="${tone}" src="assets/${img}.png" alt=""><img class="tower ${tone}" src="assets/${done ? 'iso_tower_lib' : 'iso_tower_occ'}.png" alt=""></div>`;
}

// goFor, heat, selected, held and heldAt: as in map.js's renderMap. Account districts are unchanged.
export function renderOneCityMap({ city, progress, accountCards, focus, cameBack, scout, accountsError,
  goFor = (d) => `district:${d.id}`, heat = {}, selected = null, held = null, heldAt = null }) {
  const device = city.districts.map((d0) => {
    const d = heldView(d0, held);
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}${heat[d.id] ? ` heat-${esc(heat[d.id])}` : ''}" data-go="${esc(goFor(d))}"${selected === d.id ? ' aria-current="true"' : ''}>
        <span class="d-name">${esc(d.name.toUpperCase())}</span>${skyline(d.status)}
        <p>${esc(districtLine(d, reclaimed, heldAt))}</p><span class="d-foot">${districtBadges(d, reclaimed)}</span>
      </button>`;
  }).join('');
  const accounts = (accountCards || []).map((c) => `
      <button type="button" class="district account${c.checkAgain ? ' warmish' : ''}" data-go="rc:#/district/${esc(c.id)}"${focus === c.id ? ' data-focus' : ''}>
        <span class="d-name">${esc(String(c.name).toUpperCase())}</span>${accountSkyline(c)}
        <p>${esc(c.description)}</p>
        <span class="d-foot">${c.completed ? `<span class="badge cyan">${esc(c.percent)}% REPORTED</span>` : '<span class="badge skip">NOT STARTED</span>'}
        ${c.checkAgain ? '<span class="badge warn">CHECK AGAIN</span>' : ''}</span>
      </button>`).join('');
  const line = mapLine(city, cameBack, held, heldAt);
  return `
  <section class="map" aria-label="Your computer and your accounts as one city">
    <div class="ring-label"${focus === 'computer' ? ' data-focus' : ''}><h2 class="label">YOUR COMPUTER · FROM THE CHECKUP</h2></div>
    <div class="districts">${device}</div>
    <div class="ring-label"><h2 class="label">YOUR ACCOUNTS · YOU REPORT THESE</h2></div>
    ${accountsError
      ? `<p class="say">${esc('Your accounts’ districts couldn’t load. Your computer’s districts still work.')}</p>`
      : `<div class="districts">${accounts}</div>`}
    <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(line)}</p></div>
  </section>`;
}
