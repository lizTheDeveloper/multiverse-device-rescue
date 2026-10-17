import { esc } from '../escape.js';
import { SCOUT, mapScoutLine } from '../scout-lines.js';
import { reclaimedIn } from '../progress.js';

const SKYLINE = {
  hot: ['iso_tower_occ', 'iso_occupied', 'iso_tower_occ'],
  warn: ['iso_progress', 'iso_occupied'],
  clear: ['iso_liberated', 'iso_tower_lib'],
  // Some checks here couldn't run: never drawn like a clear district.
  partial: ['iso_progress', 'iso_occupied'],
  fog: ['iso_occupied', 'iso_tower_occ'],
  none: ['iso_occupied'],
};

export function skyline(status) {
  const cls = status === 'fog' || status === 'none' ? 'skyline fog' : 'skyline';
  const tone = { hot: 'dark', warn: 'warm', clear: 'lit' }[status] || '';
  return `<div class="${cls}" aria-hidden="true">${(SKYLINE[status] || SKYLINE.none)
    .map((img) => `<img class="${img.includes('tower') ? 'tower ' : ''}${tone}" src="assets/${img}.png" alt="">`).join('')}</div>`;
}

// `reclaimed` is how many missions here were checked again and gone.
export function districtBadges(d, reclaimed = 0) {
  const crit = d.missions.filter((m) => m.severity === 'critical').length;
  const warn = d.missions.length - crit;
  const out = [];
  if (crit) out.push(`<span class="badge crit">${crit} CRITICAL</span>`);
  if (warn) out.push(`<span class="badge warn">${warn} WARNING</span>`);
  if (d.notes.length) out.push(`<span class="badge skip">${d.notes.length} NOTES</span>`);
  if (d.fog.length) out.push(`<span class="badge fog">${d.fog.length} COULDN’T CHECK</span>`);
  if (reclaimed) out.push(`<span class="badge safe">${reclaimed} RECLAIMED</span>`);
  else if (d.status === 'clear') out.push('<span class="badge safe">NOTHING FOUND</span>');
  return out.join('');
}

export function districtLine(d, reclaimed = 0) {
  if (d.status === 'fog') return 'Couldn’t check here. That doesn’t mean it’s safe.';
  if (d.status === 'none') return 'No checks ran here on this computer.';
  if (d.status === 'clear' && reclaimed) return 'What was found here before is gone now. Device Rescue checked again.';
  if (d.status === 'clear') return 'Nothing found in the checks that ran here.';
  return d.blurb;
}

export function renderMap({ city, progress, cameBack, scout }) {
  const cards = city.districts.map((d) => {
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}" data-go="district:${esc(d.id)}">
        <h4>${esc(d.name.toUpperCase())}</h4>
        ${skyline(d.status)}
        <p>${esc(districtLine(d, reclaimed))}</p>
        <span class="d-foot">${districtBadges(d, reclaimed)}</span>
      </button>`;
  }).join('');
  const line = cameBack && cameBack.length ? SCOUT.cameBack : mapScoutLine(city);
  return `
  <section class="map" aria-label="Your computer as a city">
    <div class="districts">${cards}</div>
    <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(line)}</p></div>
  </section>`;
}
