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
// A district holding a monitoring finding (held.js): its own city card has
// nothing left in it, but it isn't clear. It reads as checked, points to where
// it is said, and never says NOTHING FOUND or RECLAIMED. Standard mode (or a
// host that can't say its mode): the note above the map. City mode
// (`heldAt`, the generated district's name): that district, as there's no note.
export const HELD_DISTRICT_LINE = 'Checked. See the note above.';
export const HELD_SCOUT_LINE = 'There’s a note above the map. Fog means a place I couldn’t see into.';
export const heldDistrictLine = (heldAt) => (heldAt ? `Checked. See ${heldAt}.` : HELD_DISTRICT_LINE);
export const heldScoutLine = (heldAt) => (heldAt ? `Have a look in ${heldAt}. Fog means a place I couldn’t see into.` : HELD_SCOUT_LINE);
export function heldView(d, held) {
  return held && typeof held.has === 'function' && held.has(d.id) && d.status === 'clear' ? { ...d, status: 'partial', held: true } : d;
}

export function districtBadges(d, reclaimed = 0) {
  const crit = d.missions.filter((m) => m.severity === 'critical').length;
  const warn = d.missions.length - crit;
  const out = [];
  if (crit) out.push(`<span class="badge crit">${crit} CRITICAL</span>`);
  if (warn) out.push(`<span class="badge warn">${warn} WARNING</span>`);
  if (d.notes.length) out.push(`<span class="badge skip">${d.notes.length} NOTES</span>`);
  if (d.fog.length) out.push(`<span class="badge fog">${d.fog.length} COULDN’T CHECK</span>`);
  const unfinished = (d.unfinished || []).length;
  if (unfinished) out.push(`<span class="badge fog">${unfinished} DIDN’T FINISH</span>`);
  if (d.held) return out.join('');
  if (reclaimed) out.push(`<span class="badge safe">${reclaimed} RECLAIMED</span>`);
  else if (d.status === 'clear') out.push('<span class="badge safe">NOTHING FOUND</span>');
  return out.join('');
}

export function districtLine(d, reclaimed = 0, heldAt = null) {
  if (d.held) return heldDistrictLine(heldAt);
  if (d.status === 'fog') return 'Couldn’t check here. That doesn’t mean it’s safe.';
  if (d.status === 'partial' && (d.unfinished || []).length && !d.fog.length) return 'Some checks here didn’t finish. That doesn’t mean it’s safe.';
  if (d.status === 'none') return 'No checks ran here on this computer.';
  if (d.status === 'clear' && reclaimed) return 'What was found here before is gone now. Reclaim City checked again.';
  if (d.status === 'clear') return 'Nothing found in the checks that ran here.';
  return d.blurb;
}

// `goFor(d)`: what a district card opens (the deck filters its queue instead).
// `heat`: districtId → 'hot' | 'warn' for open signals. `selected`: the filtered district.
// `held`: the ids of districts holding a monitoring finding (heldView).
export function mapLine(city, cameBack, held, heldAt = null) {
  if (cameBack && cameBack.length) return SCOUT.cameBack;
  const line = mapScoutLine(city);
  return line === SCOUT.mapQuiet && held && held.size ? heldScoutLine(heldAt) : line;
}

export function renderMap({ city, progress, cameBack, scout, goFor = (d) => `district:${d.id}`, heat = {}, selected = null, held = null, heldAt = null }) {
  const cards = city.districts.map((d0) => {
    const d = heldView(d0, held);
    const reclaimed = progress ? reclaimedIn(progress, d).length : 0;
    return `
      <button type="button" class="district ${esc(d.status)}${heat[d.id] ? ` heat-${esc(heat[d.id])}` : ''}" data-go="${esc(goFor(d))}"${selected === d.id ? ' aria-current="true"' : ''}>
        <h4>${esc(d.name.toUpperCase())}</h4>
        ${skyline(d.status)}
        <p>${esc(districtLine(d, reclaimed, heldAt))}</p>
        <span class="d-foot">${districtBadges(d, reclaimed)}</span>
      </button>`;
  }).join('');
  const line = mapLine(city, cameBack, held, heldAt);
  return `
  <section class="map" aria-label="Your computer as a city">
    <div class="districts">${cards}</div>
    <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(line)}</p></div>
  </section>`;
}
