import { esc } from '../escape.js';
import { reclaimedIn } from '../progress.js';

const statusOf = (progress, id) => (progress.missions[id] && progress.missions[id].status) || 'open';

// A district is taken back when nothing in it is still open or saved for later,
// something in it was reclaimed (checked again and gone) or marked as yours,
// and no check in it failed. Fog means we couldn't see, so it is never complete.
export function districtComplete(district, progress) {
  if (district.fog && district.fog.length) return false;
  if (district.missions.some((m) => ['open', 'later'].includes(statusOf(progress, m.id)))) return false;
  const yours = district.missions.filter((m) => statusOf(progress, m.id) === 'yours').length;
  return yours + reclaimedIn(progress, district).length > 0;
}

export function renderMilestone({ district: d, progress, scout }) {
  const fixed = reclaimedIn(progress, d);
  const yours = d.missions.filter((m) => statusOf(progress, m.id) === 'yours');
  const fog = (d.fog || []).map((x) => `<li><strong>${esc(x.module)}</strong>: ${esc(x.reason)}</li>`).join('');
  const lead = fog
    ? 'Reclaim City checked each fix again. Some checks here couldn’t run.'
    : 'Every mission here is done. Reclaim City checked each fix again.';
  return `
  <section class="outcome ${fog ? 'o-err' : 'o-win'} milestone">
    ${fog ? '<span class="badge fog">NOT EVERYTHING HERE COULD BE CHECKED</span>' : '<span class="badge safe">DISTRICT TAKEN BACK</span>'}
    <h2>${esc(d.name.toUpperCase())}</h2>
    ${scout('proud', 72)}
    <p>${esc(lead)}</p>
    ${fixed.length ? `<div class="panel"><div class="label">FIXED AND CHECKED</div><ul class="notes">${fixed.map((m) => `<li>${esc(m.title)}</li>`).join('')}</ul></div>` : ''}
    ${yours.length ? `<div class="panel"><div class="label">MARKED AS YOURS</div><p class="intel">These stay listed. They weren’t fixed, because you said they’re yours.</p><ul class="notes">${yours.map((m) => `<li>${esc(m.title)}</li>`).join('')}</ul></div>` : ''}
    ${fog ? `<div class="panel fogged"><div class="label">COULDN’T CHECK HERE</div><p class="intel">Couldn’t check here. That doesn’t mean it’s safe.</p><ul class="fog-list">${fog}</ul></div>` : ''}
    <button type="button" class="btn-s" data-go="map">BACK TO THE CITY</button>
  </section>`;
}
