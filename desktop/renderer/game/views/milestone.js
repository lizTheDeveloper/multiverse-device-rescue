import { esc } from '../escape.js';

const statusOf = (progress, id) => (progress.missions[id] && progress.missions[id].status) || 'open';

export function districtComplete(district, progress) {
  return district.missions.length > 0
    && district.missions.every((m) => ['reclaimed', 'yours'].includes(statusOf(progress, m.id)));
}

export function renderMilestone({ district: d, progress, scout }) {
  const fixed = d.missions.filter((m) => statusOf(progress, m.id) === 'reclaimed');
  const yours = d.missions.filter((m) => statusOf(progress, m.id) === 'yours');
  return `
  <section class="outcome o-win milestone">
    <span class="badge safe">DISTRICT TAKEN BACK</span>
    <h2>${esc(d.name.toUpperCase())}</h2>
    ${scout('proud', 72)}
    <p>Every mission here is done. Device Rescue checked each fix again.</p>
    ${fixed.length ? `<div class="panel"><div class="label">FIXED AND CHECKED</div><ul class="notes">${fixed.map((m) => `<li>${esc(m.title)}</li>`).join('')}</ul></div>` : ''}
    ${yours.length ? `<div class="panel"><div class="label">MARKED AS YOURS</div><p class="intel">These stay listed. They weren’t fixed, because you said they’re yours.</p><ul class="notes">${yours.map((m) => `<li>${esc(m.title)}</li>`).join('')}</ul></div>` : ''}
    <button type="button" class="btn-s" data-go="map">BACK TO THE CITY</button>
  </section>`;
}
