import { esc } from '../escape.js';
import { bossDistricts, bossPercent } from '../boss.js';

const LABEL = { sweeping: 'SWEEPING', swept: 'SWEPT', waiting: 'WAITING' };

function skyline() {
  return '<div class="skyline" aria-hidden="true"><img src="assets/iso_occupied.png" alt=""><img class="tower" src="assets/iso_tower_occ.png" alt=""></div>';
}

export function renderBoss({ boss, scout, tips }) {
  const ds = bossDistricts(boss);
  const pct = bossPercent(boss);
  const current = ds.find((d) => d.state === 'sweeping');
  const line = current
    ? `Checking ${current.name} now. You don’t need to watch. I’ll call you when it’s done.`
    : 'Starting the checkup engine.';
  const tipList = Array.isArray(tips) && tips.length ? `
    <details class="panel" open><summary class="label">POP-UPS YOU MIGHT SEE</summary>
      <ul class="notes">${tips.map((t) => `<li><strong>${esc(t.title)}</strong> ${esc(t.body)}</li>`).join('')}</ul></details>` : '';
  return `
  <section class="boss" aria-label="Your checkup is running">
    <div class="boss-top">${scout('proud', 72)}
      <div class="boss-meter"><h2>THE SWEEP</h2>
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="--pct: ${pct}%"></i></div>
        <div class="bar-meta"><span>${boss.total ? `${esc(boss.index)} / ${esc(boss.total)} CHECKS` : 'GETTING READY'}</span>
          ${boss.found ? `<span>${esc(boss.found)} THING${boss.found === 1 ? '' : 'S'} NOTED SO FAR</span>` : ''}</div></div></div>
    <div class="districts sweep">${ds.map((d) => `
      <div class="district ${d.state}"><h4>${esc(d.name.toUpperCase())}</h4>${skyline()}
        <span class="d-foot"><span class="badge ${d.state === 'sweeping' ? 'cyan' : 'skip'}">${LABEL[d.state]}</span></span></div>`).join('')}</div>
    <div class="row"><p class="say">${esc(line)}</p>
      <button type="button" class="btn-s lime" data-go="training">PLAY A LESSON WHILE YOU WAIT</button>
      <button type="button" class="btn-t" data-act="leave">PLAIN VIEW</button></div>
    ${tipList}
  </section>`;
}
