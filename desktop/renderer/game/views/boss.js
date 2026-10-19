import { esc } from '../escape.js';
import { bossDistricts, bossPercent } from '../boss.js';

const LABEL = { sweeping: 'SWEEPING', swept: 'SWEPT', waiting: 'WAITING' };

function skyline() {
  return '<div class="skyline" aria-hidden="true"><img src="assets/iso_occupied.png" alt=""><img class="tower" src="assets/iso_tower_occ.png" alt=""></div>';
}

// `learn(id)`: the district's lesson ({ done, count, finished }), or null when no
// lesson teaches it. Then it's a plain card, not a button.
function districtCard(d, learn) {
  const badge = `<span class="badge ${d.state === 'sweeping' ? 'cyan' : 'skip'}">${LABEL[d.state]}</span>`;
  const head = `<h4>${esc(d.name.toUpperCase())}</h4>${skyline()}`;
  const l = learn ? learn(d.id) : null;
  if (!l) return `<div class="district ${d.state}">${head}<span class="d-foot">${badge}</span></div>`;
  const now = d.state === 'sweeping';
  // Every lesson for it is finished: the card itself opens nothing, so DONE
  // never drops the person into a quiz. A review is a separate, optional button.
  if (l.done) {
    return `
      <div class="district learned ${d.state}">${head}
        <span class="d-foot" id="sweep-${esc(d.id)}">${badge}<span class="cue">DONE ✓</span></span>
        <p>You’ve done ${l.count === 1 ? 'this lesson' : 'these lessons'}.
          <button type="button" class="btn-t" data-go="review:${esc(d.id)}" aria-label="Review one? (optional): a lesson about ${esc(d.name)}">REVIEW ONE? (OPTIONAL)</button></p></div>`;
  }
  const progress = l.count > 1 ? ` <small>${esc(l.finished)}/${esc(l.count)} DONE</small>` : '';
  return `
      <button type="button" class="district learnable ${d.state}${now ? ' suggested' : ''}" data-go="learn:${esc(d.id)}"
        aria-label="Learn about ${esc(d.name)}" aria-describedby="${now ? `now-${esc(d.id)} ` : ''}sweep-${esc(d.id)}">${head}
        ${now ? `<span class="now" id="now-${esc(d.id)}">Scanning now — learn about it</span>` : ''}
        <span class="d-foot" id="sweep-${esc(d.id)}">${badge}<span class="cue">LEARN ▶</span>${progress}</span></button>`;
}

// `tipsOpen`: the pop-up tips stay as the person left them across redraws.
export function renderBoss({ boss, scout, tips, tipsOpen = true, learn = null }) {
  const ds = bossDistricts(boss);
  const pct = bossPercent(boss);
  const current = ds.find((d) => d.state === 'sweeping');
  const teaches = current && learn && learn(current.id);
  const anyLesson = !!learn && ds.some((d) => learn(d.id));
  const line = !current ? `Starting the checkup engine.${anyLesson ? ' Pick a district marked LEARN to see what it looks for.' : ''}`
    : teaches ? `Checking ${current.name} now. Click it to learn what I’m looking for. I’ll call you when the checkup is done.`
      : `Checking ${current.name} now. You don’t need to watch. I’ll call you when it’s done.`;
  const tipList = Array.isArray(tips) && tips.length ? `
    <details class="panel"${tipsOpen ? ' open' : ''}><summary class="label" data-act="toggle-tips">POP-UPS YOU MIGHT SEE</summary>
      <ul class="notes">${tips.map((t) => `<li><strong>${esc(t.title)}</strong> ${esc(t.body)}</li>`).join('')}</ul></details>` : '';
  return `
  <section class="boss" aria-label="Your checkup is running">
    <div class="boss-top">${scout('proud', 72)}
      <div class="boss-meter"><h2>THE SWEEP</h2>
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="--pct: ${pct}%"></i></div>
        <div class="bar-meta"><span>${boss.total ? `${esc(boss.index)} / ${esc(boss.total)} CHECKS` : 'GETTING READY'}</span>
          ${boss.found ? `<span>${esc(boss.found)} THING${boss.found === 1 ? '' : 'S'} NOTED SO FAR</span>` : ''}</div></div></div>
    ${tipList}
    <div class="districts sweep">${ds.map((d) => districtCard(d, learn)).join('')}</div>
    <div class="row"><p class="say">${esc(line)}</p>
      <button type="button" class="btn-s lime" data-go="training">ALL LESSONS</button>
      <button type="button" class="btn-t" data-act="leave">PLAIN VIEW</button></div>
  </section>`;
}
