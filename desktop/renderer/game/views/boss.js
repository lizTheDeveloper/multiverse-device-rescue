import { esc } from '../escape.js';
import { bossDistricts, bossPercent, bossPreview } from '../boss.js';

const LABEL = { sweeping: 'SWEEPING', swept: 'SWEPT', waiting: 'WAITING', skip: 'NOT IN THIS SWEEP' };
const label = (d) => (d.state === 'part' && d.checks ? `${d.checks.done}/${d.checks.of} CHECKED` : LABEL[d.state] || 'WAITING');

function skyline() {
  return '<div class="skyline" aria-hidden="true"><img src="assets/iso_occupied.png" alt=""><img class="tower" src="assets/iso_tower_occ.png" alt=""></div>';
}

// `learn(id)`: the district's lesson ({ done, count, finished }), or null when no
// lesson teaches it. Then it's a plain card, not a button.
function districtCard(d, learn) {
  const badge = `<span class="badge ${d.state === 'sweeping' ? 'cyan' : 'skip'}">${esc(label(d))}</span>`;
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

export const NO_MISSION_LINE = 'No missions from here yet.';
// Mission titles shown per swept district before "AND N MORE".
export const PREVIEW_SHOWN = 6;
// After the last check, before the city: the engine's "who made it" lookups.
export const LOOKUP_LINE = 'Every district is checked. I’m finding out who built what. I’ll call you when the city is ready.';

// What the swept districts' finished checks found, read-only: titles to come
// back to, never a mission to start, and never "all clear" mid-sweep.
function previewHtml(preview) {
  if (!preview.length) return '';
  const rows = preview.map((d) => {
    const n = d.missions.length;
    const said = n ? `${n} MISSION${n === 1 ? '' : 'S'} WAITING` : '';
    const fog = d.fog ? `${d.fog} COULDN’T CHECK` : '';
    // No mission from it: one neutral line, the same whatever it found (some
    // of it may be held), so it is never blank and never reads as "clear".
    // A long list shows its first few titles; the count above says how many in all.
    const more = n > PREVIEW_SHOWN ? `<li class="more">AND ${n - PREVIEW_SHOWN} MORE</li>` : '';
    const titles = n ? `<ul class="notes">${d.missions.slice(0, PREVIEW_SHOWN).map((m) => `<li>${esc(m.title)}</li>`).join('')}${more}</ul>`
      : `<p class="intel">${esc(NO_MISSION_LINE)}</p>`;
    return `<li><strong>${esc(d.name.toUpperCase())}</strong>${said ? ` <span class="badge skip">${esc(said)}</span>` : ''}${fog ? ` <span class="badge fog">${esc(fog)}</span>` : ''}${titles}</li>`;
  }).join('');
  return `
    <section class="panel sweep-so-far" aria-label="Swept so far"><h3 class="label">SWEPT SO FAR</h3>
      <p class="intel">Missions open when the sweep is done.</p>
      <ul class="notes">${rows}</ul></section>`;
}

// `tipsOpen`: the pop-up tips stay as the person left them across redraws.
// `toCity(doc)`: the controller's scan-to-city path, for the swept-so-far preview.
export const POPUP_LINE = 'Your computer may ask for permission. Click Allow. Nothing here ever asks for your password.';
// `firstSweep`: no sweep has finished on this computer before, so Scout says
// once where the plain list is.
export const FIRST_SWEEP_LINE = 'This is your city. The LIST tab shows the same things as a list, any time.';
export function renderBoss({ boss, scout, tips, tipsOpen = false, learn = null, toCity = null, firstSweep = false }) {
  const ds = bossDistricts(boss);
  const pct = bossPercent(boss);
  // The check now running; its district may already read SWEPT if it was the last one there.
  const current = ds.find((d) => d.state === 'sweeping') || (boss && boss.current ? ds.find((d) => d.id === boss.current) : undefined);
  const teaches = current && learn && learn(current.id);
  const anyLesson = !!learn && ds.some((d) => learn(d.id));
  const lookingUp = boss && boss.total > 0 && boss.index >= boss.total;
  const line = lookingUp ? LOOKUP_LINE : !current ? `Starting the checkup engine.${anyLesson ? ' Pick a district marked LEARN to see what it looks for.' : ''}`
    : teaches ? `Checking ${current.name} now. Click it to learn what I’m looking for. I’ll call you when the checkup is done.`
      : `Checking ${current.name} now. You don’t need to watch. I’ll call you when it’s done.`;
  // One line; what each pop-up says is behind it, closed until asked for.
  const tipList = Array.isArray(tips) && tips.length ? `
    <p class="intel popup-line">${esc(POPUP_LINE)}</p>
    <details class="panel"${tipsOpen ? ' open' : ''}><summary class="label" data-act="toggle-tips">POP-UPS YOU MIGHT SEE</summary>
      <ul class="notes">${tips.map((t) => `<li><strong>${esc(t.title)}</strong> ${esc(t.body)}</li>`).join('')}</ul></details>` : '';
  return `
  <section class="boss" aria-label="Your checkup is running">
    <div class="boss-top">${scout('proud', 72)}
      <div class="boss-meter"><h2>THE SWEEP</h2>
        <div class="bar" role="progressbar" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="--pct: ${pct}%"></i></div>
        <div class="bar-meta"><span>${boss.total ? `${esc(boss.index)} / ${esc(boss.total)} CHECKS` : 'GETTING READY'}</span>
          ${boss.found ? `<span>${esc(boss.found)} THING${boss.found === 1 ? '' : 'S'} NOTED SO FAR</span>` : ''}</div></div></div>
    <div class="row boss-say"><p class="say">${firstSweep ? `${esc(FIRST_SWEEP_LINE)} ` : ''}${esc(line)}</p>
      <button type="button" class="btn-s lime" data-go="training">ALL LESSONS</button></div>
    ${tipList}
    <div class="districts sweep">${ds.map((d) => districtCard(d, learn)).join('')}</div>
    ${previewHtml(bossPreview(boss, toCity))}
  </section>`;
}
