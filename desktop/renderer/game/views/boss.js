// The sweep: the real scan, drawn in the command center's language (HUD,
// panels, labels, ops log). Left: what is being checked right now, why, and
// where. Centre: WHILE YOU WAIT, a lesson after another, never covering the
// progress. Right: the city's districts. Bottom: the sweep log of finished
// checks. Pure; every string from the engine or a lesson is escaped.
import { esc } from '../escape.js';
import { bossDistricts, bossPercent } from '../boss.js';
import { noteFor, logLine } from '../sweep.js';
import { DISTRICTS, OUTSKIRTS, districtIdFor } from '../findings-to-city.js';

const LABEL = { sweeping: 'SWEEPING', swept: 'SWEPT', waiting: 'WAITING' };
export const SWEEP_LOG_SHOWN = 10;

function skyline() {
  return '<div class="skyline" aria-hidden="true"><img src="assets/iso_occupied.png" alt=""><img class="tower" src="assets/iso_tower_occ.png" alt=""></div>';
}

const districtName = (category) => {
  const id = districtIdFor(category);
  return ([...DISTRICTS, OUTSKIRTS].find((d) => d.id === id) || OUTSKIRTS).name;
};
// A note's `where` may wrap commands in backticks; the whole line is shown as evidence.
const plainWhere = (s) => String(s || '').replace(/`/g, '');

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

// NOW CHECKING: the check running right now, in plain words, then the evidence
// line (where it looks, the check's own name, its district).
function nowPanel(boss, scout, line) {
  const now = boss.now;
  const note = now ? noteFor(now.module) : null;
  const count = now && boss.total && now.index ? ` · CHECK ${esc(now.index)} OF ${esc(boss.total)}` : '';
  let body;
  if (note) {
    body = `
      <h3 class="now-what">${esc(note.what)}</h3>
      ${note.why ? `<p class="intel now-why">${esc(note.why)}</p>` : ''}
      <dl class="evidence">
        ${note.where ? `<dt>LOOKS AT</dt><dd><code class="where">${esc(plainWhere(note.where))}</code></dd>` : ''}
        <dt>CHECK</dt><dd><code>${esc(note.module)}</code> · ${esc(districtName(now.category))}</dd>
      </dl>`;
  } else if (now) {
    body = '<h3 class="now-what">A check</h3>';
  } else if (boss.log && boss.log.length) {
    const last = logLine(boss.log[boss.log.length - 1]);
    body = `<h3 class="now-what">Starting the next check</h3>
      <p class="intel now-why">Just finished: ${esc(last.what)} · ${esc(last.result)}</p>`;
  } else {
    body = '<h3 class="now-what">Starting the checkup engine</h3>';
  }
  return `
    <section class="panel active sweep-now" aria-label="Now checking">
      <div class="label">NOW CHECKING${count}</div>
      <div class="now-row">${scout('proud', 64)}<div class="now-body">${body}</div></div>
      <p class="working"><i aria-hidden="true"></i>Working. Some checks take longer than others; a long pause is normal.</p>
      <p class="say">${esc(line)}</p>
    </section>`;
}

// WHILE YOU WAIT: the lesson open inline, or the next one on offer.
// `offer`: { lesson, reason } | null. `lessonsLoaded`: false while they load.
function learnPanel({ lessonHtml, offer, lessonsLoaded, lessonsDone, lessonsTotal, now }) {
  const head = `<div class="label">WHILE YOU WAIT${lessonsTotal ? ` · ${esc(lessonsDone)}/${esc(lessonsTotal)} LESSONS DONE` : ''}</div>`;
  if (lessonHtml) return `<section class="panel sweep-learn open quiz" aria-label="A lesson while you wait">${head}${lessonHtml}</section>`;
  let body;
  if (offer && offer.lesson) {
    const l = offer.lesson;
    const n = Array.isArray(l.questions) ? l.questions.length : 0;
    const note = now ? noteFor(now.module) : null;
    const why = offer.reason === 'module' && note ? `About the check running now: ${note.what.charAt(0).toLowerCase()}${note.what.slice(1)}.`
      : offer.reason === 'district' && now ? `About ${districtName(now.category)}, being checked now.`
        : 'A short lesson. The checkup keeps going while you do it.';
    body = `
      <p class="offer-why">${esc(why)}</p>
      <h3 class="offer-title">${esc(l.title)}</h3>
      <p class="offer-meta">${n} question${n === 1 ? '' : 's'}</p>
      <div class="row"><button type="button" class="btn-p" data-act="sweep-start:${esc(l.id)}">START ▶</button>
        <button type="button" class="btn-t" data-act="sweep-pass">ANOTHER ONE</button></div>`;
  } else if (!lessonsLoaded) {
    body = '<p class="intel">Getting the lessons ready.</p>';
  } else if (lessonsTotal) {
    body = `<p class="intel">Every lesson is done. Want to try a few questions again, asked a different way?</p>
      <div class="row"><button type="button" class="btn-s" data-act="sweep-review">REVIEW ONE ▶</button></div>`;
  } else {
    body = '<p class="intel">The lessons couldn’t load. The checkup still works.</p>';
  }
  return `<section class="panel sweep-learn" aria-label="A lesson while you wait">${head}${body}</section>`;
}

function logPanel(boss) {
  const entries = (boss.log || []).slice(-SWEEP_LOG_SHOWN).reverse();
  const rows = entries.map((e) => {
    const l = logLine(e);
    const badge = l.tone === 'noted' ? 'amb' : l.tone === 'couldnt' ? 'fog' : 'skip';
    return `<li><span class="log-n">${e.index ? esc(e.index) : ''}</span><span class="log-what">${esc(l.what)}</span><span class="badge ${badge}">${esc(l.result.toUpperCase())}</span>${l.module ? `<code>${esc(l.module)}</code>` : ''}</li>`;
  }).join('');
  const more = (boss.log || []).length > SWEEP_LOG_SHOWN ? `<p class="intel">And ${boss.log.length - SWEEP_LOG_SHOWN} earlier.</p>` : '';
  return `
    <section class="panel deck-log sweep-log" aria-label="Sweep log"><div class="label">SWEEP LOG · FINISHED CHECKS</div>
      ${rows ? `<ol class="log">${rows}</ol>${more}` : '<p class="intel">Each check shows up here as it finishes.</p>'}
    </section>`;
}

// `tipsOpen`: the pop-up tips stay as the person left them across redraws.
export function renderBoss({ boss, scout, tips, tipsOpen = true, learn = null, lessonHtml = '', offer = null,
  lessonsLoaded = true, lessonsDone = 0, lessonsTotal = 0 }) {
  const ds = bossDistricts(boss);
  const pct = bossPercent(boss);
  const current = ds.find((d) => d.state === 'sweeping');
  const teaches = current && learn && learn(current.id);
  const anyLesson = !!learn && ds.some((d) => learn(d.id));
  const line = !current ? `I’ll call you when the checkup is done.${anyLesson ? ' Pick a district marked LEARN to see what it looks for.' : ''}`
    : teaches ? `Checking ${current.name} now. Pick it under DISTRICTS to learn what I’m looking for. I’ll call you when the checkup is done.`
      : `Checking ${current.name} now. You don’t need to watch. I’ll call you when it’s done.`;
  const tipList = Array.isArray(tips) && tips.length ? `
    <details class="panel tips"${tipsOpen ? ' open' : ''}><summary class="label" data-act="toggle-tips">POP-UPS YOU MIGHT SEE</summary>
      <ul class="notes">${tips.map((t) => `<li><strong>${esc(t.title)}</strong> ${esc(t.body)}</li>`).join('')}</ul></details>` : '';
  const top = `
  <header class="hud deck-top sweep-top">
    <span class="hud-title">THE SWEEP</span>
    <span class="stat cyan">${boss.total ? `<b>${esc(boss.index)}/${esc(boss.total)}</b> <small>CHECKS DONE</small>` : '<small>GETTING READY</small>'}</span>
    ${boss.found ? `<span class="stat amb"><b>${esc(boss.found)}</b> <small>NOTED</small></span>` : ''}
    ${boss.couldnt ? `<span class="stat grey"><b>${esc(boss.couldnt)}</b> <small>COULDN’T CHECK</small></span>` : ''}
    <span class="switch"><button type="button" data-go="training">ALL LESSONS</button><button type="button" data-act="leave">PLAIN VIEW</button><b class="on">SWEEP</b></span>
  </header>`;
  return `${top}
  <section class="boss sweep-deck" aria-label="Your checkup is running">
    <div class="sweep-meter">
      <div class="bar" role="progressbar" aria-label="Checkup progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${pct}"><i style="--pct: ${pct}%"></i></div></div>
    <div class="sweep-side">${nowPanel(boss, scout, line)}</div>
    ${tipList ? `<div class="sweep-tips">${tipList}</div>` : ''}
    ${learnPanel({ lessonHtml, offer, lessonsLoaded, lessonsDone, lessonsTotal, now: boss.now })}
    <aside class="sweep-city" aria-label="The city's districts"><div class="label">DISTRICTS</div>
      <div class="districts sweep">${ds.map((d) => districtCard(d, learn)).join('')}</div></aside>
    ${logPanel(boss)}
  </section>`;
}
