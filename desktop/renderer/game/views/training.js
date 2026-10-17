import { esc } from '../escape.js';
import { lessonDone } from '../progress.js';

// Lesson text may name a page in `backticks`; show it as code. Escape first.
export function lessonText(s) {
  return esc(s).replace(/`([^`]+)`/g, '<code>$1</code>');
}

export function cityBanner() {
  return `<div class="banner" role="status"><span>Your checkup is done.</span>
    <button type="button" class="btn-p" data-go="city">SEE YOUR CITY ▶</button></div>`;
}

// On every Training Grounds and lesson screen: the way to the checkup.
export function skipBar(scan) {
  if (scan && scan.running) {
    return `<div class="skip-bar"><span>Your checkup is running: ${esc(scan.index)} of ${esc(scan.total || '…')} checks.</span>
      <button type="button" class="btn-s lime" data-go="boss">BACK TO THE CHECKUP ▶</button></div>`;
  }
  const label = scan && scan.error ? 'START THE CHECKUP ▶' : 'SKIP TO THE CHECKUP ▶';
  return `<div class="skip-bar"><span>You don’t need to finish any lessons first.</span>
    <button type="button" class="btn-s lime" data-act="start-checkup">${label}</button></div>`;
}

export function trainingHud(progress, lessons) {
  const done = lessons.filter((l) => lessonDone(progress, l.id)).length;
  return `<header class="hud"><span class="hud-title">THE TRAINING GROUNDS</span>
    ${lessons.length ? `<span class="stat lime"><b>${done}/${lessons.length}</b> <small>LESSONS</small></span>` : ''}
    <span class="switch"><button type="button" data-act="leave">PLAIN VIEW</button></span></header>`;
}

function lessonItem(l, progress) {
  const n = l.questions.length;
  return `<li><button type="button" class="lesson${lessonDone(progress, l.id) ? ' done' : ''}" data-go="lesson:${esc(l.id)}">
    <b>${esc(l.title)}</b><small>${n} question${n === 1 ? '' : 's'}</small>
    ${lessonDone(progress, l.id) ? '<span class="badge cyan">DONE</span>' : ''}</button></li>`;
}

export function renderTraining({ ordered, progress, worryTitle, scan, scout, pendingCity }) {
  const all = [...ordered.recommended, ...ordered.other];
  const head = worryTitle ? `RECOMMENDED FOR “${esc(String(worryTitle).toUpperCase())}”` : 'START HERE';
  const failed = scan && scan.error ? `
    <div class="panel fogged" role="alert"><div class="label">THE CHECKUP STOPPED</div>
      <p class="intel">The checkup didn’t finish. This is what it said: ${esc(scan.error)}</p>
      <p class="intel">Nothing on your computer was changed. You can start it again whenever you’re ready.</p></div>` : '';
  return `
  ${trainingHud(progress, all)}
  ${pendingCity ? cityBanner() : ''}
  ${failed}
  <section class="train">
    <div class="lessons">
      ${ordered.recommended.length ? `<span class="label">${head}</span><ul>${ordered.recommended.map((l) => lessonItem(l, progress)).join('')}</ul>` : ''}
      ${ordered.other.length ? `<span class="label faint">ALSO HERE</span><ul>${ordered.other.map((l) => lessonItem(l, progress)).join('')}</ul>` : ''}
      ${all.length ? '' : '<p class="intel">The lessons couldn’t load. The checkup still works.</p>'}
    </div>
    <div class="quiz">
      <div class="scout-row">${scout('happy', 72)}<p class="say">${esc('These are short. Pick any one, or go straight to the checkup.')}</p></div>
    </div>
  </section>
  ${skipBar(scan)}`;
}
