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
// `scanFinished`: this worry's checkup already finished, so it would run again.
export function skipBar(scan, scanFinished = false) {
  if (scan && scan.running) {
    return `<div class="skip-bar"><span>Your checkup is running: ${esc(scan.index)} of ${esc(scan.total || '…')} checks.</span>
      <button type="button" class="btn-s lime" data-go="boss">BACK TO THE CHECKUP ▶</button></div>`;
  }
  const label = scan && scan.error ? 'START THE CHECKUP ▶'
    : scanFinished ? 'RUN THE CHECKUP AGAIN ▶' : 'SKIP TO THE CHECKUP ▶';
  return `<div class="skip-bar"><span>You don’t need to finish any lessons first.</span>
    <button type="button" class="btn-s quiet" data-act="start-checkup">${label}</button></div>`;
}

export function trainingHud(progress, lessons) {
  const done = lessons.filter((l) => lessonDone(progress, l.id)).length;
  return `<header class="hud"><span class="hud-title">THE TRAINING GROUNDS</span>
    ${lessons.length ? `<span class="stat lime"><b>${done}/${lessons.length}</b> <small>LESSONS</small></span>` : ''}
    <span class="switch"><button type="button" data-act="leave">PLAIN VIEW</button></span></header>`;
}

// `next`: the one lesson to start first; it gets the strongest styling.
function lessonItem(l, progress, next = false) {
  const n = l.questions.length;
  const done = lessonDone(progress, l.id);
  return `<li><button type="button" class="lesson${done ? ' done' : ''}${next ? ' next' : ''}" data-go="lesson:${esc(l.id)}">
    <b>${esc(l.title)}</b><small>${n} question${n === 1 ? '' : 's'}</small>
    ${done ? '<span class="badge cyan">DONE</span>' : ''}<span class="go" aria-hidden="true">${done ? 'AGAIN' : 'START'} ▶</span></button></li>`;
}

// `lessonsLoaded`: false while the lesson files are still loading, so an empty
// list isn't yet a failure.
export function renderTraining({ ordered, progress, worryTitle, scan, scout, pendingCity, lessonsLoaded = false, scanFinished = false }) {
  const all = [...ordered.recommended, ...ordered.other];
  const nextLesson = ordered.recommended.find((l) => !lessonDone(progress, l.id)) || all.find((l) => !lessonDone(progress, l.id));
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
      ${ordered.recommended.length ? `<span class="label">${head}</span><ul>${ordered.recommended.map((l) => lessonItem(l, progress, l === nextLesson)).join('')}</ul>` : ''}
      ${ordered.other.length ? `<span class="label faint">ALSO HERE</span><ul>${ordered.other.map((l) => lessonItem(l, progress, l === nextLesson)).join('')}</ul>` : ''}
      ${all.length ? '' : lessonsLoaded
    ? '<p class="intel">The lessons couldn’t load. The checkup still works.</p>'
    : '<p class="intel">Getting the lessons ready.</p>'}
    </div>
    <div class="quiz">
      <div class="scout-row">${scout('happy', 72)}<p class="say">${esc('These are short. Pick any one, or go straight to the checkup.')}</p></div>
      <button type="button" class="btn-s lime" data-go="range">DRILL RANGE ▶</button>
      <p class="intel">Practice sorting made-up signals. Nothing in the range touches your computer.</p>
    </div>
  </section>
  ${skipBar(scan, scanFinished)}`;
}
