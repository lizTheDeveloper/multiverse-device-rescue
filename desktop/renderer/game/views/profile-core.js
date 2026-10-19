// The profile screen: YOUR FILE in game style, "Your progress" in plain view.
// Same content, two sets of words. Pure: takes PlayerProfile.summary(…) and
// returns HTML. Counts only for the city: never a finding's name.
import { esc } from '../escape.js';
import { PUBLISH_FIELDS, STAYS_HERE, lessonsLearned } from '../profile/publish.js';
import { isHidden } from '../profile/skills.js';

const WORDS = {
  game: {
    title: 'YOUR FILE', rank: 'RANK', training: 'TRAINING', skills: 'SKILLS', drills: 'DRILLS', city: 'CITY',
    history: 'DATA HISTORY', startOver: 'START OVER', publish: 'ADD TO MY SCHOOL PROFILE', back: 'BACK TO THE DECK',
    stamp: { learned: 'LEARNED', measuring: 'IN PROGRESS', skipped: 'SKIPPED — YOU SAID YOU KNOW THIS', 'worth-a-look': 'SKIPPED — A REFRESHER MAY HELP', refresher: 'REFRESHER', 'not-yet': 'NOT YET' },
    depth: { 'not-yet': 'NOT YET', introduced: 'INTRODUCED', practiced: 'PRACTICED' },
  },
  plain: {
    title: 'Your progress', rank: 'Points', training: 'Lessons', skills: 'Skills', drills: 'Practice drills', city: 'Your checkups',
    history: 'Data history', startOver: 'Start over', publish: 'Add to my school profile', back: 'Close',
    stamp: { learned: 'Learned', measuring: 'In progress', skipped: 'Skipped — you said you know this', 'worth-a-look': 'Skipped — a refresher may help', refresher: 'Worth a refresher', 'not-yet': 'Not started' },
    depth: { 'not-yet': 'Not yet', introduced: 'Introduced', practiced: 'Practiced' },
  },
};
const STEP = { 'not-yet': 1, introduced: 2, practiced: 3 };

// A lesson as the app shows it: judged on its shown concepts only, the same
// rule publish.js uses for the total, so the headline matches what would be
// published. A lesson with no shown concept is left out.
const ORDER = ['learned', 'refresher', 'worth-a-look', 'skipped', 'measuring', 'not-yet'];
function shownLesson(l) {
  const states = (Array.isArray(l && l.concepts) ? l.concepts : []).filter((c) => c && !isHidden(c.id)).map((c) => c.state);
  if (!states.length) return null;
  let state = 'not-yet';
  if (states.every((x) => x === 'learned')) state = 'learned';
  else if (states.includes('refresher')) state = 'refresher';
  else if (states.includes('worth-a-look')) state = 'worth-a-look';
  else if (states.every((x) => x === 'learned' || x === 'skipped')) state = 'skipped';
  else if (states.some((x) => x !== 'not-yet')) state = 'measuring';
  return { ...l, state: ORDER.includes(state) ? state : 'not-yet' };
}

function lessonNote(l, theme) {
  if (l.state === 'measuring') return 'A few more questions will show whether it’s learned.';
  if (l.state === 'worth-a-look') return 'A drill suggests a refresher.';
  if (l.state === 'refresher') return 'Some recent answers missed, so a refresher could help.';
  if (l.state === 'skipped') return theme === 'game' ? 'Not counted as learned until you take it.' : 'Not counted as learned yet.';
  return '';
}

// Game rows get the button that opens the lesson; plain view has no lesson host yet.
function lessonAction(l, theme) {
  if (theme !== 'game') return '';
  const label = { learned: 'REVIEW ONE', measuring: 'CONTINUE', skipped: 'TAKE THE LESSON', 'worth-a-look': '2 QUESTIONS', refresher: '2 QUESTIONS', 'not-yet': 'START' }[l.state] || 'START';
  return `<button type="button" class="btn-s" data-go="lesson:${esc(l.id)}" aria-label="${esc(label.toLowerCase())}: ${esc(l.title)}">${esc(label)} ▶</button>`;
}

function rankHtml(s, w, theme) {
  const r = s.rank;
  if (theme === 'game') {
    return `<p class="rank-name"><b>${esc(r.name)}</b> <small>${esc(r.points)} POINTS</small></p>
      <p class="intel">${r.next ? `${esc(r.toNext)} to ${esc(r.next)}.` : 'Top rank.'} Rank never drops.</p>`;
  }
  return `<p>${esc(w.rank)}: ${esc(r.points)} (level ${esc(r.level)} of ${esc(r.of)})</p>`;
}

function drillsHtml(d) {
  if (!d.tried) return '<p>No practice drills yet.</p>';
  const lines = [`<p>${esc(d.right)} of ${esc(d.tried)} right${d.lastTen.of ? ` · last ${esc(d.lastTen.of)}: ${esc(d.lastTen.right)} right` : ''}</p>`];
  if (d.total >= 3 && d.over >= 2 && d.over > d.under) lines.push(`<p>You flag things as threats more often than they are (${esc(d.over)} times).</p>`);
  else if (d.total >= 3 && d.under >= 2 && d.under >= d.over) lines.push(`<p>A few threats got past you as “mine” (${esc(d.under)}).</p>`);
  if (!d.total) lines.push('<p>Which way your calls lean is counted from now on.</p>');
  return lines.join('');
}

function historyHtml(s, w) {
  const rows = (s.migrations || []).map((m) => `<li>Moved to this version${m.from ? ` from version ${esc(m.from)}` : ''}: ${esc((m.changes || []).join('; '))}</li>`).join('');
  return `<details><summary>${esc(w.history)}</summary>${rows ? `<ul>${rows}</ul>` : '<p>Nothing has been moved or changed.</p>'}</details>`;
}

export const START_OVER = 'Start over? This clears your lessons, drills, rank and missions here. Nothing on your computer changes.';

// `publish`: whether the "Add to my school profile" control exists (publishOffered).
// `confirming`: the person pressed Start over and is being asked to be sure.
export function createProfileRenderer(ready) {
  return function renderProfile({ summary: s, theme = 'game', publish = false, confirming = false }) {
  const w = WORDS[theme === 'plain' ? 'plain' : 'game'];
  const shown = s.lessons.map(shownLesson).filter(Boolean);
  const lessons = shown.map((l) => `
      <li class="profile-lesson ${esc(l.state)}"><span class="stamp">${esc(w.stamp[l.state] || w.stamp['not-yet'])}</span>
        <b>${esc(l.title)}</b>${lessonNote(l, theme) ? `<small>${esc(lessonNote(l, theme))}</small>` : ''}${lessonAction(l, theme)}</li>`).join('');
  const skills = s.skills.map((k) => `
      <li><b>${esc(k.title)}</b> <span class="meter" aria-hidden="true">${[1, 2, 3].map((i) => `<i class="${i <= STEP[k.depth] ? 'on' : ''}"></i>`).join('')}</span>
        <span>${esc(w.depth[k.depth])} (step ${esc(STEP[k.depth])} of 3)</span></li>`).join('');
  const c = s.city;
  return `
  <section class="profile ${theme === 'plain' ? 'profile-plain' : 'profile-game'}" aria-labelledby="profile-title">
    <h2 id="profile-title" tabindex="-1">${esc(w.title)}</h2>
    <div class="panel"><h3 class="label">${esc(w.rank)}</h3>${rankHtml(s, w, theme)}</div>
    <div class="panel"><h3 class="label">${esc(w.training)}</h3><p>${esc(lessonsLearned(s))} of ${esc(shown.length)} learned</p><ul class="profile-lessons">${lessons}</ul></div>
    <div class="panel"><h3 class="label">${esc(w.skills)}</h3><ul class="profile-skills">${skills}</ul></div>
    <div class="panel"><h3 class="label">${esc(w.drills)}</h3>${drillsHtml(s.drills)}</div>
    <div class="panel"><h3 class="label">${esc(w.city)}</h3>
      <p>${esc(c.reclaimed)} fixed and confirmed · ${esc(c.later)} set aside for later · ${esc(c.yours)} marked as yours${c.lastSweep === null ? '' : ` · last checkup ${esc(c.lastSweep)}% secured`}</p></div>
    ${confirming ? `<div class="panel" role="alertdialog" aria-labelledby="start-over-q"><p id="start-over-q">${esc(START_OVER)}</p>
      <div class="row"><button type="button" class="btn-s" data-act="profile-start-over-yes">${esc(theme === 'plain' ? 'Yes, start over' : 'YES, START OVER')}</button>
        <button type="button" class="btn-t" data-act="profile-start-over-no" data-autofocus>${esc(theme === 'plain' ? 'Keep my progress' : 'KEEP MY PROGRESS')}</button></div></div>` : ''}
    <footer class="row">${historyHtml(s, w)}
      ${publish && ready === true ? `<button type="button" class="btn-s" data-act="profile-publish">${esc(w.publish)}</button>` : ''}
      <button type="button" class="btn-t" data-act="profile-start-over">${esc(w.startOver)}</button>
      <button type="button" class="btn-t" data-act="profile-close">${esc(w.back)}</button></footer>
  </section>`;
  };
}

// TEST SEAM: production code imports views/profile.js, which binds `ready` to
// PUBLISH_READY. A source-scan test fails if anything else names the creators.

// Where focus goes when the screen opens: the heading (or the question, when
// asking whether to start over). `root`: the element holding the screen.
export function focusProfile(root) {
  if (!root || typeof root.querySelector !== 'function') return null;
  const el = root.querySelector('[data-autofocus]') || root.querySelector('#profile-title');
  if (el && typeof el.focus === 'function') el.focus();
  return el;
}

// Escape closes the sheet or the question; returns the act to run, or null.
export function profileKeyAct(key, { confirming = false, sheet = false } = {}) {
  if (key !== 'Escape') return null;
  if (sheet) return 'publish-close';
  return confirming ? 'profile-start-over-no' : 'profile-close';
}

// The consent sheet. Every box starts unticked; the preview is the exact text
// that would leave. `payload`: buildPayload(…) for the ticked boxes, or null.
// TODO(consent-sheet focus): when the sheet is wired into the controller, move
// focus to #pub-title on open, keep Tab inside the dialog, and return focus to
// the control that opened it on close. Not wired yet, so not done here.
export function createPublishSheet(ready) {
  return function renderPublishSheet({ summary: s, ticked = [], payload = null, theme = 'game' }) {
  if (ready !== true) return '';
  const plain = theme === 'plain';
  const want = new Set(ticked);
  const shown = (f) => (f.id === 'skills'
    ? s.skills.filter((k) => k.depth !== 'not-yet').map((k) => `${k.title}: ${k.depth}`).join(', ') || 'none started yet'
    : String(f.value(s)));
  const boxes = PUBLISH_FIELDS.map((f) => `
      <li><input type="checkbox" id="pub-${esc(f.id)}" data-act="pub-toggle:${esc(f.id)}"${want.has(f.id) ? ' checked' : ''}>
        <label for="pub-${esc(f.id)}">${esc(f.label)}: <b>${esc(shown(f))}</b></label></li>`).join('');
  return `
  <div class="sheet" role="dialog" aria-modal="true" aria-labelledby="pub-title">
    <h2 id="pub-title" tabindex="-1">Add to my school profile</h2>
    <p>Tick what you want to add. Nothing is sent: you save a file or copy the text, and add it in the school’s Profile Viewer yourself.</p>
    <p><strong>${esc(STAYS_HERE)}</strong></p>
    <fieldset><legend>What to add</legend><ul class="pub-fields">${boxes}</ul></fieldset>
    <h3>Exactly what would leave</h3>
    <pre class="pub-preview" aria-live="polite">${payload ? esc(payload) : 'Nothing ticked yet.'}</pre>
    <div class="row">
      <button type="button" class="btn-p" data-act="publish-save"${payload ? '' : ' disabled'}>${plain ? 'Save a file' : 'SAVE A FILE'}</button>
      <button type="button" class="btn-s" data-act="publish-copy"${payload ? '' : ' disabled'}>${plain ? 'Copy' : 'COPY'}</button>
      <button type="button" class="btn-t" data-act="publish-close">${plain ? 'Close' : 'CLOSE'}</button></div>
  </div>`;
  };
}
