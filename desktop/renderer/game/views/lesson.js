import { esc } from '../escape.js';
import { lessonText, skipBar, cityBanner, trainingHud } from './training.js';

// One question of a lesson, its what-to-know, options and feedback. Shared by
// the lesson screen and the sweep, which shows a lesson inline while the scan
// runs (`inline`: a compact header with a way to put it away, no Scout).
// `settingFor(key)` gives { key, hint } for a question's `setting` on a Mac, else null.
// `routerHtml()` gives the router button's HTML (after a scan), else ''; questions marked `router` show it.
export function lessonQuizHtml({ lesson: l, qIndex, picked, scout, settingFor = () => null, routerHtml = () => '', inline = false }) {
  const i = Math.max(0, Math.min(qIndex, l.questions.length - 1));
  const q = l.questions[i];
  const last = i >= l.questions.length - 1;
  // The lesson's intro opens question 1; each question's own `teach` sits right above it.
  const know = [i === 0 && l.briefing, q.teach].filter(Boolean);
  const setting = q.setting ? settingFor(q.setting) : null;
  const settingHtml = setting ? `
      <button type="button" class="btn-s setting-open" data-act="open-setting:${esc(setting.key)}">OPEN IN SYSTEM SETTINGS ▶</button>
      <p class="setting-hint">${esc(setting.hint)}</p>` : '';
  const routerButton = q.router ? routerHtml() : '';
  const answer = picked != null ? q.options[picked] : null;
  const options = q.options.map((o, n) => {
    const cls = answer ? (o.correct ? ' right' : (n === picked ? ' wrong' : '')) : '';
    return `<button type="button" class="opt${cls}" data-act="answer:${n}" data-k="${String.fromCharCode(65 + n)}"${answer ? ' aria-disabled="true"' : ''}>${lessonText(o.text)}</button>`;
  }).join('');
  const message = q.message ? `
    <div class="message-card"><span class="badge skip">${esc(String(q.message.type || '').toUpperCase())}</span>
      <p class="from">From: ${esc(q.message.from)}</p>
      ${q.message.subject ? `<p><strong>${esc(q.message.subject)}</strong></p>` : ''}
      <p>${esc(q.message.body)}</p></div>` : '';
  const after = answer ? `
    <div class="feedback" role="status">${lessonText(answer.feedback)}</div>
    ${last
      ? `<p class="intel"><strong>In the checkup:</strong> ${lessonText(l.whatTheScanLooksFor)}</p>
         <button type="button" class="btn-p" data-act="finish-lesson">FINISH LESSON</button>`
      : '<button type="button" class="btn-p" data-act="next-question">NEXT QUESTION</button>'}` : '';
  const head = inline
    ? `<div class="crumbs"><b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${l.questions.length}
        <button type="button" class="btn-t" data-act="sweep-close">PUT IT AWAY</button></div>`
    : `<div class="crumbs"><button type="button" data-go="training">Training Grounds</button> / <b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${l.questions.length}</div>`;
  return `
    ${head}
    ${know.length ? `<div class="panel know"><h2 class="label">WHAT TO KNOW</h2>${know.map((t) => `<p class="intel">${lessonText(t)}</p>`).join('')}${settingHtml}${routerButton}</div>` : ''}
    ${message}
    <h2 class="q">${lessonText(q.prompt)}</h2>
    <div class="options">${options}</div>
    ${after}
    ${inline ? '' : `<div class="scout-row">${scout(answer && answer.correct ? 'happy' : 'thinkingA', 54)}</div>`}`;
}

export function renderLesson({ lesson, qIndex, picked, scan, scout, pendingCity, scanFinished = false, settingFor = () => null, routerHtml = () => '' }) {
  return `
  ${trainingHud({ lessons: {} }, [])}
  ${pendingCity ? cityBanner() : ''}
  <section class="quiz lesson-screen">
    ${lessonQuizHtml({ lesson, qIndex, picked, scout, settingFor, routerHtml })}
  </section>
  ${skipBar(scan, scanFinished)}`;
}
