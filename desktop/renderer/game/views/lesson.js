import { esc } from '../escape.js';
import { lessonText, skipBar, cityBanner, trainingHud } from './training.js';

// `settingFor(key)` gives { key, hint } for a question's `setting` on a Mac, else null.
// `routerHtml()` gives the router button's HTML (after a scan), else ''; questions marked `router` show it.
// `items`: this visit's items from the item bank (each with prompt, options,
// teach, setting, message); without it, the lesson's own questions.
// `showTeach`: whether this item's "what to know" shows (it hides once the
// person has got one item in its family right).
// Feedback says first whether the answer was right, in words, not only a colour.
const SAYS_ALREADY = /^\s*(?:right|correct|yes|exactly|not quite|nope|no\b)/i;
export function verdict(answer) {
  if (!answer || SAYS_ALREADY.test(String(answer.feedback || ''))) return '';
  return `<b>${answer.correct ? 'Right.' : 'Not quite.'}</b> `;
}

export function renderLesson({ lesson: l, items = null, qIndex, picked, showTeach = true, scan, scout, pendingCity, scanFinished = false, settingFor = () => null, routerHtml = () => '' }) {
  const list = Array.isArray(items) && items.length ? items : l.questions;
  const i = Math.max(0, Math.min(qIndex, list.length - 1));
  const q = list[i];
  const last = i >= list.length - 1;
  // The lesson's intro opens question 1; each question's own `teach` sits right above it.
  const know = [i === 0 && l.briefing, showTeach && q.teach].filter(Boolean);
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
    <div class="feedback" role="status">${verdict(answer)}${lessonText(answer.feedback)}</div>
    ${last
      ? `<p class="intel"><strong>In the checkup:</strong> ${lessonText(l.whatTheScanLooksFor)}</p>
         <button type="button" class="btn-p" data-act="finish-lesson">FINISH LESSON</button>`
      : '<button type="button" class="btn-p" data-act="next-question">NEXT QUESTION</button>'}` : '';
  return `
  ${trainingHud({ lessons: {} }, [])}
  ${pendingCity ? cityBanner() : ''}
  <section class="quiz lesson-screen">
    <div class="crumbs"><button type="button" data-go="training">Training Grounds</button> / <b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${list.length}</div>
    ${know.length ? `<div class="panel"><div class="label">WHAT TO KNOW</div>${know.map((t) => `<p class="intel">${lessonText(t)}</p>`).join('')}${settingHtml}${routerButton}</div>` : ''}
    ${message}
    <p class="q">${lessonText(q.prompt)}</p>
    <div class="options">${options}</div>
    ${after}
    <div class="scout-row">${scout(answer && answer.correct ? 'happy' : 'thinkingA', 54)}</div>
  </section>
  ${skipBar(scan, scanFinished)}`;
}
