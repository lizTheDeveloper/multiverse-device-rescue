import { esc } from '../escape.js';
import { lessonText, skipBar, cityBanner, trainingHud } from './training.js';

export function renderLesson({ lesson: l, qIndex, picked, scan, scout, pendingCity }) {
  const i = Math.max(0, Math.min(qIndex, l.questions.length - 1));
  const q = l.questions[i];
  const last = i >= l.questions.length - 1;
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
  return `
  ${trainingHud({ lessons: {} }, [])}
  ${pendingCity ? cityBanner() : ''}
  <section class="quiz lesson-screen">
    <div class="crumbs"><button type="button" data-go="training">Training Grounds</button> / <b>${esc(l.title)}</b> · QUESTION ${i + 1} OF ${l.questions.length}</div>
    ${i === 0 ? `<div class="panel"><div class="label">WHAT TO KNOW</div><p class="intel">${lessonText(l.briefing)}</p></div>` : ''}
    ${message}
    <p class="q">${lessonText(q.prompt)}</p>
    <div class="options">${options}</div>
    ${after}
    <div class="scout-row">${scout(answer && answer.correct ? 'happy' : 'thinkingA', 54)}</div>
  </section>
  ${skipBar(scan)}`;
}
