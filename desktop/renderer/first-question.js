'use strict';

/*
 * The one question asked after the worry screen, and the follow-up asked
 * once a session when a scan turns up software that can be used to watch a
 * computer. Each answer picks the display preference (DisplayMode): 'city'
 * or 'standard'. The answer itself is never stored, only the preference.
 *
 * Loaded as a plain script (global `FirstQuestion`); tested from Node.
 */
const FirstQuestion = (function () {
  const FIRST = {
    kind: 'first',
    title: 'One more question',
    text: 'Is there someone in your life you’re worried might be watching your devices — a partner, an ex, a family member, someone you live with?',
    note: 'Your answer only changes what this app shows you. You can change it with “Something changed?” on the worry screen.',
    answers: [
      { id: 'no', label: 'No', mode: 'standard' },
      { id: 'yes', label: 'Yes, that’s part of it', mode: 'city' },
      { id: 'rather-not', label: 'I’d rather not say', mode: 'standard' },
    ],
  };
  const RECHECK = {
    kind: 'recheck',
    title: 'Before you go on',
    text: 'We found something that can be used to watch a computer. Is that something you know about?',
    note: 'Nothing has been changed or removed.',
    answers: [
      { id: 'known', label: 'Yes, I know about it', mode: 'standard' },
      { id: 'unknown', label: 'No, I don’t', mode: 'city' },
      { id: 'rather-not', label: 'I’d rather not say', mode: 'standard' },
    ],
  };
  const QUESTIONS = { first: FIRST, recheck: RECHECK };

  // "I think someone is watching me" goes straight to 'city' without asking.
  const STRAIGHT_TO_CITY = 'watched';

  function modeFor(kind, answerId) {
    const q = QUESTIONS[kind];
    const a = q && q.answers.find((x) => x.id === answerId);
    return a ? a.mode : null;
  }

  // After a worry is picked: the mode to use now, or 'ask' for the question first.
  function afterWorry(situation, mode) {
    if (situation && situation.id === STRAIGHT_TO_CITY) return 'city';
    return mode === 'city' || mode === 'standard' ? mode : 'ask';
  }

  // Monitoring software turned up: ask once a session, and never in 'city',
  // which already keeps it out of reach. `asked` lives in memory only.
  function recheckDue({ mode, monitoringSeen, asked }) {
    return mode !== 'city' && !!monitoringSeen && !asked;
  }

  function questionHtml(kind, esc) {
    const q = QUESTIONS[kind];
    if (!q) return '';
    return `<h1 id="question-title">${esc(q.title)}</h1>
      <p class="lede">${esc(q.text)}</p>
      <ul class="question-answers">${q.answers.map((a) => `
        <li><button type="button" class="btn btn--secondary question-answer" data-answer="${esc(a.id)}">${esc(a.label)}</button></li>`).join('')}
      </ul>
      <p class="muted">${esc(q.note)}</p>`;
  }

  return { QUESTIONS, STRAIGHT_TO_CITY, modeFor, afterWorry, recheckDue, questionHtml };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = FirstQuestion;
}
