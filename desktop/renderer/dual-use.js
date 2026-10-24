'use strict';

/*
 * Workplace and parental monitoring tools (stalkerware_scan's
 * employee_monitoring and parental_control findings). Standard mode's list
 * asks one question per category, on that category's first card, and the
 * answer frames every finding of the category in this checkup.
 *
 * The deciding fact is who sees what the program records, not why it was
 * installed: monitoring often starts with a reason that sounded fair (a child
 * uses the device; it's "for work"). So only "Only me" (parental) and "My
 * employer's" (work) say "most likely"; every other answer, "Not sure"
 * included, is the monitoring path. No answer clears a finding: the severity,
 * the removal warning line and the card's own text stay as the engine wrote
 * them, and these checks are never markable.
 *
 * Answers live in app.js's memory for one checkup: never stored, exported or
 * sent with "Copy for any AI" or "Ask about this". City mode never asks (these
 * findings are held in the help district there).
 *
 * Plain words only, none of QuietNotes' MARKERS, so standard mode shows them.
 * Loaded as a plain script (global `DualUse`); tested from Node.
 */
const DualUse = (function () {
  const MODULE = 'stalkerware_scan';
  const QUESTIONS = {
    parental_control: {
      ask: 'Who gets this program’s reports?',
      options: [{ id: 'me', label: 'Only me' }, { id: 'someone', label: 'Someone else' }, { id: 'notsure', label: 'Not sure' }],
      likely: 'me',
    },
    employee_monitoring: {
      ask: 'Whose computer is this?',
      options: [{ id: 'employer', label: 'My employer’s' }, { id: 'mine', label: 'Mine' }, { id: 'notsure', label: 'Not sure' }],
      likely: 'employer',
    },
  };
  const LIKELY = {
    parental_control: 'Most likely the parental controls you set up.',
    employee_monitoring: 'Most likely your employer’s own monitoring, on its own computer.',
  };
  const WATCHED = 'Treat it as monitoring someone may have put here without asking. Don’t remove it yet; write down what was found and when.';
  const WATCHED_MORE = {
    parental_control: 'Sometimes monitoring starts with a reason that sounded fair, like a child using the device. What matters is who sees what it records.',
    employee_monitoring: 'Work software on your own computer is worth asking about: what it records, when, and who sees it. The rules depend on where you live; a workers’ rights group or legal aid can tell you what’s allowed.',
  };
  const CHANGE = 'Change my answer';

  const has = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

  // The category this finding is asked about, else null.
  function categoryOf(f) {
    if (!f || typeof f !== 'object') return null;
    const seen = Array.isArray(f.seen_in) ? f.seen_in : [];
    if (f.module !== MODULE && !seen.includes(MODULE)) return null;
    const c = f.data && typeof f.data === 'object' ? f.data.stalkerware_category : null;
    return typeof c === 'string' && has(QUESTIONS, c) ? c : null;
  }

  const isOption = (cat, id) => has(QUESTIONS, cat) && QUESTIONS[cat].options.some((o) => o.id === id);

  // What an answer says: { path: 'likely' | 'watched', lines } or null (no answer).
  function framing(cat, answer) {
    if (!isOption(cat, answer)) return null;
    if (answer === QUESTIONS[cat].likely) return { path: 'likely', lines: [LIKELY[cat]] };
    return { path: 'watched', lines: [WATCHED, WATCHED_MORE[cat]] };
  }

  // A new answers object: `id` null clears the category; anything else unknown changes nothing.
  function setAnswer(answers, cat, id) {
    const out = { ...(answers || {}) };
    if (!has(QUESTIONS, cat)) return out;
    if (id == null) { delete out[cat]; return out; }
    if (isOption(cat, id)) out[cat] = id;
    return out;
  }

  // The card's block: the framing once answered, else the question (only
  // when `opts.ask`: the category's first card). '' in city mode.
  function blockHtml(mode, finding, answers, opts, esc) {
    if (mode === 'city') return '';
    const cat = categoryOf(finding);
    if (!cat) return '';
    const a = answers && has(answers, cat) ? answers[cat] : null;
    const fr = framing(cat, a);
    if (fr) {
      return `<div class="finding-card__dual-use finding-card__dual-use--${fr.path}" role="note">`
        + fr.lines.map((l) => `<p>${esc(l)}</p>`).join('')
        + (opts && opts.ask ? `<p><button type="button" class="link-button" data-dual-use-undo="${esc(cat)}">${esc(CHANGE)}</button></p>` : '')
        + '</div>';
    }
    if (!opts || !opts.ask) return '';
    const q = QUESTIONS[cat];
    return `<div class="finding-card__dual-use finding-card__dual-use--ask"><p><strong>${esc(q.ask)}</strong></p><p>`
      + q.options.map((o) => `<button type="button" class="btn btn--secondary btn--small" data-dual-use="${esc(`${cat}:${o.id}`)}">${esc(o.label)}</button>`).join(' ')
      + '</p></div>';
  }

  // "parental_control:me" -> ['parental_control', 'me'], else null.
  function parse(value) {
    const m = /^([a-z_]+):([a-z]+)$/.exec(String(value || ''));
    return m && isOption(m[1], m[2]) ? [m[1], m[2]] : null;
  }

  return { MODULE, QUESTIONS, LIKELY, WATCHED, WATCHED_MORE, CHANGE, categoryOf, framing, setAnswer, blockHtml, parse };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = DualUse;
}
