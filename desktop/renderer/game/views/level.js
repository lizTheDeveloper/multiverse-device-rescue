// The detail level's own pieces: the three first-run cards, and (technical)
// a finding's evidence and check-it-yourself commands. Pure. Every string from the engine is escaped.
import { esc } from '../escape.js';
import { LEVEL_CHOICES, evidenceRows, checkCommands, COMMANDS_NOTE } from '../level.js';

// The one-time ask, on the Training Grounds until a card is picked. After
// that the level is in SETTINGS (display-panel.js), with text and motion.
export function renderLevelPicker() {
  const cards = LEVEL_CHOICES.map((c) => `
      <button type="button" class="level-card" data-act="level:${esc(c.id)}">
        <b>${esc(c.title)}</b><small>${esc(c.line)}</small></button>`).join('');
  return `
  <section class="panel level-pick first" aria-label="How much detail">
    <div class="row"><span class="label">HOW MUCH DETAIL DO YOU WANT?</span></div>
    <div class="level-cards">${cards}</div>
    <p class="intel faint">Pick whichever fits. You can change it any time under SETTINGS at the top.</p>
  </section>`;
}

// EVIDENCE and CHECK IT YOURSELF, for the technical level. '' when the finding
// has neither. `clues`: the finding's clues (clues.js), whose commands are reused.
export function evidenceHtml(finding, platform, clues = []) {
  const rows = evidenceRows(finding);
  const cmds = checkCommands(finding, platform, clues);
  if (!rows.length && !cmds.length) return '';
  const table = rows.length ? `<dl class="ev-table">${rows.map(([k, v]) => `<dt>${esc(k)}</dt><dd>${esc(v)}</dd>`).join('')}</dl>` : '';
  const checks = cmds.length ? `<div class="label">CHECK IT YOURSELF</div>
      <ul class="cmds">${cmds.map((c) => `<li><code>${esc(c.cmd)}</code><small>${esc(c.what)}</small></li>`).join('')}</ul>
      <p class="intel faint">${esc(COMMANDS_NOTE)}</p>` : '';
  return `<div class="panel evidence-panel"><div class="label">EVIDENCE</div>${table}${checks}</div>`;
}
