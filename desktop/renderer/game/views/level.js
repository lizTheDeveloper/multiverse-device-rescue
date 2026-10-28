// The detail level's own pieces: the three cards, the HUD button that opens
// them again, and (technical) a finding's evidence and check-it-yourself
// commands. Pure. Every string from the engine is escaped.
import { esc } from '../escape.js';
import { LEVEL_CHOICES, DEFAULT_LEVEL, evidenceRows, checkCommands, COMMANDS_NOTE } from '../level.js';

const SHORT = { new: 'NEW', everyday: 'EVERYDAY', technical: 'TECHNICAL' };

// `chosen`: the stored level, or null (never asked). `first`: the one-time ask,
// which says it can be changed later; otherwise it's the settings panel.
export function renderLevelPicker({ chosen = null, first = false }) {
  const cards = LEVEL_CHOICES.map((c) => `
      <button type="button" class="level-card${chosen === c.id ? ' on' : ''}" data-act="level:${esc(c.id)}"${chosen === c.id ? ' aria-pressed="true"' : ''}>
        <b>${esc(c.title)}</b><small>${esc(c.line)}</small></button>`).join('');
  const head = first ? 'HOW MUCH DETAIL DO YOU WANT?' : 'DETAIL LEVEL';
  const foot = first ? 'Pick whichever fits. You can change it any time with DETAIL at the top.'
    : 'This changes how much is shown, not what is checked. Every fix still asks first.';
  return `
  <section class="panel level-pick${first ? ' first' : ''}" aria-label="How much detail">
    <div class="row"><span class="label">${head}</span>${first ? '' : '<button type="button" class="btn-t" data-act="level-close">CLOSE</button>'}</div>
    <div class="level-cards">${cards}</div>
    <p class="intel faint">${esc(foot)}</p>
  </section>`;
}

// For a HUD's .switch: opens the picker.
export function levelButton(level) {
  return `<button type="button" data-act="level-open" aria-label="Detail level: ${esc(SHORT[level] || SHORT[DEFAULT_LEVEL])}. Change it.">DETAIL: ${esc(SHORT[level] || SHORT[DEFAULT_LEVEL])}</button>`;
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
