import { esc } from '../escape.js';
import { countReclaimed } from '../progress.js';

export function renderHud({ title, city, progress }) {
  const t = (city && city.totals) || { critical: 0, warning: 0, fog: 0 };
  const open = (city.districts || []).reduce((n, d) => n + d.missions.length, 0);
  const done = countReclaimed(progress);
  return `
  <header class="hud">
    <span class="hud-title">${esc(title)}</span>
    <span class="stat mag"><b>${t.critical}</b> <small>CRITICAL</small></span>
    <span class="stat amb"><b>${t.warning}</b> <small>WARNING</small></span>
    <span class="stat lime"><b>${done}</b> <small>RECLAIMED</small></span>
    ${open ? `<span class="stat grey"><b>${open}</b> <small>TO DO</small></span>` : ''}
    ${t.fog ? `<span class="stat grey"><b>${t.fog}</b> <small>COULDN’T CHECK</small></span>` : ''}
    <span class="switch"><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
  </header>`;
}
