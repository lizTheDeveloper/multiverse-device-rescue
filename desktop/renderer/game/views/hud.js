import { esc } from '../escape.js';
import { countReclaimed } from '../progress.js';

// With `counts` the HUD shows the two kinds of progress apart: what the computer
// confirmed and what the person reported. Without it, Plan A's RECLAIMED.
// It tops the screens inside the city (a district, a briefing), so CITY is a
// button back to the command center, not just a label.
// `levelHtml`: the DETAIL button (views/level.js levelButton), or ''.
export function renderHud({ title, city, progress, counts, levelHtml = '' }) {
  const t = (city && city.totals) || { critical: 0, warning: 0, fog: 0 };
  // Marked as yours isn't to do: it's in YOURS.
  const open = (city.districts || []).reduce((n, d) => n + d.missions.filter((m) => !m.marked).length, 0);
  const done = countReclaimed(progress);
  return `
  <header class="hud">
    <span class="hud-title">${esc(title)}</span>
    <span class="stat mag"><b>${t.critical}</b> <small>CRITICAL</small></span>
    <span class="stat amb"><b>${t.warning}</b> <small>WARNING</small></span>
    ${counts
      ? `<span class="stat lime"><b>${Number(counts.confirmed) || 0}</b> <small>CONFIRMED</small></span>
    <span class="stat cyan"><b>${Number(counts.reported) || 0}</b> <small>YOU REPORTED</small></span>`
      : `<span class="stat lime"><b>${done}</b> <small>RECLAIMED</small></span>`}
    ${open ? `<span class="stat grey"><b>${open}</b> <small>TO DO</small></span>` : ''}
    ${t.fog ? `<span class="stat grey"><b>${t.fog}</b> <small>COULDN’T CHECK</small></span>` : ''}
    <span class="switch">${levelHtml}<button type="button" data-go="training">TRAINING</button><button type="button" data-act="list">LIST</button><button type="button" class="on" data-go="city" aria-label="Back to the city">CITY</button></span>
  </header>`;
}
