// The deck's right-hand instruments for new and everyday: the incident report
// at a glance. Every number moves when the person does something, and none
// of them is a fear number. Pure; every graph has its words beside it.
//
// - CASES CLOSED: cases sorted or fixed, out of every case (case-file.js
//   caseReport). It moves with each verdict, so every click shows up here.
// - RANK: XP and how much to the next rank (ledger rankOf), the near goal.
// - THIS SESSION: calls made after reading the clues, and the longest run of
//   them in a row. A call made without looking ends the run: the run
//   rewards looking, never speed. Memory only.
// Technical keeps the denser instruments (views/instruments.js).
import { esc } from '../escape.js';

const pct = (n, of) => (of > 0 ? Math.max(0, Math.min(100, Math.round((n / of) * 100))) : 0);
const plural = (n, one, many) => `${n} ${n === 1 ? one : many}`;

// The incident report's one line, for the top of the queue. Zeros are left out.
export function reportLine(r) {
  const parts = [
    r.unidentified ? plural(r.unidentified, 'lead to identify', 'leads to identify') : '',
    r.investigating ? `${r.investigating} looking closer` : '',
    r.doorsOpen ? plural(r.doorsOpen, 'open door', 'open doors') : '',
    r.threats ? plural(r.threats, 'threat to deal with', 'threats to deal with') : '',
    r.blind ? plural(r.blind, 'blind spot', 'blind spots') : '',
    r.identified ? `${r.identified} identified` : '',
  ].filter(Boolean);
  return parts.length ? parts.join(' · ') : 'No open cases.';
}

export function reportHtml(r) {
  return `<p class="case-report" aria-label="Incident report">${esc(reportLine(r))}</p>`;
}

// `integrity`: signals.js cityIntegrity's percent (districts with nothing open), or null.
export function renderScoreboard({ report, rank, session = { sorted: 0, run: 0, best: 0 }, confirmed = 0, reported = 0, integrity = null }) {
  const r = report || { open: 0, closed: 0 };
  const total = r.open + r.closed;
  const closedPct = pct(r.closed, total);
  const toward = rank.next ? pct(rank.points - rank.min, rank.next.min - rank.min) : 100;
  const next = rank.next ? `${rank.toNext} XP to ${rank.next.name}` : 'Top rank';
  const fixes = confirmed || reported
    ? `<p class="sb-small">${[confirmed ? `<b>${esc(confirmed)}</b> <small>CONFIRMED</small>` : '', reported ? `<b>${esc(reported)}</b> <small>YOU REPORTED</small>` : ''].filter(Boolean).join(' · ')}</p>` : '';
  const city = integrity == null ? '' : `<p class="sb-small">Districts secured <b>${esc(integrity)}%</b></p>`;
  return `
  <section class="panel instruments scoreboard" aria-label="Your progress">
    <h2 class="label">CASES CLOSED</h2>
    <p class="sb-big"><b>${esc(r.closed)}</b><small> / ${esc(total)}</small></p>
    <div class="bar sb-bar" role="progressbar" aria-label="Cases closed" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${closedPct}"><i style="--pct: ${closedPct}%"></i></div>
    ${fixes}${city}
    <h2 class="label">RANK</h2>
    <p class="rank-name"><b>${esc(rank.name)}</b> <small>${esc(rank.points)} XP</small></p>
    <div class="bar" role="progressbar" aria-label="Rank progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${toward}"><i style="--pct: ${toward}%"></i></div>
    <p class="sb-small">${esc(next)}</p>
    <h2 class="label">THIS SESSION</h2>
    <p class="sb-session"><b>${esc(session.sorted)}</b> <small>sorted after looking</small>${session.best > 1 ? ` · <b>${esc(session.best)}</b> <small>in a row</small>` : ''}</p>
  </section>`;
}

// The recap after a sweep: what it did, what the person did, in one line.
export function recapText({ checks = 0, cases = 0, sortedOnSweep = 0, lessons = 0 }) {
  return [
    `${checks} checks`,
    plural(cases, 'case to look at', 'cases to look at'),
    sortedOnSweep ? `${sortedOnSweep} sorted while it ran` : '',
    lessons ? plural(lessons, 'lesson done', 'lessons done') : '',
  ].filter(Boolean).join(' · ');
}
