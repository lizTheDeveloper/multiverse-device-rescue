// The deck's instruments: city integrity, its sparkline, the three bars and
// rank progress. Pure. Every graph has a text equivalent; the sparkline itself
// is hidden from screen readers because the sentence says the same thing.
// On a first sweep the sentence only repeats the big number, so only screen
// readers get it.
import { esc } from '../escape.js';

const pct = (n) => Math.max(0, Math.min(100, Math.round(Number(n) || 0)));

export function integrityText(current, previous) {
  if (current == null) return 'City integrity: no reading. Nothing could be checked, and fog never counts as secure.';
  if (previous == null) return `City integrity ${current}%.`;
  if (current > previous) return `City integrity ${current}%, up from ${previous}% last sweep.`;
  if (current < previous) return `City integrity ${current}%, down from ${previous}% last sweep.`;
  return `City integrity ${current}%, the same as last sweep.`;
}

// The last ten sweeps. A sweep that checked nothing (null) is a gap, not a zero.
export function sparklineSvg(values) {
  const vs = (values || []).slice(-10);
  const pts = vs.map((v, i) => (typeof v === 'number' ? [i, v] : null)).filter(Boolean);
  if (pts.length < 2) return '';
  const step = vs.length > 1 ? 100 / (vs.length - 1) : 0;
  const points = pts.map(([i, v]) => `${(i * step).toFixed(1)},${(29 - pct(v) * 0.28).toFixed(1)}`).join(' ');
  return `<svg class="spark" viewBox="0 0 100 30" preserveAspectRatio="none" aria-hidden="true" focusable="false"><polyline points="${points}" fill="none" stroke="currentColor" stroke-width="2" vector-effect="non-scaling-stroke"/></svg>`;
}

function bar(n, max, label, tone) {
  const value = Number(n) || 0;
  const w = max > 0 ? pct((value / max) * 100) : 0;
  return `<div class="ibar ${tone}"><span class="ibar-n"><b>${value}</b> <small>${label}</small></span><span class="ibar-track" aria-hidden="true"><i style="--pct: ${w}%"></i></span></div>`;
}

export function renderInstruments({ integrity, previous, history, bars, rank }) {
  const b = bars || {};
  const max = Math.max(1, Number(b.sorted) || 0, Number(b.confirmed) || 0, Number(b.reported) || 0);
  const toward = rank.next ? pct(((rank.points - rank.min) / (rank.next.min - rank.min)) * 100) : 100;
  const next = rank.next ? `${rank.toNext} points to ${rank.next.name}.` : 'Top rank.';
  return `
  <section class="panel instruments">
    <div class="label">CITY INTEGRITY</div>
    <p class="integrity" aria-hidden="true"><b>${integrity == null ? '—' : `${esc(integrity)}%`}</b></p>
    ${sparklineSvg(history)}
    <p class="intel${integrity != null && previous == null ? ' sr-only' : ''}">${esc(integrityText(integrity, previous))}</p>
    <div class="label">SIGNALS</div>
    ${bar(b.sorted, max, 'SORTED', 'cyan')}${bar(b.confirmed, max, 'CONFIRMED', 'lime')}${bar(b.reported, max, 'YOU REPORTED', 'amb')}
    <p class="intel">Confirmed means Reclaim City checked again and it’s gone. You reported is your word for it. They’re counted apart.</p>
    <div class="label">RANK</div>
    <p class="rank-name"><b>${esc(rank.name)}</b> <small>${esc(rank.points)} POINTS</small></p>
    <div class="bar" role="progressbar" aria-label="Rank progress" aria-valuemin="0" aria-valuemax="100" aria-valuenow="${toward}"><i style="--pct: ${toward}%"></i></div>
    <p class="intel">${esc(next)}</p>
  </section>`;
}
