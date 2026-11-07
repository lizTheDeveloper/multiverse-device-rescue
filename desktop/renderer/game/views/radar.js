// YOUR COMPUTER'S RADAR, in YOURS: what the things the person identified as
// theirs are for (own-categories.js radarOf), as a spider chart. The SVG is
// a picture of the table beside it, which is what screen readers get. Pure.
import { esc } from '../escape.js';
import { RADAR_AXES } from '../own-categories.js';

const R = 80;
const C = 110;
const point = (i, n, r) => {
  const a = (Math.PI * 2 * i) / n - Math.PI / 2;
  return [C + r * Math.cos(a), C + r * Math.sin(a)];
};
const pts = (list) => list.map(([x, y]) => `${x.toFixed(1)},${y.toFixed(1)}`).join(' ');

// `counts`: radarOf(deck). `running`: optional { [category]: n } of those running now.
export function renderRadar({ counts = {}, running = null }) {
  const axes = RADAR_AXES;
  const n = axes.length;
  const values = axes.map((a) => Number(counts[a.id]) || 0);
  const total = values.reduce((s, v) => s + v, 0) + (Number(counts.other) || 0);
  if (!total) {
    return `<section class="panel radar" aria-labelledby="radar-title"><h2 class="label" id="radar-title">YOUR COMPUTER’S RADAR</h2>
      <p class="intel">When you call something MINE and say what it’s for, it shows up here, so you can see what your computer is used for.</p></section>`;
  }
  const max = Math.max(1, ...values);
  const rings = [0.25, 0.5, 0.75, 1].map((f) => `<polygon class="r-ring" points="${pts(axes.map((_, i) => point(i, n, R * f)))}"/>`).join('');
  const spokes = axes.map((_, i) => { const [x, y] = point(i, n, R); return `<line class="r-spoke" x1="${C}" y1="${C}" x2="${x.toFixed(1)}" y2="${y.toFixed(1)}"/>`; }).join('');
  const shape = `<polygon class="r-shape" points="${pts(values.map((v, i) => point(i, n, R * (v / max))))}"/>`;
  const labels = axes.map((a, i) => {
    const [x, y] = point(i, n, R + 18);
    const anchor = Math.abs(x - C) < 4 ? 'middle' : x > C ? 'start' : 'end';
    return `<text class="r-label" x="${x.toFixed(1)}" y="${(y + 4).toFixed(1)}" text-anchor="${anchor}">${esc(a.icon)}</text>`;
  }).join('');
  const rows = [...axes, { id: 'other', icon: '…', label: 'Something else' }]
    .map((a) => ({ a, v: Number(counts[a.id]) || 0, on: running ? Number(running[a.id]) || 0 : null }))
    .filter((x) => x.v > 0)
    .map((x) => `<tr><th scope="row"><span aria-hidden="true">${esc(x.a.icon)}</span> ${esc(x.a.label)}</th><td>${esc(x.v)}</td>${running ? `<td>${esc(x.on)}</td>` : ''}</tr>`).join('');
  return `
  <section class="panel radar" aria-labelledby="radar-title"><h2 class="label" id="radar-title">YOUR COMPUTER’S RADAR</h2>
    <div class="radar-body">
      <svg class="radar-svg" viewBox="0 0 220 220" role="img" aria-labelledby="radar-title" aria-describedby="radar-table" focusable="false">
        <g aria-hidden="true">${rings}${spokes}${shape}${labels}</g></svg>
      <table class="radar-table" id="radar-table"><caption class="sr-only">What the things you identified as yours are for</caption>
        <thead><tr><th scope="col">For</th><th scope="col">Yours</th>${running ? '<th scope="col">Running now</th>' : ''}</tr></thead>
        <tbody>${rows}</tbody></table>
    </div>
  </section>`;
}
