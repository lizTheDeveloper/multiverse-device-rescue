// The deck's WATCH CONNECTIONS instrument, and the small state steps behind
// it. Pure. The watch itself runs in main (desktop/watch.js); this draws its
// controls and a text progress line, and says where the results went. Its
// findings arrive in INCOMING SIGNALS like a re-check's and score nothing.
import { esc } from '../escape.js';
import { MONITORING_MODULES } from '../ledger.js';

// The same list main allows (desktop/watch.js WATCH_MINUTES).
export const WATCH_MINUTES = [1, 2, 5, 10, 15, 30];
export const WATCH_DEFAULT_MINUTES = 5;
const FAILED = 'The connection watch couldn’t finish. Your checkup results are unchanged.';

const minutesOf = (m) => (WATCH_MINUTES.includes(m) ? m : WATCH_DEFAULT_MINUTES);
const count = (n) => Math.max(0, Math.floor(Number(n) || 0));

export const idleWatch = (minutes = WATCH_DEFAULT_MINUTES) => (
  { state: 'idle', minutes: minutesOf(minutes), elapsed: 0, total: 0, snapshots: 0, message: '' });

export const watchStarted = (w) => ({ ...idleWatch(w && w.minutes), state: 'running', total: minutesOf(w && w.minutes) * 60 });

// A {progress: {phase: "watch", elapsed, total, snapshots}} event from main.
export function watchProgress(w, ev) {
  const p = ev && ev.progress;
  if (!w || w.state !== 'running' || !p || p.phase !== 'watch') return w;
  return { ...w, elapsed: count(p.elapsed), total: count(p.total) || w.total, snapshots: count(p.snapshots) };
}

// runWatch's answer: {ok: true, doc}, {ok: false, reason, message}, or null when the call itself failed.
export function watchFinished(w, r) {
  const minutes = w && w.minutes;
  if (r && r.ok) return { ...idleWatch(minutes), state: 'done' };
  const failed = !r || r.reason === 'failed';
  return { ...idleWatch(minutes), state: failed ? 'failed' : 'refused', message: String((r && r.message) || FAILED) };
}

// The same test main's gate uses: a warning or critical finding from a monitoring check.
export function watchOffered(doc) {
  if (!doc || !Array.isArray(doc.modules)) return false;
  return !doc.modules.some((m) => m && MONITORING_MODULES.has(m.name) && Array.isArray(m.findings)
    && m.findings.some((f) => f && (f.severity === 'critical' || f.severity === 'warning')));
}

export function watchProgressText({ minutes, elapsed, snapshots }) {
  const n = minutesOf(minutes);
  return `Watching… ${Math.min(n, Math.floor(count(elapsed) / 60))} of ${n} minutes, ${count(snapshots)} snapshots.`;
}

function startHtml(n) {
  const picks = WATCH_MINUTES.map((m) => `<button type="button" class="btn-s" data-act="watch-minutes:${m}" aria-pressed="${m === n ? 'true' : 'false'}">${m}</button>`).join('');
  return `
    <p class="intel">Watches which apps on this computer connect where, for ${n} minutes. Nothing leaves this computer, and you can keep using it while the watch runs. Results last until your next checkup.</p>
    <div class="row watch-minutes" role="group" aria-label="Minutes to watch"><span class="label">MINUTES</span>${picks}</div>
    <button type="button" class="btn-s lime" data-act="watch-start">START THE WATCH ▶</button>`;
}

export function renderWatch({ state = 'idle', minutes, elapsed = 0, snapshots = 0, message = '' } = {}) {
  const n = minutesOf(minutes);
  let body;
  if (state === 'running') {
    body = `
    <p class="intel" role="status" data-watch="progress">${esc(watchProgressText({ minutes: n, elapsed, snapshots }))}</p>
    <button type="button" class="btn-s" data-act="watch-stop">STOP</button>
    <p class="intel">Stopping keeps what was gathered.</p>`;
  } else {
    const said = state === 'done' ? 'Watch finished. What it saw is in INCOMING SIGNALS.'
      : state === 'refused' || state === 'failed' ? String(message || FAILED) : '';
    body = `${said ? `
    <p class="intel watch-said" role="status">${esc(said)}</p>` : ''}${startHtml(n)}`;
  }
  return `
  <section class="panel watch" aria-label="Watch connections">
    <div class="label">WATCH CONNECTIONS</div>${body}
  </section>`;
}
