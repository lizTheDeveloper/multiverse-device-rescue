// The deck's WATCH CONNECTIONS instrument, and the small state steps behind
// it. Pure. The watch itself runs in main (desktop/watch.js); this draws its
// controls and a text progress line, and says where the results went. Its
// findings arrive in INCOMING SIGNALS like a re-check's and score nothing.
// The lookups switch (who runs each address) is on unless the person turns it off.
import { esc } from '../escape.js';
import { MONITORING_MODULES } from '../ledger.js';

// The same list main allows (desktop/watch.js WATCH_MINUTES).
export const WATCH_MINUTES = [1, 2, 5, 10, 15, 30];
export const WATCH_DEFAULT_MINUTES = 5;
const FAILED = 'The connection watch couldn’t finish. Your checkup results are unchanged.';

const minutesOf = (m) => (WATCH_MINUTES.includes(m) ? m : WATCH_DEFAULT_MINUTES);
const count = (n) => Math.max(0, Math.floor(Number(n) || 0));
export const plural = (n, word) => `${n} ${word}${n === 1 ? '' : 's'}`;

export const idleWatch = (minutes = WATCH_DEFAULT_MINUTES, lookups = true) => ({ state: 'idle', minutes: minutesOf(minutes),
  lookups: lookups !== false, phase: 'watch', elapsed: 0, total: 0, snapshots: 0, lookupDone: 0, lookupTotal: 0, message: '' });

const again = (w) => idleWatch(w && w.minutes, w && w.lookups);
export const watchStarted = (w) => ({ ...again(w), state: 'running', total: minutesOf(w && w.minutes) * 60 });

// The minute buttons and the lookups switch change nothing while a watch runs.
export const watchMinutes = (w, m) => (w.state === 'running' ? w : idleWatch(m, w.lookups));
export const watchToggleLookups = (w) => (w.state === 'running' ? w : { ...w, lookups: !w.lookups });

// A {progress: {phase: "watch", elapsed, total, snapshots}} event from main,
// then {progress: {phase: "lookup", done, total}} while addresses are looked up.
export function watchProgress(w, ev) {
  const p = ev && ev.progress;
  if (!w || w.state !== 'running' || !p) return w;
  if (p.phase === 'lookup') return { ...w, phase: 'lookup', lookupDone: count(p.done), lookupTotal: count(p.total) };
  if (p.phase !== 'watch') return w;
  return { ...w, elapsed: count(p.elapsed), total: count(p.total) || w.total, snapshots: count(p.snapshots) };
}

// runWatch's answer: {ok: true, doc}, {ok: false, reason, message}, or null when the call itself failed.
export function watchFinished(w, r) {
  if (r && r.ok) return { ...again(w), state: 'done' };
  const failed = !r || r.reason === 'failed';
  return { ...again(w), state: failed ? 'failed' : 'refused', message: String((r && r.message) || FAILED) };
}

// The same test main's gate uses: a warning or critical finding from a monitoring check.
export function watchOffered(doc) {
  if (!doc || !Array.isArray(doc.modules)) return false;
  return !doc.modules.some((m) => m && MONITORING_MODULES.has(m.name) && Array.isArray(m.findings)
    && m.findings.some((f) => f && (f.severity === 'critical' || f.severity === 'warning')));
}

export function watchProgressText({ minutes, elapsed, snapshots, phase, lookupDone, lookupTotal }) {
  if (phase === 'lookup') {
    const total = count(lookupTotal);
    return `Looking up who runs each address… ${Math.min(count(lookupDone), total)} of ${total}.`;
  }
  const n = minutesOf(minutes);
  return `Watching… ${Math.min(n, Math.floor(count(elapsed) / 60))} of ${plural(n, 'minute')}, ${plural(count(snapshots), 'snapshot')}.`;
}

function startHtml(n, lookups) {
  const picks = WATCH_MINUTES.map((m) => `<button type="button" class="btn-s" data-act="watch-minutes:${m}" aria-pressed="${m === n ? 'true' : 'false'}">${m}</button>`).join('');
  const what = lookups
    ? `Watches which apps on this computer connect where, for ${plural(n, 'minute')}, then looks up who runs each address. You can keep using the computer while the watch runs. Results last until your next checkup.`
    : `Watches which apps on this computer connect where, for ${plural(n, 'minute')}. Nothing leaves this computer, and you can keep using it while the watch runs. Results last until your next checkup.`;
  return `
    <p class="intel">${what}</p>
    <div class="row watch-minutes" role="group" aria-label="Minutes to watch"><span class="label">MINUTES</span>${picks}</div>
    <label class="intel watch-lookups"><input type="checkbox" data-act="watch-lookups"${lookups ? ' checked' : ''}> Look up who runs each address (sends the addresses, not what was in them, to RIPE NCC and rdap.org)</label>
    <button type="button" class="btn-s lime" data-act="watch-start">START THE WATCH ▶</button>`;
}

export function renderWatch({ state = 'idle', minutes, lookups = true, phase = 'watch', elapsed = 0, snapshots = 0,
  lookupDone = 0, lookupTotal = 0, message = '' } = {}) {
  const n = minutesOf(minutes);
  let body;
  if (state === 'running') {
    body = `
    <p class="intel" role="status" data-watch="progress">${esc(watchProgressText({ minutes: n, elapsed, snapshots, phase, lookupDone, lookupTotal }))}</p>
    <button type="button" class="btn-s" data-act="watch-stop">STOP</button>
    <p class="intel">Stopping keeps what was gathered.</p>`;
  } else {
    const said = state === 'done' ? 'Watch finished. What it saw is in INCOMING SIGNALS.'
      : state === 'refused' || state === 'failed' ? String(message || FAILED) : '';
    body = `${said ? `
    <p class="intel watch-said" role="status">${esc(said)}</p>` : ''}${startHtml(n, lookups !== false)}`;
  }
  return `
  <section class="panel watch" aria-label="Watch connections">
    <div class="label">WATCH CONNECTIONS</div>${body}
  </section>`;
}
