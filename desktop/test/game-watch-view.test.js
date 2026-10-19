// The WATCH CONNECTIONS instrument (renderer/game/views/watch.js): pure HTML
// for each state, its text equivalents, and the small state steps the
// controller wires up.
const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const view = () => import('../renderer/game/views/watch.js');
const IDLE = 'Watches which apps on this computer connect where, for 5 minutes. Nothing leaves this computer, and you can keep using it while the watch runs. Results last until your next checkup.';

test('idle: the heading, what it does for the chosen minutes, the picker and a start button', async () => {
  const { renderWatch } = await view();
  const html = renderWatch({ state: 'idle', minutes: 5 });
  assert.match(html, /WATCH CONNECTIONS/);
  assert.ok(html.includes(IDLE), 'the idle sentence, with the minutes');
  assert.match(renderWatch({ state: 'idle', minutes: 15 }), /connect where, for 15 minutes\./);
  assert.match(html, /data-act="watch-start"/);
  assert.doesNotMatch(html, /data-act="watch-stop"/);
});

test('the picker offers exactly 1, 2, 5, 10, 15 and 30 minutes, the chosen one pressed', async () => {
  const { renderWatch, WATCH_MINUTES, WATCH_DEFAULT_MINUTES } = await view();
  assert.deepStrictEqual(WATCH_MINUTES, [1, 2, 5, 10, 15, 30]);
  assert.deepStrictEqual(WATCH_MINUTES, require('../watch').WATCH_MINUTES, 'the same list main allows');
  assert.strictEqual(WATCH_DEFAULT_MINUTES, 5);
  const html = renderWatch({ state: 'idle', minutes: 10 });
  const offered = [...html.matchAll(/data-act="watch-minutes:(\d+)"/g)].map((m) => Number(m[1]));
  assert.deepStrictEqual(offered, [1, 2, 5, 10, 15, 30]);
  assert.match(html, /data-act="watch-minutes:10"[^>]*aria-pressed="true"/);
  assert.strictEqual((html.match(/aria-pressed="true"/g) || []).length, 1);
  // A minutes value off the list falls back to the default.
  assert.match(renderWatch({ state: 'idle', minutes: 7 }), /data-act="watch-minutes:5"[^>]*aria-pressed="true"/);
  assert.match(renderWatch({ state: 'idle', minutes: '<b>' }), /for 5 minutes\./);
});

test('running: a text progress line (no graph-only state), STOP, and no picker or start', async () => {
  const { renderWatch } = await view();
  const html = renderWatch({ state: 'running', minutes: 10, elapsed: 185, total: 600, snapshots: 37 });
  assert.match(html, /Watching… 3 of 10 minutes, 37 snapshots\./);
  assert.match(html, /role="status"[^>]*data-watch="progress"|data-watch="progress"[^>]*role="status"/);
  assert.match(html, /data-act="watch-stop"[^>]*>STOP</);
  assert.match(html, /Stopping keeps what was gathered/);
  assert.doesNotMatch(html, /data-act="watch-start"|data-act="watch-minutes:/);
  // Before the first progress event.
  assert.match(renderWatch({ state: 'running', minutes: 1 }), /Watching… 0 of 1 minutes, 0 snapshots\./);
});

test('done: where the results went, and a way to watch again', async () => {
  const { renderWatch } = await view();
  const html = renderWatch({ state: 'done', minutes: 5 });
  assert.match(html, /role="status"[^>]*>Watch finished\. What it saw is in INCOMING SIGNALS\./);
  assert.match(html, /data-act="watch-start"/);
  assert.ok(html.includes(IDLE));
});

test('refused and failed show main’s message, escaped', async () => {
  const { renderWatch } = await view();
  for (const state of ['refused', 'failed']) {
    const html = renderWatch({ state, minutes: 5, message: EVIL });
    assert.ok(!html.includes(EVIL), `${state}: the message is escaped`);
    assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
    assert.match(html, /role="status"/);
    assert.match(html, /data-act="watch-start"/);
  }
});

test('the progress sentence is the same text the live update writes', async () => {
  const { watchProgressText } = await view();
  assert.strictEqual(watchProgressText({ minutes: 2, elapsed: 61, snapshots: 12 }), 'Watching… 1 of 2 minutes, 12 snapshots.');
  assert.strictEqual(watchProgressText({ minutes: 2, elapsed: 'x', snapshots: null }), 'Watching… 0 of 2 minutes, 0 snapshots.');
  assert.strictEqual(watchProgressText({ minutes: 2, elapsed: 999, snapshots: 3 }), 'Watching… 2 of 2 minutes, 3 snapshots.');
});

test('state steps: start, progress events, a result, a refusal, a failure', async () => {
  const { idleWatch, watchStarted, watchProgress, watchFinished } = await view();
  const idle = idleWatch();
  assert.deepStrictEqual(idle, { state: 'idle', minutes: 5, elapsed: 0, total: 0, snapshots: 0, message: '' });
  assert.strictEqual(idleWatch(15).minutes, 15);
  assert.strictEqual(idleWatch(7).minutes, 5);
  const run = watchStarted({ ...idle, minutes: 2, message: 'old' });
  assert.deepStrictEqual(run, { state: 'running', minutes: 2, elapsed: 0, total: 120, snapshots: 0, message: '' });
  const p = watchProgress(run, { progress: { phase: 'watch', elapsed: 30, total: 120, snapshots: 6 } });
  assert.deepStrictEqual([p.elapsed, p.total, p.snapshots], [30, 120, 6]);
  assert.strictEqual(watchProgress(idle, { progress: { phase: 'watch', elapsed: 30 } }), idle, 'ignored unless running');
  assert.strictEqual(watchProgress(run, { progress: { phase: 'scan', elapsed: 30 } }), run, 'other phases are ignored');
  assert.strictEqual(watchProgress(run, null), run);
  assert.strictEqual(watchFinished(p, { ok: true, doc: {} }).state, 'done');
  const r = watchFinished(p, { ok: false, reason: 'monitoring', message: 'Off.' });
  assert.deepStrictEqual([r.state, r.message, r.minutes], ['refused', 'Off.', 2]);
  assert.strictEqual(watchFinished(p, { ok: false, reason: 'failed', message: 'No.' }).state, 'failed');
  const none = watchFinished(p, null);
  assert.strictEqual(none.state, 'failed');
  assert.ok(none.message);
});

test('offered only with a checkup that found no monitoring software', async () => {
  const { watchOffered } = await view();
  const mod = (name, severity) => ({ name, findings: severity ? [{ severity }] : [] });
  assert.strictEqual(watchOffered(null), false);
  assert.strictEqual(watchOffered({}), false);
  assert.strictEqual(watchOffered({ modules: [mod('a_mod', 'critical')] }), true);
  assert.strictEqual(watchOffered({ modules: [mod('stalkerware_scan', 'info')] }), true, 'an info note is on most computers');
  assert.strictEqual(watchOffered({ modules: [mod('stalkerware_scan', 'warning')] }), false);
  assert.strictEqual(watchOffered({ modules: [mod('keylogger_indicators', 'critical')] }), false);
});
