// The WATCH CONNECTIONS instrument (renderer/game/views/watch.js): pure HTML
// for each state, its text equivalents, and the small state steps the
// controller wires up.
const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const view = () => import('../renderer/game/views/watch.js');
const IDLE = 'Watches which apps on this computer connect where, for 5 minutes, then looks up who runs each address. You can keep using the computer while the watch runs. Results last until your next checkup.';
const IDLE_OFF = 'Watches which apps on this computer connect where, for 5 minutes. Nothing leaves this computer, and you can keep using it while the watch runs. Results last until your next checkup.';
const LOOKUPS_LABEL = 'Look up who runs each address (sends the addresses, not what was in them, to RIPE NCC, rdap.org and the regional registry that holds each one, and asks your DNS provider for their names)';

test('idle: the heading, what it does for the chosen minutes, the picker and a start button', async () => {
  const { renderWatch } = await view();
  const html = renderWatch({ state: 'idle', minutes: 5 });
  assert.match(html, /WATCH CONNECTIONS/);
  assert.ok(html.includes(IDLE), 'the idle sentence, with the minutes');
  assert.match(renderWatch({ state: 'idle', minutes: 15 }), /connect where, for 15 minutes, then/);
  assert.match(renderWatch({ state: 'idle', minutes: 1 }), /connect where, for 1 minute, then looks up/);
  assert.match(renderWatch({ state: 'idle', minutes: 1, lookups: false }), /connect where, for 1 minute\. Nothing/);
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
  assert.match(renderWatch({ state: 'idle', minutes: '<b>' }), /for 5 minutes, then/);
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
  assert.match(renderWatch({ state: 'running', minutes: 1 }), /Watching… 0 of 1 minute, 0 snapshots\./);
  assert.match(renderWatch({ state: 'running', minutes: 1, elapsed: 5, snapshots: 1 }), /Watching… 0 of 1 minute, 1 snapshot\./);
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
  assert.strictEqual(watchProgressText({ minutes: 1, elapsed: 60, snapshots: 1 }), 'Watching… 1 of 1 minute, 1 snapshot.');
});

test('state steps: start, progress events, a result, a refusal, a failure', async () => {
  const { idleWatch, watchStarted, watchProgress, watchFinished } = await view();
  const idle = idleWatch();
  assert.deepStrictEqual(idle, { state: 'idle', minutes: 5, lookups: true, stopping: false, phase: 'watch', elapsed: 0, total: 0, snapshots: 0,
    lookupDone: 0, lookupTotal: 0, message: '' });
  assert.strictEqual(idleWatch(15).minutes, 15);
  assert.strictEqual(idleWatch(15, false).lookups, false);
  assert.strictEqual(idleWatch(7).minutes, 5);
  const run = watchStarted({ ...idle, minutes: 2, message: 'old' });
  assert.deepStrictEqual(run, { state: 'running', minutes: 2, lookups: true, stopping: false, phase: 'watch', elapsed: 0, total: 120, snapshots: 0,
    lookupDone: 0, lookupTotal: 0, message: '' });
  assert.strictEqual(watchStarted({ ...idle, lookups: false }).lookups, false, 'the switch carries into the run');
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

test('the view and main agree on when monitoring software turns the watch off', async () => {
  const { watchOffered } = await view();
  const { handleWatch } = require('../watch');
  const mod = (name, severities) => ({ name, status: 'ok', supported: true, findings: severities.map((severity) => ({ title: 't', severity })) });
  const cases = [
    [mod('stalkerware_scan', ['warning'])], [mod('mvt_spyware_scan', ['critical'])], [mod('keylogger_indicators', ['info', 'warning'])],
    [mod('stalkerware_scan', ['info'])], [mod('keylogger_indicators', [])], [mod('a_mod', ['critical', 'warning'])],
    [mod('a_mod', ['info']), mod('stalkerware_scan', ['info'])],
  ];
  for (const modules of cases) {
    const doc = { schema_version: 1, platform: 'darwin', modules };
    const r = await handleWatch(5, { getLastDoc: () => doc, setLastDoc: () => {}, policies: [], isBusy: () => false, onEvent: () => {},
      logError: () => {}, runWatch: async () => null });
    const mainRefuses = r.reason === 'monitoring';
    assert.strictEqual(watchOffered(doc), !mainRefuses, JSON.stringify(modules));
  }
  // Both ways are covered above.
  assert.ok(cases.some((m) => !watchOffered({ modules: m })) && cases.some((m) => watchOffered({ modules: m })));
});

test('the lookups switch: on by default, its exact label, and the idle sentence says what is sent', async () => {
  const { renderWatch } = await view();
  const on = renderWatch({ state: 'idle', minutes: 5 });
  assert.match(on, /<input type="checkbox" data-act="watch-lookups" checked>/);
  assert.ok(on.includes(LOOKUPS_LABEL), 'the label, word for word');
  assert.match(on, /<label[^>]*>\s*<input type="checkbox" data-act="watch-lookups"[^>]*>\s*Look up who runs/, 'the label wraps the box');
  assert.ok(on.includes(IDLE));
  assert.ok(!on.includes('Nothing leaves this computer'), 'not while addresses are sent');
  const off = renderWatch({ state: 'idle', minutes: 5, lookups: false });
  assert.match(off, /<input type="checkbox" data-act="watch-lookups">/);
  assert.ok(off.includes(IDLE_OFF), 'off: the sentence from before lookups');
  assert.ok(off.includes(LOOKUPS_LABEL));
  // Done, refused and failed offer it too; a running watch doesn't.
  assert.match(renderWatch({ state: 'done', minutes: 5, lookups: false }), /data-act="watch-lookups">/);
  assert.doesNotMatch(renderWatch({ state: 'running', minutes: 5 }), /watch-lookups/);
});

test('state steps for the switch: toggled while idle, kept across minutes, a run and its result', async () => {
  const { idleWatch, watchStarted, watchFinished, watchToggleLookups, watchMinutes } = await view();
  const off = watchToggleLookups(idleWatch(10));
  assert.deepStrictEqual([off.lookups, off.minutes], [false, 10]);
  assert.strictEqual(watchToggleLookups(off).lookups, true);
  assert.deepStrictEqual([watchMinutes(off, 2).lookups, watchMinutes(off, 2).minutes], [false, 2]);
  const run = watchStarted(off);
  assert.strictEqual(watchToggleLookups(run), run, 'not while a watch runs');
  assert.strictEqual(watchMinutes(run, 2), run, 'not while a watch runs');
  assert.strictEqual(watchFinished(run, { ok: true, doc: {} }).lookups, false);
  assert.strictEqual(watchFinished(run, null).lookups, false);
  assert.strictEqual(idleWatch(5, 'no').lookups, true, 'only false turns it off');
});

test('lookup progress: the running line says who-runs lookups are under way, with counts', async () => {
  const { renderWatch, watchStarted, watchProgress, watchProgressText, idleWatch } = await view();
  let w = watchStarted(idleWatch(1));
  w = watchProgress(w, { progress: { phase: 'watch', elapsed: 60, total: 60, snapshots: 12 } });
  w = watchProgress(w, { progress: { phase: 'lookup', done: 3, total: 40 } });
  assert.deepStrictEqual([w.phase, w.lookupDone, w.lookupTotal, w.snapshots], ['lookup', 3, 40, 12]);
  assert.strictEqual(watchProgressText(w), 'Looking up who runs each address… 3 of 40.');
  assert.match(renderWatch(w), /data-watch="progress"[^>]*>Looking up who runs each address… 3 of 40\./);
  assert.strictEqual(watchProgressText(watchProgress(w, { progress: { phase: 'lookup', done: 'x', total: 1 } })),
    'Looking up who runs each address… 0 of 1.');
  assert.strictEqual(watchProgressText(watchProgress(w, { progress: { phase: 'lookup', done: 9, total: 2 } })),
    'Looking up who runs each address… 2 of 2.', 'never more done than there are');
  assert.strictEqual(watchProgress(idleWatch(), { progress: { phase: 'lookup', done: 1, total: 2 } }).phase, 'watch', 'ignored unless running');
});

test('stopping: the running line reads exactly that until the watch ends', async () => {
  const { renderWatch, idleWatch, watchStarted, watchStopping, watchProgress, watchFinished, watchProgressText } = await view();
  const STOPPING = 'Stopping… finishing what was gathered.';
  assert.strictEqual(watchStopping(idleWatch()).stopping, false, 'nothing to stop');
  let w = watchStopping(watchStarted(idleWatch(5)));
  assert.strictEqual(w.state, 'running');
  assert.strictEqual(watchProgressText(w), STOPPING);
  assert.ok(renderWatch(w).includes(`data-watch="progress">${STOPPING}</p>`));
  w = watchProgress(w, { progress: { phase: 'lookup', done: 2, total: 5 } });
  assert.strictEqual(watchProgressText(w), STOPPING, 'later progress keeps the line');
  assert.strictEqual(watchFinished(w, { ok: true }).stopping, false);
  assert.strictEqual(watchStarted(watchFinished(w, null)).stopping, false, 'the next watch starts fresh');
});
