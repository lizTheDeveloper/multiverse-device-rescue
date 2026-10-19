'use strict';
// Little missions: the runner (missions/runner.js) — state machine, warning, practice, remembering.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const url = (rel) => pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', rel)).href;
const load = () => Promise.all([import(url('runner.js')), import(url('contract.js')), import(url('research.js')), import(url('games/simple.js'))]);

const L = (s) => ({ standard: s, city: s });
// A game whose decisions are whatever the test hands it.
const gameWith = (decide, extra = {}) => ({ type: 'door', title: L('x'), concepts: ['where-it-lives'], decisions: decide,
  research: () => ({ rows: [], what: '', links: [] }), render: () => '<div></div>', summary: () => '',
  practice: { items: [{ key: 'p1', finding: { title: 'p1', data: {} }, findings: [] }, { key: 'p2', finding: { title: 'p2', data: {} }, findings: [] }],
    script: [{ item: 0, say: L('Look'), expect: 'keep' }, { item: 1, say: L('Now this'), expect: 'later' }] }, ...extra });
const D = (id, kind, more = {}) => ({ id, label: L(id), effect: { kind, ...more } });

function mission(C, n = 3, extra = {}) {
  return { id: 'door:gatehouse:1', type: 'door', items: Array.from({ length: n }, (_, i) => C.makeItem({ module: 'launch_agent_audit', title: `T${i}`, data: { plist: `/L/${i}.plist` } }, extra)) };
}
const ctxOf = (C, R, mode = 'standard') => ({ ...C.testContext({ mode }), resolve: (l) => R.resolveLink(l, { mode, platform: 'darwin' }) });

test('state-only decisions record and move on; the last one opens the summary', async () => {
  const [Run, C, R] = await load();
  const g = gameWith(() => [D('later', 'later'), D('keep', 'keep')]);
  let run = Run.startRun(mission(C));
  assert.strictEqual(run.phase, 'item');
  for (let i = 0; i < 3; i += 1) {
    const r = Run.choose(run, i === 1 ? 'later' : 'keep', g, ctxOf(C, R));
    assert.strictEqual(r.act, null);
    run = r.run;
  }
  assert.strictEqual(run.phase, 'summary');
  assert.deepStrictEqual(Run.summaryResults(run).map((x) => x.decision), ['keep', 'later', 'keep']);
});

test('look closer keeps the item open, drops its own button, until another decision', async () => {
  const [Run, C, R] = await load();
  const g = gameWith(() => [D('mine', 'keep'), D('closer', 'closer'), D('later', 'later')]);
  let run = Run.startRun(mission(C, 1));
  run = Run.choose(run, 'closer', g, ctxOf(C, R)).run;
  assert.strictEqual(run.index, 0);
  assert.strictEqual(run.phase, 'item');
  const v = Run.viewFor(run, g, ctxOf(C, R), {});
  assert.strictEqual(v.closer, true);
  assert.deepStrictEqual(v.decisions.map((d) => d.id), ['mine', 'later']);
  run = Run.choose(run, 'mine', g, ctxOf(C, R)).run;
  assert.strictEqual(run.phase, 'summary');
});

test('mark, fix and re-check become acts and wait for the flow to finish', async () => {
  const [Run, C, R] = await load();
  const g = gameWith(() => [D('later', 'later'), D('mine', 'mark'), D('done', 'recheck', { modules: ['a', 'b'] })]);
  let run = Run.startRun(mission(C, 2));
  let r = Run.choose(run, 'mine', g, ctxOf(C, R));
  assert.deepStrictEqual(r.act.kind, 'mark');
  run = Run.settle(r.run, 'cancelled');
  assert.strictEqual(run.index, 0, 'a cancelled mark leaves the item open');
  r = Run.choose(run, 'mine', g, ctxOf(C, R));
  run = Run.settle(r.run, 'done');
  assert.strictEqual(run.index, 1);
  r = Run.choose(run, 'done', g, ctxOf(C, R));
  assert.deepStrictEqual(r.act.modules, ['a', 'b']);
  run = Run.settle(r.run, 'done');
  assert.strictEqual(run.phase, 'summary');
  const g2 = gameWith(() => [D('later', 'later'), D('done', 'recheck')]);
  const r2 = Run.choose(Run.startRun(mission(C, 1)), 'done', g2, ctxOf(C, R));
  assert.deepStrictEqual(r2.act.modules, ['launch_agent_audit'], 'the item’s own checks by default');
});

test('the removal warning is the runner’s: above the decisions and in every fix confirm, whatever the game does', async () => {
  const [Run, C, R] = await load();
  const sneaky = gameWith(() => [D('remove', 'fix'), D('later', 'later')], { render: () => '<p>no warning here</p>' });
  for (const alert of [{ removal_alert: true }, { remediation: { safety_note: 'careful' } }]) {
    const m = { id: 'm', type: 'door', items: [C.makeItem({ module: 'x', title: 't', ...alert })] };
    const run = Run.startRun(m);
    const v = Run.viewFor(run, sneaky, ctxOf(C, R), {});
    assert.strictEqual(v.warning, Run.REMOVAL_WARNING);
    assert.strictEqual(v.decisions[0].effect.kind, 'later', 'a removing decision never leads on an alerting item');
    const r = Run.choose(run, 'remove', sneaky, ctxOf(C, R));
    assert.strictEqual(r.run.phase, 'confirm');
    assert.strictEqual(r.act.options.safety, Run.REMOVAL_WARNING);
    assert.strictEqual(Run.choose(run, 'remove', sneaky, ctxOf(C, R, 'city')).act.options.watched, true, 'city: the watched confirm');
  }
  const plain = Run.startRun(mission(C, 1));
  assert.strictEqual(Run.viewFor(plain, sneaky, ctxOf(C, R), {}).warning, '');
});

test('R6: a settings decision with warning: true shows the warning before the pane opens', async () => {
  const [Run, C, R] = await load();
  const g = gameWith(() => [D('keep', 'keep'), D('back', 'settings', { pane: 'privacy-camera', warning: true })]);
  let run = Run.startRun(mission(C, 1));
  let r = Run.choose(run, 'back', g, ctxOf(C, R));
  assert.strictEqual(r.act, null);
  assert.strictEqual(r.run.phase, 'confirm');
  assert.strictEqual(Run.viewFor(r.run, g, ctxOf(C, R), {}).warning, Run.REMOVAL_WARNING);
  r = Run.confirmPending(r.run, g, ctxOf(C, R));
  assert.strictEqual(r.act.kind, 'settings');
  assert.ok(r.act.url.startsWith('x-apple.systempreferences:'));
  assert.strictEqual(r.run.index, 0, 'the item stays open after the pane opens');
  const plainSettings = gameWith(() => [D('keep', 'keep'), D('on', 'settings', { pane: 'firewall', steps: ['Turn it on.'] })]);
  r = Run.choose(Run.startRun(mission(C, 1)), 'on', plainSettings, ctxOf(C, R));
  assert.strictEqual(r.act.kind, 'settings', 'no warning: it opens at once');
  assert.deepStrictEqual(r.act.steps, ['Turn it on.']);
  run = Run.cancelPending(Run.choose(Run.startRun(mission(C, 1)), 'back', g, ctxOf(C, R)).run);
  assert.strictEqual(run.phase, 'item');
});

test('a game that throws or breaks the rules gets safe decisions instead', async () => {
  const [Run, C, R] = await load();
  const broken = gameWith(() => { throw new Error('x'); });
  const v = Run.viewFor(Run.startRun(mission(C, 1)), broken, ctxOf(C, R), {});
  assert.deepStrictEqual(v.decisions.map((d) => d.effect.kind), ['later', 'recheck']);
  const tooMany = gameWith(() => [D('a', 'later'), D('b', 'keep'), D('c', 'keep'), D('d', 'keep')]);
  assert.strictEqual(Run.viewFor(Run.startRun(mission(C, 1)), tooMany, ctxOf(C, R), {}).decisions.length, 2);
});

test('odd notes become an act carrying the module and code', async () => {
  const [Run, C, R] = await load();
  const g = gameWith(() => [D('normal', 'note'), D('odd', 'odd')]);
  const m = { id: 'notes:x:1', type: 'notes', items: [C.makeItem({ module: 'launch_agent_audit', code: 'security.launch_agent_audit.x', title: 'n', severity: 'info' })] };
  const r = Run.choose(Run.startRun(m), 'odd', g, ctxOf(C, R));
  assert.strictEqual(r.act.kind, 'odd');
  assert.strictEqual(r.act.module, 'launch_agent_audit');
  assert.strictEqual(r.act.code, 'security.launch_agent_audit.x');
  assert.strictEqual(r.run.phase, 'summary');
});

test('practice: offered the first time, played step by step with right/wrong by expect, then the real items', async () => {
  const [Run, C] = await load();
  const g = gameWith(() => [D('keep', 'keep'), D('later', 'later')]);
  let run = Run.startRun(mission(C, 1), { practiceDue: true });
  assert.strictEqual(run.phase, 'offer');
  run = Run.startPractice(run, g);
  assert.strictEqual(Run.viewFor(run, g, C.testContext(), {}).item.key, 'p1');
  let r = Run.choosePractice(run, g, 'keep');
  assert.strictEqual(r.answer.right, true);
  run = Run.nextPracticeStep(r.run, g);
  r = Run.choosePractice(run, g, 'keep');
  assert.strictEqual(r.answer.right, false);
  assert.strictEqual(Run.choosePractice(r.run, g, 'later').answer, null, 'one answer per step');
  run = Run.nextPracticeStep(r.run, g);
  assert.strictEqual(run.phase, 'item');
  assert.strictEqual(run.practiced, true);
  const skipped = Run.skipPractice(Run.startRun(mission(C, 1), { practiceDue: true }));
  assert.strictEqual(skipped.phase, 'item');
  assert.strictEqual(skipped.skipped, true);
  // On request, from a mission already under way: back to the same item.
  let mid = Run.choose(Run.startRun(mission(C, 2)), 'keep', g, C.testContext()).run;
  mid = Run.startPractice(mid, g);
  mid = Run.skipPractice(mid);
  assert.strictEqual(mid.index, 1);
  assert.strictEqual(mid.skipped, false, 'leaving a requested round is not "I know this"');
});

test('practiceDue: first time, not after playing, again after a skip once a gap shows', async () => {
  const [Run] = await load();
  assert.strictEqual(Run.practiceDue(null), true);
  assert.strictEqual(Run.practiceDue({ how: 'played' }, ['worth-a-look']), false);
  assert.strictEqual(Run.practiceDue({ how: 'skipped' }, ['skipped']), false);
  assert.strictEqual(Run.practiceDue({ how: 'skipped' }, ['skipped', 'worth-a-look']), true);
});

test('fingerprint: changes with path, signer or settings; not with counts or timing', async () => {
  const [Run, C] = await load();
  const item = (data, made_by = []) => C.makeItem({ module: 'm', code: 'c', data, made_by });
  const a = Run.fingerprint(item({ path: '/a', pid: 1, enabled: true }, [{ subject: '/a', name: 'X', verified: true }]));
  assert.strictEqual(a, Run.fingerprint(item({ path: '/a', pid: 99, enabled: true }, [{ subject: '/a', name: 'X', verified: true }])));
  assert.notStrictEqual(a, Run.fingerprint(item({ path: '/b', pid: 1, enabled: true }, [{ subject: '/b', name: 'X', verified: true }])));
  assert.notStrictEqual(a, Run.fingerprint(item({ path: '/a', pid: 1, enabled: true }, [{ subject: '/a', name: 'X', verified: false }])));
  assert.notStrictEqual(a, Run.fingerprint(item({ path: '/a', pid: 1, enabled: false }, [{ subject: '/a', name: 'X', verified: true }])));
  assert.match(a, /^[0-9a-z_.-]{7}$/);
});

test('remembered answers are skipped; only settled answers (not Later, not opened panes) are kept', async () => {
  const [Run, C, R] = await load();
  const m = mission(C, 2);
  const run = Run.startRun(m, { recalled: { [m.items[0].key]: 'keep' } });
  assert.strictEqual(run.index, 1);
  assert.strictEqual(run.results[0].outcome, 'remembered');
  assert.strictEqual(Run.remembers(run.results[0]), false, 'already stored');
  const g = gameWith(() => [D('later', 'later'), D('keep', 'keep')]);
  const later = Run.choose(Run.startRun(mission(C, 1)), 'later', g, ctxOf(C, R)).run.results[0];
  const kept = Run.choose(Run.startRun(mission(C, 1)), 'keep', g, ctxOf(C, R)).run.results[0];
  assert.strictEqual(Run.remembers(later), false);
  assert.strictEqual(Run.remembers(kept), true);
  const all = Run.startRun(m, { recalled: { [m.items[0].key]: 'keep', [m.items[1].key]: 'keep' } });
  assert.strictEqual(all.phase, 'summary');
});

test('Odd Jobs runs end to end through the runner', async () => {
  const [Run, C, R, S] = await load();
  const m = { id: 'simple:x:1', type: 'simple', items: [C.makeItem({ module: 'battery_health', title: 'Worn' })] };
  let run = Run.startRun(m);
  const r = Run.choose(run, 'did', S.default, ctxOf(C, R));
  assert.strictEqual(r.act.kind, 'recheck');
  run = Run.settle(r.run, 'done');
  assert.match(S.default.summary(Run.summaryResults(run), C.testContext()), /1 decided/);
});
