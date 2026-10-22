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

test('a research link opens at once on a plain item, and waits behind the warning on a warned one', async () => {
  const [Run, C, R] = await load();
  const ctx = ctxOf(C, R);
  const act = (item) => ({ kind: 'settings', url: 'x-apple.systempreferences:com.apple.LoginItems-Settings.extension', text: '', item, steps: [] });
  const plain = gameWith(() => [D('keep', 'keep'), D('later', 'later')]);
  let run = Run.startRun(mission(C, 1));
  let r = Run.openLink(run, plain, ctx, act(run.items[0]));
  assert.ok(r.act, 'opens straight away');
  assert.strictEqual(r.run.phase, 'item');
  // A decision on the item is warned (R6): its links wait too.
  const warnedGame = gameWith(() => [D('keep', 'keep'), D('off', 'settings', { pane: 'login-items', warning: true })]);
  r = Run.openLink(run, warnedGame, ctx, act(run.items[0]));
  assert.strictEqual(r.act, null);
  assert.strictEqual(r.run.phase, 'confirm');
  assert.strictEqual(Run.viewFor(r.run, warnedGame, ctx, {}).warning, Run.REMOVAL_WARNING);
  const done = Run.confirmPending(r.run, warnedGame, ctx);
  assert.strictEqual(done.act.kind, 'settings');
  assert.strictEqual(done.run.phase, 'item');
  // An alerting item.
  run = Run.startRun(mission(C, 1, { removal_alert: true }));
  r = Run.openLink(run, plain, ctx, act(run.items[0]));
  assert.strictEqual(r.act, null);
  assert.strictEqual(Run.cancelPending(r.run).phase, 'item');
});

test('Keep on an item that warns asks a one-line confirm first; on a plain item it is one click', async () => {
  const [Run, C, R] = await load();
  const ctx = ctxOf(C, R);
  const g = gameWith(() => [D('keep', 'keep'), D('later', 'later')]);
  let run = Run.startRun(mission(C, 2, { removal_alert: true }));
  let r = Run.choose(run, 'keep', g, ctx);
  assert.strictEqual(r.run.phase, 'confirm');
  assert.strictEqual(r.run.pending.ask, 'keep');
  assert.strictEqual(Run.doneCount(r.run), 0, 'nothing kept yet');
  assert.strictEqual(Run.cancelPending(r.run).phase, 'item');
  const ok = Run.confirmPending(r.run, g, ctx);
  assert.strictEqual(Run.doneCount(ok.run), 1);
  assert.strictEqual(ok.run.results[0].decision, 'keep');
  run = Run.startRun(mission(C, 2));
  r = Run.choose(run, 'keep', g, ctx);
  assert.strictEqual(Run.doneCount(r.run), 1, 'a plain item keeps at once');
});

// --- R12: a question step (ask) ---

// A two-question game: the first answer picks the second question, the second picks the outcome.
const quiz = () => {
  const seen = { decisions: [], research: [] };
  const g = gameWith((item, ctx) => {
    const a = (ctx && ctx.answers) || [];
    seen.decisions.push(a.slice());
    if (!a.length) return [D('mine', 'ask'), D('dunno', 'ask')];
    if (a.length === 1) return [D('yes', 'ask'), D('no', 'ask')];
    return [D('later', 'later'), D('keep', 'keep')];
  }, {
    research: (item, ctx) => { seen.research.push(((ctx && ctx.answers) || []).slice()); return { rows: [], what: '', links: [] }; },
    render: (view) => `<p>${(view.answers || []).join(',')}</p>`,
  });
  return { g, seen };
};

test('ask keeps the item and grows answers', async () => {
  const [Run, C, R] = await load();
  const { g } = quiz();
  let run = Run.startRun(mission(C, 2));
  const key = run.items[0].key;
  let r = Run.choose(run, 'mine', g, ctxOf(C, R));
  assert.strictEqual(r.act, null);
  run = r.run;
  assert.strictEqual(run.phase, 'item');
  assert.strictEqual(run.index, 0, 'the same item stays on screen');
  assert.deepStrictEqual(run.answers[key], ['mine']);
  assert.strictEqual(Run.doneCount(run), 0, 'nothing is recorded');
  run = Run.choose(run, 'no', g, ctxOf(C, R)).run;
  assert.deepStrictEqual(run.answers[key], ['mine', 'no']);
  assert.strictEqual(run.index, 0);
  // The outcome's own decision answers the item as usual.
  run = Run.choose(run, 'keep', g, ctxOf(C, R)).run;
  assert.strictEqual(run.index, 1);
  assert.deepStrictEqual(Run.summaryResults(run).map((x) => x.decision), ['keep']);
});

test('ask answers reach decisions and render via ctx/view', async () => {
  const [Run, C, R] = await load();
  const { g, seen } = quiz();
  let run = Run.startRun(mission(C, 1));
  const ctx = ctxOf(C, R);
  run = Run.choose(run, 'dunno', g, ctx).run;
  const item = Run.currentItem(run);
  const actx = Run.contextFor(run, ctx, item);
  assert.deepStrictEqual(actx.answers, ['dunno']);
  g.research(item, actx);
  assert.deepStrictEqual(seen.research.pop(), ['dunno']);
  const v = Run.viewFor(run, g, ctx, {});
  assert.deepStrictEqual(v.answers, ['dunno']);
  assert.deepStrictEqual(v.decisions.map((d) => d.id), ['yes', 'no']);
  assert.deepStrictEqual(seen.decisions.pop(), ['dunno']);
  assert.strictEqual(g.render(v, actx), '<p>dunno</p>');
  // A fresh item has no answers.
  const fresh = Run.startRun(mission(C, 1));
  assert.deepStrictEqual(Run.viewFor(fresh, g, ctx, {}).answers, []);
  assert.deepStrictEqual(Run.contextFor(fresh, ctx, Run.currentItem(fresh)).answers, []);
});

test('unask drops the last answer', async () => {
  const [Run, C, R] = await load();
  const { g } = quiz();
  let run = Run.startRun(mission(C, 1));
  const key = run.items[0].key;
  run = Run.choose(run, 'mine', g, ctxOf(C, R)).run;
  run = Run.choose(run, 'yes', g, ctxOf(C, R)).run;
  run = Run.unask(run);
  assert.deepStrictEqual(run.answers[key], ['mine']);
  assert.strictEqual(run.phase, 'item');
  run = Run.unask(run);
  assert.deepStrictEqual(Run.viewFor(run, g, ctxOf(C, R), {}).answers, []);
  assert.strictEqual(Run.unask(run), run, 'nothing to drop: the same run');
});

test('answers are never in remembers or summaryResults points', async () => {
  const [Run, C, R] = await load();
  const { g } = quiz();
  let run = Run.startRun(mission(C, 1));
  run = Run.choose(run, 'mine', g, ctxOf(C, R)).run;
  run = Run.choose(run, 'yes', g, ctxOf(C, R)).run;
  run = Run.choose(run, 'keep', g, ctxOf(C, R)).run;
  const rs = Run.summaryResults(run);
  assert.strictEqual(rs.length, 1);
  assert.ok(!rs.some((x) => x.effect && x.effect.kind === 'ask'));
  assert.ok(!rs.some((x) => 'answers' in x));
  assert.strictEqual(Run.remembers({ outcome: 'done', effect: { kind: 'ask' } }), false);
  // R13: an unpaid effect is never remembered either.
  assert.strictEqual(Run.remembers({ outcome: 'done', effect: { kind: 'keep', unpaid: true } }), false);
  assert.strictEqual(Run.remembers({ outcome: 'done', effect: { kind: 'keep' } }), true);
});

test('practice step answers reach decisions', async () => {
  const [Run, C, R] = await load();
  const { g, seen } = quiz();
  g.practice = { items: g.practice.items, script: [{ item: 0, say: L('First'), expect: 'mine' }, { item: 0, answers: ['mine'], say: L('Then'), expect: 'yes' }] };
  let run = Run.startPractice(Run.startRun(mission(C, 1), { practiceDue: true }), g);
  let v = Run.viewFor(run, g, ctxOf(C, R), {});
  assert.deepStrictEqual(v.decisions.map((d) => d.id), ['mine', 'dunno']);
  assert.deepStrictEqual(v.answers, []);
  run = Run.choosePractice(run, g, 'mine').run;
  run = Run.nextPracticeStep(run, g);
  v = Run.viewFor(run, g, ctxOf(C, R), {});
  assert.deepStrictEqual(seen.decisions.pop(), ['mine']);
  assert.deepStrictEqual(v.decisions.map((d) => d.id), ['yes', 'no']);
  assert.deepStrictEqual(v.answers, ['mine']);
  assert.strictEqual(v.expectLabel.standard, 'yes');
});
