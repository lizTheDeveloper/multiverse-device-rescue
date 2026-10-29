const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const MarkFlow = require('../renderer/mark-flow.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const ticks = async (n = 8) => { for (let i = 0; i < n; i += 1) await tick(); };
const UNDO = ['Choose “Stop treating this as mine”'];
const taskFinding = (n, extra = {}) => ({
  module: 'launch_agent_audit', code: 'security.launch_agent_audit.suspicious_path', title: `Background task: t${n}`, severity: 'warning',
  data: { label: `t${n}`, program: `/Users/me/.x/t${n}`, plist: `/Users/me/Library/LaunchAgents/t${n}.plist` },
  markable: { kind: 'background_task', id: `00000000000${n}`, code: 'security.launch_agent_audit.suspicious_path', label: `t${n}`,
    program: `/Users/me/.x/t${n}`, plist: `/Users/me/Library/LaunchAgents/t${n}.plist`, will_change: 'Stops warning.', how_to_undo: UNDO }, ...extra });
const sig = (n, over = {}) => ({ id: `s${n}`, kind: 'real', severity: 'warning', title: `Background task: t${n}`, districtId: 'gatehouse',
  module: 'launch_agent_audit', finding: taskFinding(n), missionId: `s${n}`, marked: false, stale: false, tag: null, ...over });

function harness({ signals = [sig(1), sig(2), sig(3)], watched = false, held = false, markResult = (id) => ({ status: 'marked', ids: [id] }) } = {}) {
  const calls = { mark: [], unmark: [], recheck: [], rebuilt: 0, renders: 0, log: [], marked: 0 };
  let current = signals;
  // The fake engine's own list: what a re-check would then report as marked.
  const saved = new Set(signals.filter((s) => s.marked).map((s) => s.finding.data.known_item_id));
  const engineView = () => current.map((s) => {
    const id = s.marked ? s.finding.data.known_item_id : s.finding.markable && s.finding.markable.id;
    const on = saved.has(id);
    if (on === s.marked) return s;
    return { ...s, marked: on, tag: on ? 'mine' : null,
      finding: on ? { ...s.finding, markable: undefined, data: { ...s.finding.data, marked_by_user: true, known_item_id: id } } : s.finding };
  });
  const api = {
    markMine: async (id) => { calls.mark.push(id); const r = markResult(id); if (r.status === 'marked') saved.add(id); return r; },
    unmarkMine: async (id) => { calls.unmark.push(id); saved.delete(id); return { status: 'removed', ids: [id] }; },
    recheckModule: async (name) => { calls.recheck.push(name); return { ok: true, doc: { name } }; },
  };
  return { calls, api, set: (s) => { current = s; },
    deps: { api, MarkFlow, signals: engineView, opts: () => ({ watched, held }), docChanged: () => true,
      rebuild: () => { calls.rebuilt += 1; }, render: () => { calls.renders += 1; }, log: (k, t) => calls.log.push(`${k}: ${t}`),
      noteMarked: () => { calls.marked += 1; }, modulesFor: () => ['launch_agent_audit'] } };
}

test('one click marks a background task: no question, out of the queue at once, Undo offered', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness();
  const desk = createMarkDesk(h.deps);
  await desk.ask('s1');
  assert.deepStrictEqual(h.calls.mark, ['000000000001']);
  const shown = desk.overlay(h.deps.signals());
  assert.strictEqual(shown[0].marked, true, 'moved to YOURS before the re-check comes back');
  assert.strictEqual(shown[1].marked, false);
  assert.match(desk.toast.text, /t1/);
  assert.ok(desk.toast.undo);
  assert.strictEqual(h.calls.marked, 1, 'the ledger notes it (no clean bonus next sweep)');
  assert.ok(h.calls.log.some((l) => l.startsWith('MINE')));
  await ticks();
  assert.deepStrictEqual(h.calls.recheck, ['launch_agent_audit'], 're-checked quietly, without a screen change');
});

test('city mode asks once, inline; CANCEL marks nothing; YES marks', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness({ watched: true });
  const desk = createMarkDesk(h.deps);
  await desk.ask('s1');
  assert.deepStrictEqual(h.calls.mark, []);
  assert.deepStrictEqual(desk.confirm, { target: 's1', watch: false });
  desk.no();
  assert.strictEqual(desk.confirm, null);
  assert.deepStrictEqual(h.calls.mark, []);
  await desk.ask('s1');
  await desk.yes('s1');
  assert.deepStrictEqual(h.calls.mark, ['000000000001']);
});

test('bulk: ticked items start unticked, and one action marks every ticked one', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness();
  const desk = createMarkDesk(h.deps);
  assert.strictEqual(desk.picked.size, 0);
  desk.pick('s1'); desk.pick('s3');
  await desk.askPicked();
  assert.deepStrictEqual(h.calls.mark, ['000000000001', '000000000003']);
  assert.strictEqual(desk.picked.size, 0);
  assert.match(desk.toast.text, /2/);
  desk.pick('s2'); desk.pick('s2');
  assert.strictEqual(desk.picked.size, 0, 'a second tick unticks');
});

test('Undo puts it straight back in the queue and unmarks it in the engine', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness();
  const desk = createMarkDesk(h.deps);
  await desk.ask('s2');
  await ticks();
  await desk.undo();
  assert.deepStrictEqual(h.calls.unmark, ['000000000002']);
  assert.strictEqual(desk.overlay(h.deps.signals())[1].marked, false);
});

test('NOT MINE on something the engine already marked sends its saved id back', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const marked = sig(4, { marked: true, tag: 'mine', finding: { ...taskFinding(4), markable: undefined, data: { ...taskFinding(4).data, marked_by_user: true, known_item_id: 'abababababab' } } });
  const h = harness({ signals: [marked] });
  const desk = createMarkDesk(h.deps);
  await desk.unmine(['s4']);
  assert.deepStrictEqual(h.calls.unmark, ['abababababab']);
  assert.strictEqual(desk.overlay([marked])[0].marked, false, 'back in the queue at once');
});

test('an engine refusal marks nothing and says so', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness({ markResult: () => ({ status: 'refused', message: 'It changed since the checkup.' }) });
  const desk = createMarkDesk(h.deps);
  await desk.ask('s1');
  assert.strictEqual(desk.overlay(h.deps.signals())[0].marked, false);
  assert.strictEqual(desk.toast.tone, 'error');
  assert.match(desk.toast.text, /changed since the checkup/);
  assert.strictEqual(h.calls.marked, 0);
});

test('SAFETY: a forged or monitoring id never reaches the engine', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const spy = sig(5, { module: 'stalkerware_scan', finding: { ...taskFinding(5), module: 'stalkerware_scan' } });
  const h = harness({ signals: [spy, sig(6, { severity: 'critical', finding: { ...taskFinding(6), severity: 'critical' } })] });
  const desk = createMarkDesk(h.deps);
  await desk.ask('s5');
  await desk.ask('s6');
  await desk.ask('nope');
  desk.pick('s5');
  await desk.askPicked();
  await desk.yes('s5');
  assert.deepStrictEqual(h.calls.mark, []);
  assert.strictEqual(desk.picked.size, 0, 'it can’t even be ticked');
});

test('SAFETY: while monitoring software is held, every quick mark asks first, bulk included', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness({ held: true });
  const desk = createMarkDesk(h.deps);
  await desk.ask('s1');
  assert.deepStrictEqual(h.calls.mark, []);
  assert.ok(desk.confirm);
  desk.no();
  desk.pick('s1'); desk.pick('s2');
  await desk.askPicked();
  assert.deepStrictEqual(h.calls.mark, []);
  assert.deepStrictEqual(desk.confirm, { target: '*', watch: false, count: 2 });
});

test('clearing the last one is a slightly bigger beat', async () => {
  const { createMarkDesk } = await game('mark-desk.js');
  const h = harness({ signals: [sig(1)] });
  const desk = createMarkDesk(h.deps);
  await desk.ask('s1');
  assert.strictEqual(desk.toast.allDone, true);
});
