// "A computer I don't want to turn on or connect": the steps screen comes
// first, with no scan, because the computer in use may be the clean one.
const test = require('node:test');
const assert = require('node:assert');
const { page, clean } = require('./page-harness.js');

const KEY = 'device-rescue.display';
const GUIDE = 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/infected-device/';

const onSteps = (p) => !p.byId('screen-steps').hidden;
// A click on a control inside the steps card (delegated, like the real page).
function press(p, attrs) {
  const target = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
  const ev = { target: { closest: () => target }, preventDefault() {} };
  (p.byId('steps-card').listeners.click || []).forEach((fn) => fn(ev));
}
const act = (p, action) => press(p, { 'data-steps-action': action });

test('the worry is on the list, worded the way a frightened person would say it', () => {
  const p = page();
  const s = p.run('SITUATIONS').find((x) => x.id === 'offline');
  assert.strictEqual(s.title, 'A computer I don’t want to turn on or connect');
  assert.strictEqual(s.profile, 'infected_device');
  assert.strictEqual(s.guide, GUIDE);
});

test('picking it opens the steps, starts no scan and asks nothing yet', () => {
  for (const store of [{ [KEY]: 'standard' }, { [KEY]: 'city' }, {}]) {
    const p = page({ store });
    p.byId('btn-get-started').click();
    const before = p.calls.game.length; // city mode opens on the Training Grounds
    p.pick('offline');
    assert.ok(onSteps(p), JSON.stringify(store));
    assert.deepStrictEqual(p.shown(), []);
    assert.deepStrictEqual(p.calls.scans, []);
    assert.deepStrictEqual(p.calls.game.slice(before), []);
    assert.match(p.byId('steps-card').innerHTML, /Step 1 of 5/);
  }
});

test('"Done" moves to the next step; the screen is redrawn', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('offline');
  act(p, 'done');
  assert.match(p.byId('steps-card').innerHTML, /Step 2 of 5/);
  assert.match(p.byId('steps-card').innerHTML, /data-steps-tick="0" checked/);
  press(p, { 'data-steps-go': '4' });
  assert.match(p.byId('steps-card').innerHTML, /Step 5 of 5/);
});

test('a checkbox ticks just its own step', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('offline');
  const input = { getAttribute: (k) => (k === 'data-steps-tick' ? '3' : null), checked: true };
  (p.byId('steps-card').listeners.change || []).forEach((fn) => fn({ target: input }));
  assert.match(p.byId('steps-card').innerHTML, /data-steps-tick="3" checked/);
  assert.match(p.byId('steps-card').innerHTML, /Step 1 of 5/);
});

test('the full guide and the accounts guide open in the browser', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('offline');
  act(p, 'guide');
  press(p, { 'data-steps-go': '4' });
  act(p, 'link');
  assert.deepStrictEqual(p.calls.guides, [GUIDE,
    'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/']);
  assert.deepStrictEqual(p.calls.scans, []);
});

test('Back to the worry list', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('offline');
  act(p, 'leave');
  assert.deepStrictEqual(p.shown(), ['worry']);
  assert.ok(!onSteps(p));
});

test('"Check this computer" (plain view): the offline checkup, on the scan screen', async () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('offline');
  act(p, 'check');
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.ok(!onSteps(p));
  p.byId('btn-run-scan').click();
  assert.deepStrictEqual(p.calls.scans, ['infected_device']);
  await p.finish(clean);
  assert.deepStrictEqual(p.shown(), ['results']);
});

test('"Check this computer" before the first question: the question, then the checkup', () => {
  const p = page({ store: {} });
  p.byId('btn-play-game').click();
  p.pick('offline');
  act(p, 'check');
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('no');
  assert.deepStrictEqual(p.calls.scans, ['infected_device']);
});

test('"Check this computer" in city mode: the sweep runs in the game', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-play-game').click();
  const before = p.calls.game.length; // city mode opens on the Training Grounds
  p.pick('offline');
  assert.deepStrictEqual(p.calls.game.slice(before), []);
  act(p, 'check');
  assert.deepStrictEqual(p.calls.game.slice(before), ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['infected_device']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the steps start fresh each time the worry is picked', () => {
  const p = page();
  p.byId('btn-get-started').click();
  p.pick('offline');
  act(p, 'done');
  act(p, 'leave');
  p.pick('offline');
  assert.match(p.byId('steps-card').innerHTML, /Step 1 of 5/);
  assert.ok(!/checked/.test(p.byId('steps-card').innerHTML));
});
