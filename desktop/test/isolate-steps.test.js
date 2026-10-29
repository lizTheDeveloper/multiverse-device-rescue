const test = require('node:test');
const assert = require('node:assert');
const IS = require('../renderer/isolate-steps.js');
const { isAllowedGuideUrl } = require('../setting-urls');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const GUIDE = 'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/infected-device/';

test('the steps, in order: isolate first, accounts last', () => {
  assert.deepStrictEqual(IS.STEPS.map((s) => s.id), ['offline', 'nothing-else', 'how-is-it', 'files', 'accounts']);
  const first = IS.STEPS[0];
  assert.match(first.title, /internet/i);
  const said = first.lines.join(' ');
  assert.match(said, /cable/);
  assert.match(said, /System Settings › Wi-Fi/);
  assert.match(said, /Settings › Network & internet › Airplane mode/);
  assert.match(IS.STEPS[4].title, /different device/);
});

test('short: no step is a wall of text', () => {
  for (const s of IS.STEPS) {
    assert.ok(s.title.length <= 48, s.title);
    assert.ok(s.lines.length <= 3, s.id);
    for (const line of s.lines) assert.ok(line.length <= 140, line);
  }
});

test('the three states are named in plain words, and "won’t start" is honest about the app', () => {
  const lines = IS.STEPS[2].lines.join(' ');
  assert.match(lines, /^Starts:/);
  assert.match(lines, /Barely starts: .*safe mode/);
  assert.match(lines, /Won’t start: .*Recovery/);
  assert.match(lines, /erase and reinstall/);
});

test('every link is one the main process will open', () => {
  assert.ok(isAllowedGuideUrl(IS.GUIDE_URL));
  assert.strictEqual(IS.GUIDE_URL, GUIDE);
  for (const s of IS.STEPS) if (s.link) assert.ok(isAllowedGuideUrl(s.link.url), s.link.url);
  assert.strictEqual(IS.STEPS[4].link.url,
    'https://lizthedeveloper.github.io/multiverse-device-rescue/docs/scenarios/digital-security-reset/');
});

test('a fresh list: nothing ticked, on step 1', () => {
  const s = IS.createState();
  assert.strictEqual(s.current(), 0);
  assert.deepStrictEqual(s.progress(), { done: 0, total: 5 });
  assert.ok(IS.STEPS.every((_, i) => !s.isDone(i)));
});

test('"Done" ticks the step and moves to the next one not done', () => {
  const s = IS.createState();
  s.done();
  assert.ok(s.isDone(0));
  assert.strictEqual(s.current(), 1);
  s.tick(2, true);
  s.done();
  assert.strictEqual(s.current(), 3, 'skips the one already ticked');
  assert.deepStrictEqual(s.progress(), { done: 3, total: 5 });
});

test('each item is its own: tick, untick, jump to it', () => {
  const s = IS.createState();
  s.tick(3, true);
  assert.ok(s.isDone(3));
  s.tick(3, false);
  assert.ok(!s.isDone(3));
  s.go(4);
  assert.strictEqual(s.current(), 4);
  s.back();
  assert.strictEqual(s.current(), 3);
  s.go(0); s.back();
  assert.strictEqual(s.current(), 0, 'no step before the first');
  s.go(99);
  assert.strictEqual(s.current(), 0, 'out of range is ignored');
  s.tick(-1, true);
  assert.deepStrictEqual(s.progress(), { done: 0, total: 5 });
});

test('the last "Done" stays on the last step and says all done', () => {
  const s = IS.createState();
  for (let i = 0; i < IS.STEPS.length; i += 1) s.done();
  assert.strictEqual(s.current(), 4);
  assert.deepStrictEqual(s.progress(), { done: 5, total: 5 });
  assert.match(IS.screenHtml(s, esc), /All 5 done/);
});

test('the screen shows one step, a checklist with a box per step, and the ways on', () => {
  const s = IS.createState();
  s.done();
  const html = IS.screenHtml(s, esc);
  assert.match(html, /Step 2 of 5/);
  assert.match(html, new RegExp(esc(IS.STEPS[1].title)));
  const boxes = [...html.matchAll(/<input type="checkbox" data-steps-tick="(\d)"( checked)?/g)];
  assert.deepStrictEqual(boxes.map((m) => [m[1], !!m[2]]), [['0', true], ['1', false], ['2', false], ['3', false], ['4', false]]);
  for (const action of ['done', 'back', 'guide', 'check', 'leave']) {
    assert.match(html, new RegExp(`data-steps-action="${action}"`), action);
  }
  // Only the current step's details: the others are a title in the checklist.
  assert.ok(!html.includes(esc(IS.STEPS[3].lines[0])));
});

test('the screen escapes what it shows', () => {
  const s = IS.createState();
  const html = IS.screenHtml(s, esc);
  assert.ok(!/<script/i.test(html));
  assert.ok(html.includes('Network &amp; internet'));
});

test('a step with a link gets its own button', () => {
  const s = IS.createState();
  s.go(4);
  const html = IS.screenHtml(s, esc);
  assert.match(html, /data-steps-action="link"/);
  s.go(0);
  assert.ok(!/data-steps-action="link"/.test(IS.screenHtml(s, esc)));
});

test('which worries open the steps first', () => {
  assert.strictEqual(IS.opensFirst({ id: 'offline', steps: 'isolate' }), true);
  assert.strictEqual(IS.opensFirst({ id: 'wifi' }), false);
  assert.strictEqual(IS.opensFirst(null), false);
});

test('actions read from a click: the action, and the step for tick and go', () => {
  const el = (attrs) => ({ getAttribute: (k) => (k in attrs ? attrs[k] : null) });
  assert.deepStrictEqual(IS.actionOf(el({ 'data-steps-action': 'done' })), { action: 'done' });
  assert.deepStrictEqual(IS.actionOf(el({ 'data-steps-go': '3' })), { action: 'go', step: 3 });
  assert.deepStrictEqual(IS.actionOf(el({ 'data-steps-tick': '2' }), true), { action: 'tick', step: 2, on: true });
  assert.strictEqual(IS.actionOf(null), null);
  assert.strictEqual(IS.actionOf(el({})), null);
});

test('every button on the screen has a size, so none falls back to the browser’s tiny default', () => {
  const html = IS.screenHtml(IS.createState(), esc);
  const btns = html.match(/<button[^>]*class="btn [^"]*"/g) || [];
  assert.ok(btns.length >= 4);
  for (const b of btns) assert.match(b, /btn--(large|small)/, b);
});
