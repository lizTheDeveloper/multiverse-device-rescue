'use strict';
// Workplace and parental monitoring tools (stalkerware_scan): standard mode's
// list asks ONE question per category, and the answer frames every finding of
// that category in this checkup. In memory only: never stored, exported or
// copied. City mode never asks. Only "Only me" (parental) and "My employer's"
// (work) say "most likely"; every other answer is the monitoring path.
const test = require('node:test');
const assert = require('node:assert');
const D = require('../renderer/dual-use.js');
const Q = require('../renderer/quiet-notes.js');
const { page } = require('./page-harness.js');
const REAL = require('./fixtures/monitoring-descriptions.json');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
const unesc = (s) => String(s).replace(/&quot;/g, '"').replace(/&gt;/g, '>').replace(/&lt;/g, '<').replace(/&amp;/g, '&');
const realText = (needle) => REAL.find((r) => r.module === 'stalkerware_scan' && r.description.includes(needle)).description;
const PARENTAL_TEXT = realText("It's made for a parent");
const WORK_TEXT = realText("It's made for an employer");
const f = (category, name, extra = {}) => ({ module: 'stalkerware_scan', severity: 'warning', category: 'security',
  code: 'security.stalkerware_scan.monitoring_software_found', title: `${name} is on this computer (running process)`,
  description: category === 'parental_control' ? PARENTAL_TEXT : WORK_TEXT,
  data: { stalkerware_name: name, stalkerware_category: category, detected_as: 'running process', location: `${name} (pid 7)` }, ...extra });

const ASK_P = 'Who gets this program’s reports?';
const ASK_W = 'Whose computer is this?';
const LIKELY_P = 'Most likely the parental controls you set up.';
const LIKELY_W = 'Most likely your employer’s own monitoring, on its own computer.';
const WATCHED = 'Treat it as monitoring someone may have put here without asking. Don’t remove it yet; write down what was found and when.';
const FAIR = 'Sometimes monitoring starts with a reason that sounded fair, like a child using the device. What matters is who sees what it records.';
const WORK_ASK = 'Work software on your own computer is worth asking about: what it records, when, and who sees it. The rules depend on where you live; a workers’ rights group or legal aid can tell you what’s allowed.';

test('the questions and their answers, word for word', () => {
  assert.strictEqual(D.QUESTIONS.parental_control.ask, ASK_P);
  assert.deepStrictEqual(D.QUESTIONS.parental_control.options.map((o) => o.label), ['Only me', 'Someone else', 'Not sure']);
  assert.strictEqual(D.QUESTIONS.employee_monitoring.ask, ASK_W);
  assert.deepStrictEqual(D.QUESTIONS.employee_monitoring.options.map((o) => o.label), ['My employer’s', 'Mine', 'Not sure']);
  for (const q of Object.values(D.QUESTIONS)) for (const o of q.options) assert.ok(o.label.split(/\s+/).length <= 4, o.label);
});

test('only the categories with a question; stalkerware and other checks are never asked', () => {
  assert.strictEqual(D.categoryOf(f('parental_control', 'Qustodio')), 'parental_control');
  assert.strictEqual(D.categoryOf(f('employee_monitoring', 'Teramind')), 'employee_monitoring');
  assert.strictEqual(D.categoryOf(f('stalkerware', 'mSpy')), null);
  assert.strictEqual(D.categoryOf(f('remote_access', 'AnyDesk')), null);
  assert.strictEqual(D.categoryOf({ module: 'remote_access_tools', data: { stalkerware_category: 'parental_control' } }), null);
});

test('parental: only "Only me" clears; "Someone else" and "Not sure" are the monitoring path', () => {
  assert.deepStrictEqual(D.framing('parental_control', 'me'), { path: 'likely', lines: [LIKELY_P] });
  for (const a of ['someone', 'notsure']) assert.deepStrictEqual(D.framing('parental_control', a), { path: 'watched', lines: [WATCHED, FAIR] }, a);
  assert.strictEqual(D.framing('parental_control', 'bogus'), null);
  assert.strictEqual(D.framing('parental_control', undefined), null);
});

test('work: only "My employer’s" says most likely; "Mine" and "Not sure" are the monitoring path', () => {
  assert.deepStrictEqual(D.framing('employee_monitoring', 'employer'), { path: 'likely', lines: [LIKELY_W] });
  for (const a of ['mine', 'notsure']) assert.deepStrictEqual(D.framing('employee_monitoring', a), { path: 'watched', lines: [WATCHED, WORK_ASK] }, a);
  assert.doesNotMatch(WORK_ASK, /illegal|against the law|not allowed/i, 'never says it is illegal');
});

test('no answer is ever "it’s yours to mark": the monitoring checks are never markable', () => {
  for (const [cat, q] of Object.entries(D.QUESTIONS)) for (const o of q.options) {
    const html = D.blockHtml('standard', f(cat, 'X'), { [cat]: o.id }, { ask: true }, esc);
    assert.doesNotMatch(html, /data-mark|It’s mine|IT IS MINE/, `${cat} ${o.id}`);
  }
});

test('the wording has no relationship or hotline words, so QuietNotes keeps all of it in standard mode', () => {
  const all = [ASK_P, ASK_W, LIKELY_P, LIKELY_W, WATCHED, FAIR, WORK_ASK,
    ...Object.values(D.QUESTIONS).flatMap((q) => q.options.map((o) => o.label))];
  for (const s of all) {
    assert.doesNotMatch(s, /partner|\bex\b|abuser|stalk|housemate|advocate|hotline|traffick/i, s);
    assert.strictEqual(Q.quiet(s), s, s);
  }
});

test('city mode never asks and never frames', () => {
  for (const cat of Object.keys(D.QUESTIONS)) {
    assert.strictEqual(D.blockHtml('city', f(cat, 'X'), {}, { ask: true }, esc), '');
    assert.strictEqual(D.blockHtml('city', f(cat, 'X'), { [cat]: D.QUESTIONS[cat].options[0].id }, { ask: true }, esc), '');
  }
});

test('setAnswer keeps only a real option, and returns a new object', () => {
  const a = {};
  const b = D.setAnswer(a, 'parental_control', 'me');
  assert.deepStrictEqual(a, {});
  assert.deepStrictEqual(b, { parental_control: 'me' });
  assert.deepStrictEqual(D.setAnswer(b, 'parental_control', 'nope'), b);
  assert.deepStrictEqual(D.setAnswer(b, 'stalkerware', 'me'), b);
  assert.deepStrictEqual(D.setAnswer(b, 'parental_control', null), {});
});

// --- the LIST, in the page ---------------------------------------------------

function scanDoc(findings) {
  return { schema_version: 1, platform: 'darwin', modules: [{ name: 'stalkerware_scan', category: 'security', status: 'ok', supported: true,
    findings: findings.map(({ module, ...rest }) => rest) }] };
}

async function listPage(mode, findings) {
  const p = page({ store: { 'device-rescue.display': mode }, ready: false });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(scanDoc(findings));
  // Monitoring software brings the standard-mode follow-up once.
  if (p.shown().includes('question')) p.answer('known');
  return p;
}
// A click on a list control: the delegated handler reads the button's data attribute.
function clickList(p, attr, value) {
  const btn = { getAttribute: (n) => (n === attr ? value : null) };
  const target = { closest: (sel) => (sel === `[${attr}]` ? btn : null) };
  const root = p.byId('results-groups');
  root.contains = () => true;
  for (const fn of root.listeners.click || []) fn({ target, preventDefault() {} });
}
const cards = (html) => html.split('data-card-key=').slice(1);

test('standard list: one question per category, on its first card only', async () => {
  const p = await listPage('standard', [f('parental_control', 'Qustodio'), f('parental_control', 'Bark'), f('employee_monitoring', 'Teramind')]);
  const html = unesc(p.byId('results-groups').innerHTML);
  assert.strictEqual(html.split(ASK_P).length - 1, 1);
  assert.strictEqual(html.split(ASK_W).length - 1, 1);
  assert.match(html, /data-dual-use="parental_control:me"/);
  assert.match(html, /data-dual-use="employee_monitoring:employer"/);
});

test('standard list: "Only me" frames every parental card as likely theirs, and the removal line stays', async () => {
  const p = await listPage('standard', [f('parental_control', 'Qustodio'), f('parental_control', 'Bark'), f('employee_monitoring', 'Teramind')]);
  clickList(p, 'data-dual-use', 'parental_control:me');
  const html = unesc(p.byId('results-groups').innerHTML);
  const all = cards(html);
  const parental = all.filter((c) => /Qustodio|Bark/.test(c.split('</h3>')[0]));
  assert.strictEqual(parental.length, 2);
  for (const c of parental) {
    assert.ok(c.includes(LIKELY_P), 'framed');
    assert.ok(!c.includes(WATCHED));
    assert.ok(c.includes(Q.LINE_SHORT) || c.includes(Q.LINE), 'the removal warning line stays');
  }
  // The other category is still unanswered, and still asked.
  assert.ok(html.includes(ASK_W));
  assert.ok(!html.includes(LIKELY_W));
});

for (const [cat, answer, extra] of [['parental_control', 'someone', FAIR], ['parental_control', 'notsure', FAIR],
  ['employee_monitoring', 'mine', WORK_ASK], ['employee_monitoring', 'notsure', WORK_ASK]]) {
  test(`standard list: ${cat} "${answer}" puts every card of it on the monitoring path`, async () => {
    const names = cat === 'parental_control' ? ['Qustodio', 'Bark'] : ['Teramind', 'ActivTrak'];
    const p = await listPage('standard', names.map((n) => f(cat, n)));
    clickList(p, 'data-dual-use', `${cat}:${answer}`);
    const html = unesc(p.byId('results-groups').innerHTML);
    for (const c of cards(html)) {
      assert.ok(c.includes(WATCHED), 'monitoring path');
      assert.ok(c.includes(extra));
      assert.ok(!c.includes(LIKELY_P) && !c.includes(LIKELY_W));
      assert.ok(c.includes(Q.LINE_SHORT) || c.includes(Q.LINE), 'the removal warning line stays');
      assert.doesNotMatch(c, /\[FIX IT\]|\[IT IS MINE\]/, 'no removal and no mark on the list');
    }
  });
}

test('the answer is never stored, never in the AI copy, and a new checkup asks again', async () => {
  const p = await listPage('standard', [f('parental_control', 'Qustodio'), f('employee_monitoring', 'Teramind')]);
  const before = JSON.stringify(p.storage.data || {});
  clickList(p, 'data-dual-use', 'parental_control:someone');
  clickList(p, 'data-dual-use', 'employee_monitoring:employer');
  const stored = JSON.stringify(p.storage.data || {}) + JSON.stringify(p.storage.writes || []);
  for (const s of [FAIR, LIKELY_W, 'parental_control:', 'employee_monitoring:', 'dual']) assert.ok(!stored.includes(s), s);
  assert.strictEqual(JSON.stringify(p.storage.data || {}), before);
  // "Copy for any AI", "Ask about this" and the whole-report copy: the card's own text only.
  const sent = p.run('JSON.stringify([copyAiRegistry, askRegistry, copyAiReport])');
  assert.ok(sent.length > 50, 'the registries were read');
  for (const s of [FAIR, LIKELY_W, WATCHED, 'parental_control:', 'employee_monitoring:']) assert.ok(!sent.includes(s), s);
  // A new checkup: asked again.
  p.byId('btn-something-changed').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(scanDoc([f('parental_control', 'Qustodio')]));
  if (p.shown().includes('question')) p.answer('known');
  const again = unesc(p.byId('results-groups').innerHTML);
  assert.ok(again.includes(ASK_P), 'asked again');
  assert.ok(!again.includes(FAIR));
});

test('changing the answer puts the question back', async () => {
  const p = await listPage('standard', [f('parental_control', 'Qustodio')]);
  clickList(p, 'data-dual-use', 'parental_control:me');
  assert.ok(unesc(p.byId('results-groups').innerHTML).includes(LIKELY_P));
  clickList(p, 'data-dual-use-undo', 'parental_control');
  const html = unesc(p.byId('results-groups').innerHTML);
  assert.ok(html.includes(ASK_P));
  assert.ok(!html.includes(LIKELY_P));
});

test('city mode: the list never asks', async () => {
  const p = await listPage('city', [f('parental_control', 'Qustodio'), f('employee_monitoring', 'Teramind')]);
  const html = unesc(p.byId('results-groups').innerHTML);
  assert.ok(!html.includes(ASK_P) && !html.includes(ASK_W));
  assert.doesNotMatch(html, /data-dual-use/);
});
