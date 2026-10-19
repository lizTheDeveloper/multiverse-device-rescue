const test = require('node:test');
const assert = require('node:assert');
const FQ = require('../renderer/first-question.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

test('the question, word for word, with its three answers and their modes', () => {
  const q = FQ.QUESTIONS.first;
  assert.strictEqual(q.text, 'Is there someone in your life you’re worried might be watching your devices — a partner, an ex, a family member, someone you live with?');
  assert.deepStrictEqual(q.answers.map((a) => [a.id, a.label, a.mode]), [
    ['no', 'No', 'standard'],
    ['yes', 'Yes, that’s part of it', 'city'],
    ['rather-not', 'I’d rather not say', 'standard'],
  ]);
});

test('the follow-up when monitoring software turns up', () => {
  const q = FQ.QUESTIONS.recheck;
  assert.strictEqual(q.text, 'We found something that can be used to watch a computer. Is that something you know about?');
  assert.deepStrictEqual(q.answers.map((a) => [a.id, a.label, a.mode]), [
    ['known', 'Yes, I know about it', 'standard'],
    ['unknown', 'No, I don’t', 'city'],
    ['rather-not', 'I’d rather not say', 'standard'],
  ]);
});

test('every answer maps to a mode; anything else to nothing', () => {
  assert.strictEqual(FQ.modeFor('first', 'yes'), 'city');
  assert.strictEqual(FQ.modeFor('first', 'no'), 'standard');
  assert.strictEqual(FQ.modeFor('recheck', 'unknown'), 'city');
  assert.strictEqual(FQ.modeFor('first', 'unknown'), null);
  assert.strictEqual(FQ.modeFor('nope', 'yes'), null);
});

test('"I think someone is watching me" is city at once; otherwise ask until there is an answer', () => {
  for (const mode of [null, 'standard', 'city']) assert.strictEqual(FQ.afterWorry({ id: 'watched' }, mode), 'city');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, null), 'ask');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, 'junk'), 'ask');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, 'standard'), 'standard');
  assert.strictEqual(FQ.afterWorry({ id: 'wifi' }, 'city'), 'city');
  assert.strictEqual(FQ.afterWorry(null, null), 'ask');
});

test('the follow-up is due once, in standard mode, after monitoring software was seen', () => {
  assert.strictEqual(FQ.recheckDue({ mode: 'standard', monitoringSeen: true, asked: false }), true);
  assert.strictEqual(FQ.recheckDue({ mode: null, monitoringSeen: true, asked: false }), true);
  assert.strictEqual(FQ.recheckDue({ mode: 'standard', monitoringSeen: true, asked: true }), false);
  assert.strictEqual(FQ.recheckDue({ mode: 'standard', monitoringSeen: false, asked: false }), false);
  assert.strictEqual(FQ.recheckDue({ mode: 'city', monitoringSeen: true, asked: false }), false);
});

test('the question screen: a heading, the question, one button per answer, all escaped', () => {
  const html = FQ.questionHtml('first', esc);
  // tabindex="-1" so the page can move focus to it and a screen reader reads the question.
  assert.match(html, /<h1 id="question-title" tabindex="-1">One more question<\/h1>/);
  assert.ok(html.includes(esc(FQ.QUESTIONS.first.text)));
  assert.strictEqual((html.match(/data-answer="/g) || []).length, 3);
  assert.ok(html.includes('data-answer="rather-not"'));
  assert.strictEqual(FQ.questionHtml('nope', esc), '');
});

test('the re-ask ("Something changed?"): the same question, a way back, and "rather not say" keeps things as they are', () => {
  const q = FQ.QUESTIONS.change;
  assert.strictEqual(q.text, FQ.QUESTIONS.first.text);
  assert.deepStrictEqual(q.answers.map((a) => [a.id, a.label, a.mode]), [
    ['no', 'No', 'standard'],
    ['yes', 'Yes, that’s part of it', 'city'],
    ['rather-not', 'I’d rather not say', null],
  ]);
  assert.deepStrictEqual([q.back.id, q.back.label], ['back', 'Back — keep things as they are']);
  assert.strictEqual(FQ.modeFor('change', 'rather-not'), null);
  assert.strictEqual(FQ.modeFor('change', 'back'), null);
  assert.strictEqual(FQ.modeFor('change', 'no'), 'standard');
  const html = FQ.questionHtml('change', esc);
  assert.strictEqual((html.match(/data-answer="/g) || []).length, 4);
  assert.ok(html.includes('data-answer="back"'));
  assert.ok(html.includes(esc('Back — keep things as they are')));
  assert.ok(!FQ.questionHtml('first', esc).includes('data-answer="back"'), 'the first ask has no back: there is nothing to keep');
});

test('"watching me" among several worries still goes straight to city', () => {
  for (const mode of [null, 'standard', 'city']) {
    assert.strictEqual(FQ.afterWorry({ id: 'several', ids: ['hacked', 'watched'] }, mode), 'city');
  }
  assert.strictEqual(FQ.afterWorry({ id: 'several', ids: ['hacked', 'wifi'] }, 'standard'), 'standard');
  assert.strictEqual(FQ.afterWorry({ id: 'several', ids: ['hacked', 'wifi'] }, null), 'ask');
});
