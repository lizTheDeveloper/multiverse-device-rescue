// Workplace and parental monitoring tools say what they're made for and how
// to tell whether this one is the person's own (modules/security/stalkerware_scan).
// Standard mode quiets hotline wording; these sentences must never be quieted.
const test = require('node:test');
const assert = require('node:assert');
const Q = require('../renderer/quiet-notes.js');
const REAL = require('./fixtures/monitoring-descriptions.json');

const PURPOSE_EMPLOYEE = "It's made for an employer recording activity on work computers.";
const PURPOSE_PARENTAL = "It's made for a parent watching a child's messages, browsing and screen time.";
const WORRIED = "If you're worried someone is watching you, treat it as monitoring software someone put here without asking: don't remove it yet, and write down what was found and when.";
const WORK = "If this is a work computer and you aren't worried, it's most likely there for work; your IT department can tell you.";
const CHILD = "If a parent set it up on a child's computer and only that parent gets its reports, it's most likely that.";

const rows = (purpose) => REAL.filter((r) => r.module === 'stalkerware_scan' && r.description.includes(purpose));
const finding = (r) => ({ module: r.module, code: r.code, title: 'x', severity: 'warning', description: r.description });

test('the fixture has the engine’s real workplace and parental text', () => {
  assert.ok(rows(PURPOSE_EMPLOYEE).length >= 1);
  assert.ok(rows(PURPOSE_PARENTAL).length >= 1);
  for (const r of rows(PURPOSE_EMPLOYEE)) assert.ok(r.description.includes(WORRIED) && r.description.includes(WORK));
  for (const r of rows(PURPOSE_PARENTAL)) assert.ok(r.description.includes(WORRIED) && r.description.includes(CHILD));
});

test('none of the new sentences is hotline or relationship wording QuietNotes takes out', () => {
  for (const s of [PURPOSE_EMPLOYEE, PURPOSE_PARENTAL, WORRIED, WORK, CHILD]) assert.ok(!Q.MARKERS.test(s), s);
});

test('standard mode: the purpose and how-to-tell sentences survive, with the one removal line', () => {
  for (const [purpose, tell] of [[PURPOSE_EMPLOYEE, WORK], [PURPOSE_PARENTAL, CHILD]]) {
    for (const r of rows(purpose)) {
      const f = finding(r);
      const card = Q.cardText('standard', f);
      assert.strictEqual(card.note, 'line');
      for (const s of [purpose, WORRIED, tell]) assert.ok(card.description.includes(s), s);
      // The hotline sentence comes out of the face and stays behind the line.
      assert.ok(!/799-7233/.test(card.description));
      assert.ok(card.full.some((p) => /799-7233/.test(p)));
      assert.ok(Q.quiet(r.description).includes(WORRIED));
      assert.ok(Q.quietFinding(f).description.includes(tell));
    }
  }
});

test('city mode: held, with what it is for and how to tell on the held card, and nothing to act on', () => {
  for (const [purpose, tell] of [[PURPOSE_EMPLOYEE, WORK], [PURPOSE_PARENTAL, CHILD]]) {
    for (const r of rows(purpose)) {
      const card = Q.cardText('city', finding(r));
      assert.strictEqual(card.note, 'held');
      assert.deepStrictEqual(card.steps, []);
      assert.ok(card.description.includes(purpose));
      assert.ok(card.description.includes(tell));
      // The "don't remove it yet" sentence is an act sentence: the hold line says it instead.
      assert.ok(!Q.ACTS.test(card.description));
    }
  }
});
