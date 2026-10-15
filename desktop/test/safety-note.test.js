const test = require('node:test');
const assert = require('node:assert');
const { safetyNoteHtml } = require('../renderer/app.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
const note = 'Talk to an advocate first. 1-800-799-7233.';

test('a monitoring-related walkthrough shows its safety note', () => {
  const html = safetyNoteHtml({ description: 'Screen Sharing is on.', remediation: { safety_note: note } }, esc);
  assert.match(html, /finding-card__safety/);
  assert.match(html, /799-7233/);
});

test('the note is not repeated when the finding already gives the hotline', () => {
  const finding = { description: 'Call 1-800-799-7233 first.', remediation: { safety_note: note } };
  assert.strictEqual(safetyNoteHtml(finding, esc), '');
});

test('no note without one from the walkthrough', () => {
  assert.strictEqual(safetyNoteHtml({ description: 'x', remediation: {} }, esc), '');
  assert.strictEqual(safetyNoteHtml({ description: 'x' }, esc), '');
});

const { wantsSafetyNote, withoutSafetyParagraphs } = require('../renderer/app.js');

test('the note follows the worry the person picked', () => {
  const remote = { module: 'remote_login_check' };
  assert.strictEqual(wantsSafetyNote({ id: 'watched', safety: true }, remote), true);
  assert.strictEqual(wantsSafetyNote({ id: 'unsure' }, remote), true);
  assert.strictEqual(wantsSafetyNote({ id: 'hacked' }, remote), false);
  assert.strictEqual(wantsSafetyNote(null, remote), true);
});

test('monitoring software always gets the note', () => {
  assert.strictEqual(wantsSafetyNote({ id: 'hacked' }, { module: 'stalkerware_scan' }), true);
});

test('hotline paragraphs come out of the description, the rest stays', () => {
  const text = 'Screen Sharing is on.\n\nIf you think someone close to you set this up, call 1-800-799-7233.\n\nWhat to do: turn it off.';
  assert.strictEqual(withoutSafetyParagraphs(text), 'Screen Sharing is on.\n\nWhat to do: turn it off.');
});
