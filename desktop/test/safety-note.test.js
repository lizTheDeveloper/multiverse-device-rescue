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
