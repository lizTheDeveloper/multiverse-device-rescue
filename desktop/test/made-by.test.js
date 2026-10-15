const test = require('node:test');
const assert = require('node:assert');
const { describeMadeBy, madeByHtml } = require('../renderer/app.js');

const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');

test('a verified signature reads as a calm green line', () => {
  const d = describeMadeBy({ subject: '/Applications/Google Chrome.app', name: 'Google LLC', verified: true, how: 'Developer ID signature', location_note: '' });
  assert.strictEqual(d.tone, 'ok');
  assert.strictEqual(d.text, '✓ Made by Google LLC (verified signature)');
});

test('an Apple system file is described plainly', () => {
  const d = describeMadeBy({ name: 'Apple', verified: true, how: 'Apple system file' });
  assert.strictEqual(d.text, '✓ Made by Apple (part of macOS)');
});

test('an unsigned program in /tmp is amber and says why', () => {
  const d = describeMadeBy({ name: 'Unknown maker', verified: false, how: 'unsigned', location_note: 'Runs from /tmp, a temporary folder any program can write to.' });
  assert.strictEqual(d.tone, 'warn');
  assert.strictEqual(d.text, '⚠ Unknown maker: not signed. Runs from /tmp, a temporary folder any program can write to.');
});

test('a script is never presented as verified', () => {
  const d = describeMadeBy({ name: 'Unknown maker', verified: false, how: 'script', location_note: 'A script, not signed; check who created it.' });
  assert.strictEqual(d.tone, 'warn');
  assert.match(d.text, /check who created it/);
});

test('a signed program in a risky folder is flagged amber', () => {
  const d = describeMadeBy({ name: 'Google LLC', verified: true, how: 'Developer ID signature', location_note: 'Runs from /tmp, a temporary folder any program can write to.' });
  assert.strictEqual(d.tone, 'warn');
  assert.match(d.text, /Google LLC/);
});

test('missing or partial entries do not throw', () => {
  assert.doesNotThrow(() => describeMadeBy(undefined));
  assert.doesNotThrow(() => describeMadeBy({}));
});

test('madeByHtml renders nothing without entries and escapes text', () => {
  assert.strictEqual(madeByHtml(undefined, esc), '');
  assert.strictEqual(madeByHtml([], esc), '');
  const html = madeByHtml([{ subject: '/x/<b>.app', name: '<img src=x>', verified: true, how: 'Developer ID signature' }], esc);
  assert.ok(!html.includes('<img'));
  assert.match(html, /What does this mean/);
});

test('with several programs each line is labelled', () => {
  const html = madeByHtml([
    { subject: '/Applications/A.app', name: 'A Co', verified: true, how: 'Developer ID signature' },
    { subject: '/tmp/b', name: 'Unknown maker', verified: false, how: 'unsigned' },
  ], esc);
  assert.match(html, /made-by__subject">A\.app/);
  assert.match(html, /made-by__subject">b/);
});

test('a verified program carries its plain-language description', () => {
  const entry = { subject: 'com.loom.desktop', name: 'Loom, Inc', verified: true, how: 'Developer ID signature', location_note: '',
    what: 'Loom: records your screen and camera to make video messages you can share with a link.' };
  const d = describeMadeBy(entry);
  assert.strictEqual(d.text, '✓ Made by Loom, Inc (verified signature)');
  assert.strictEqual(d.what, entry.what);
  const html = madeByHtml([entry], esc);
  assert.match(html, /verified signature\)<span class="made-by__what"> — Loom: records your screen/);
});

test('a description is never shown for an unverified program', () => {
  const entry = { name: 'Loom, Inc', verified: false, how: 'claims to be made by Loom, Inc; couldn’t verify', what: 'Loom: records your screen.' };
  assert.ok(!describeMadeBy(entry).what);
  assert.ok(!madeByHtml([entry], esc).includes('made-by__what'));
});

test('the description is escaped', () => {
  const html = madeByHtml([{ name: 'X', verified: true, how: 'Developer ID signature', what: '<img src=x onerror=alert(1)>' }], esc);
  assert.ok(!html.includes('<img'));
  assert.match(html, /&lt;img/);
});

test('entries without a description render as before', () => {
  const html = madeByHtml([{ name: 'Google LLC', verified: true, how: 'Developer ID signature' }], esc);
  assert.ok(!html.includes('made-by__what'));
});
