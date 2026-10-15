const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { describeMadeBy, madeByHtml, MADE_BY_REASON, MADE_BY_VERIFIED_LABEL } = require('../renderer/app.js');

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

// --- no line says the same thing twice --------------------------------------------

// Every literal `how` and every note the engine can send, read from its source
// so a new one is covered without editing this test.
const ATTRIBUTION = fs.readFileSync(path.join(__dirname, '..', '..', 'rescue', 'attribution.py'), 'utf8');

function engineHows() {
  const hows = new Set();
  for (const m of ATTRIBUTION.matchAll(/MadeBy\((?:[^,()]|\([^()]*\))+,\s*(?:True|False),\s*"([^"]+)"/g)) hows.add(m[1]);
  for (const m of ATTRIBUTION.matchAll(/how="([^"]+)"/g)) hows.add(m[1]);
  return [...hows];
}

function engineNotes() {
  const notes = [];
  for (const m of ATTRIBUTION.matchAll(/^_[A-Z]+_NOTE = \(?((?:\s*"[^"]*"\s*)+)\)?$/gm)) {
    notes.push([...m[1].matchAll(/"([^"]*)"/g)].map((s) => s[1]).join(''));
  }
  for (const m of ATTRIBUTION.matchAll(/return "(Runs from [^"]+)"/g)) notes.push(m[1]);
  notes.push('This file can be changed by any program on the computer.');
  return notes;
}

function sentences(text) {
  return text
    .replace(/^[⚠✓]\s*/, '')
    .split(/(?<=[.:;])\s+|,\s+/)
    .map((s) => s.toLowerCase().replace(/[’]/g, "'").replace(/[.:;,]+$/, '').trim())
    .filter((s) => s.length > 12);
}

test('the engine source yields the hows and notes this test relies on', () => {
  const hows = engineHows();
  for (const how of ['unsigned', 'script', 'inline command', 'settings change how the program loads code',
    'program not named by full path', 'unreadable settings', 'started with extra instructions', 'Developer ID signature']) {
    assert.ok(hows.includes(how), how);
  }
  assert.ok(engineNotes().some((n) => n.startsWith('Its settings change how or where the program runs')));
  assert.ok(engineNotes().length >= 5);
});

test('the settings-change line says its sentence once', () => {
  const note = engineNotes().find((n) => n.startsWith('Its settings change how or where'));
  const d = describeMadeBy({ name: 'Unknown maker', verified: false, how: 'settings change how the program loads code', location_note: note });
  assert.strictEqual(d.text, `⚠ Unknown maker: ${note}`);
  assert.strictEqual(d.text.toLowerCase().split('how or where the program runs').length, 2);
});

test('no describeMadeBy line repeats a sentence, for any how and note', () => {
  const hows = new Set([...engineHows(), ...Object.keys(MADE_BY_REASON), ...Object.keys(MADE_BY_VERIFIED_LABEL)]);
  const notes = engineNotes();
  const location = notes.filter((n) => n.startsWith('Runs from') || n.startsWith('This file'));
  // A location note is added after the engine's own note (Attributor._identify_program), at most one.
  const own = notes.filter((n) => !location.includes(n));
  const noteChoices = ['', ...notes, ...own.flatMap((n) => location.map((l) => `${n} ${l}`))];
  let checked = 0;
  for (const how of hows) {
    for (const verified of [true, false]) {
      for (const name of ['Unknown maker', 'Example Co']) {
        for (const note of noteChoices) {
          const { text } = describeMadeBy({ name, verified, how, location_note: note });
          const parts = sentences(text);
          for (let i = 0; i < parts.length; i++) {
            for (let j = 0; j < parts.length; j++) {
              if (i === j) continue;
              assert.ok(!parts[j].startsWith(parts[i]), `repeats "${parts[i]}" in: ${text}`);
            }
          }
          checked++;
        }
      }
    }
  }
  assert.ok(checked > 100);
});
