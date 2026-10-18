const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const ROOT = path.join(__dirname, '..', '..');
const load = () => import('../renderer/game/clues.js');
const norm = (s) => String(s).replace(/\s+/g, ' ');
const src = (rel) => norm(fs.readFileSync(path.join(ROOT, rel), 'utf8'));

// The same kind of gate as game-lessons.test.js: every claim names a source,
// and the source says it.
test('every place note and every how-to-read line is sourced: its file holds its pattern and its quote word for word', async () => {
  const { PLACES, READING } = await load();
  assert.strictEqual(new Set(PLACES.map((p) => p.id)).size, PLACES.length);
  for (const p of PLACES) {
    assert.ok(['prefix', 'contains'].includes(p.kind), p.id);
    assert.ok(fs.existsSync(path.join(ROOT, p.source)), `${p.id}: no ${p.source}`);
    const text = src(p.source);
    assert.ok(text.includes(p.pattern), `${p.id}: "${p.pattern}" isn’t in ${p.source}`);
    assert.ok(text.includes(norm(p.quote)), `${p.id}: its quote isn’t in ${p.source}`);
    assert.ok(p.note && p.short, p.id);
  }
  for (const [key, r] of Object.entries(READING)) {
    assert.ok(fs.existsSync(path.join(ROOT, r.source)), `${key}: no ${r.source}`);
    assert.ok(src(r.source).includes(norm(r.quote)), `${key}: its quote isn’t in ${r.source}`);
    assert.ok(r.text, key);
  }
});

test('no clue text diagnoses this computer or names a duration', async () => {
  const { PLACES, READING, COULDNT_READ } = await load();
  const { DIAGNOSTIC_PHRASES, TIME_WORDS } = await import('../renderer/game/training.js');
  for (const text of [...PLACES.map((p) => p.note), ...Object.values(READING).map((r) => r.text), COULDNT_READ]) {
    for (const phrase of DIAGNOSTIC_PHRASES) assert.ok(!text.toLowerCase().includes(phrase), text);
    assert.doesNotMatch(text, TIME_WORDS, text);
  }
});

test('placeFor: home folders, /private/tmp, Windows paths, and places with no note', async () => {
  const { placeFor } = await load();
  const id = (p) => (placeFor(p) || {}).id || null;
  assert.strictEqual(id('/Users/ann/Library/LaunchAgents/com.x.plist'), 'user-launch-agents');
  assert.strictEqual(id('/Library/LaunchAgents/com.x.plist'), 'launch-agents');
  assert.strictEqual(id('/Library/LaunchDaemons/com.x.plist'), 'launch-daemons');
  assert.strictEqual(id('/private/tmp/x'), 'tmp');
  assert.strictEqual(id('/home/ann/.config/autostart/x.desktop'), 'hidden-config');
  assert.strictEqual(id('C:\\Users\\ann\\AppData\\Local\\Temp\\x.exe'), 'windows-temp');
  assert.strictEqual(id('C:\\Program Files\\Zoom\\zoom.exe'), 'program-files');
  assert.strictEqual(id('/Users/ann/Downloads/setup'), 'downloads');
  assert.strictEqual(id('/tmpfoo/x'), null, 'a prefix matches whole folder names only');
  assert.strictEqual(id('/opt/thing/bin'), null);
  assert.strictEqual(placeFor(''), null);
  assert.strictEqual(placeFor(null), null);
});

test('clues come only from evidence the finding has, in a fixed order', async () => {
  const { cluesFor, placeFor, READING } = await load();
  const full = cluesFor({ title: 't', description: 'Starts at login.\n\nWhat to do: remove it.',
    data: { program: '/tmp/x', first_seen: '2026-09-30T10:00:00Z' },
    made_by: [{ subject: '/tmp/x', name: 'Unknown maker', verified: false, how: 'unsigned', location_note: '' }] });
  assert.deepStrictEqual(full.map((c) => c.kind), ['maker', 'where', 'what', 'when']);
  assert.deepStrictEqual(full.map((c) => c.label), ['WHO MADE IT', 'WHERE IT LIVES', 'WHAT IT DOES', 'WHEN IT SHOWED UP']);
  assert.deepStrictEqual(full[0].lines, ['Unknown maker, not verified (unsigned)']);
  assert.strictEqual(full[0].reading, READING.unverified);
  assert.deepStrictEqual(full[1].lines, ['/tmp/x', placeFor('/tmp/x').note]);
  assert.strictEqual(full[1].reading, READING.place);
  assert.deepStrictEqual(full[2].lines, ['Starts at login.']);
  assert.deepStrictEqual(full[3].lines, ['2026-09-30']);
});

// Review Focus 2.
test('no made_by, no path, no date: only the clue it can support; no description either: none', async () => {
  const { cluesFor } = await load();
  assert.deepStrictEqual(cluesFor({ title: 't', description: 'Plain words.', data: { check: 'x', count: 3 } }).map((c) => c.kind), ['what']);
  assert.deepStrictEqual(cluesFor({ title: 't', description: '', data: {} }), []);
  assert.deepStrictEqual(cluesFor(null), []);
  assert.deepStrictEqual(cluesFor({ data: { first_seen: 'not a date', path: 'relative/x' }, made_by: 'nope' }), []);
});

test('who made it: verified, Apple, several programs, and the program’s description only when verified', async () => {
  const { cluesFor, READING } = await load();
  const v = cluesFor({ made_by: [{ name: 'Google LLC', verified: true, how: 'Developer ID signature', what: 'Chrome: a browser.' }] })[0];
  assert.deepStrictEqual(v.lines, ['Google LLC, verified (Developer ID signature)', 'Chrome: a browser.']);
  assert.strictEqual(v.reading, READING.verified);
  assert.strictEqual(cluesFor({ made_by: [{ name: 'Apple', verified: true, how: 'Apple system file' }] })[0].reading, READING.apple);
  const two = cluesFor({ made_by: [{ subject: '/Applications/A.app', name: 'A Co', verified: true, how: 'Developer ID signature' },
    { subject: '/tmp/b', name: '', verified: false, how: 'unsigned', what: 'never shown' }] })[0];
  assert.deepStrictEqual(two.lines, ['A.app: A Co, verified (Developer ID signature)', 'b: Unknown maker, not verified (unsigned)']);
  assert.strictEqual(two.reading, READING.unverified);
});

test('a place with no note still shows its path, with the plain how-to-read line', async () => {
  const { cluesFor, READING } = await load();
  assert.deepStrictEqual(cluesFor({ data: { path: '/opt/x/bin' } }), [{ kind: 'where', label: 'WHERE IT LIVES', lines: ['/opt/x/bin'], reading: READING.placeUnknown }]);
});

test('Scout’s read: says whether the scan agrees and why; never “wrong”; the person’s call stands', async () => {
  const { scoutRead } = await load();
  const sig = (severity, finding = {}, extra = {}) => ({ kind: 'real', severity, finding, marked: false, ...extra });
  const unsigned = { made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }], data: { program: '/tmp/x' } };
  const same = scoutRead(sig('critical', unsigned), 'threat');
  assert.match(same, /sees it the same way/);
  assert.match(same, /nobody has vouched for who made it/);
  const differ = scoutRead(sig('critical', unsigned), 'mine');
  assert.match(differ, /You called it yours\. Your call stands/);
  assert.match(scoutRead(sig('warning', { data: { program: '/tmp/x' } }), 'closer'), /it lives in a temporary folder/);
  const all = [same, differ, scoutRead(sig('warning', {}, { marked: true }), 'mine'),
    ...['mine', 'threat', 'closer'].flatMap((t) => ['critical', 'warning', 'info'].map((sv) => scoutRead(sig(sv), t)))];
  for (const line of all) assert.doesNotMatch(line, /\bwrong\b|incorrect|mistake/i, line);
});

test('a drill’s read: right, or the tell, and it costs nothing', async () => {
  const { drillRead } = await load();
  const d = { why: 'It runs from a hidden folder.' };
  assert.strictEqual(drillRead(d, true), 'Right. It runs from a hidden folder.');
  assert.match(drillRead(d, false), /^Not this time, and it costs you nothing\. The tell: It runs from a hidden folder\.$/);
});
