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

// The grouped connection watch (signals.js): WHERE THEY WENT.
const who = (over = {}) => ({ hostname: null, hostname_confirmed: false, asn: null, as_name: null, prefix: null, network: null,
  registrant: null, country: null, unavailable: [], ...over });
const APPLE = who({ as_name: 'APPLE-ENGINEERING - Apple Inc.' });
const GOOGLE = who({ as_name: 'GOOGLE - Google LLC', hostname: 'dns.google', hostname_confirmed: true });
const CF = who({ as_name: 'CLOUDFLARENET - Cloudflare, Inc.' });
const dst = (address, port, snapshots, w = null) => ({ address, port, protocol: 'tcp', snapshots, who: w });
const app = (target, destinations, extra = {}) => ({ module: 'connection_watch', code: 'network.connection_watch.watch_summary',
  title: `${target}: ${destinations.length} destinations during the watch`, severity: 'info',
  data: { target, destinations, more: 0, not_stored: 0, lookup_sources: SOURCES, ...extra } });
const SOURCES = ['reverse DNS (your computer’s own resolver)', 'RIPE NCC (stat.ripe.net)', 'rdap.org and the regional registry it redirects to'];
const group = (...watch) => ({ module: 'connection_watch', code: 'network.connection_watch.group', watch });

test('WHERE THEY WENT: one clue, the rollup by apps, each app busiest first, the gaps and the sources', async () => {
  const { cluesFor, READING } = await load();
  const clues = cluesFor(group(
    app('Mail', [dst('17.1.1.1', 993, 3, APPLE), dst('104.16.1.1', 443, 1, CF)]),
    app('Safari', [dst('17.1.1.2', 443, 9, APPLE), dst('8.8.8.8', 443, 2, GOOGLE), dst('104.16.1.2', 443, 2, CF)]),
    app('Music', [dst('17.1.1.3', 443, 1, APPLE)]),
    { module: 'connection_watch', code: 'network.connection_watch.watch_incomplete', title: 'Parts…', severity: 'info',
      data: { reasons: ['Looking up stopped early.', 'Only the busiest 150 addresses were looked up.'] } },
    { module: 'connection_watch', code: 'network.connection_watch.dns_not_visible', title: 'Couldn’t see which names were looked up', data: {} },
  ));
  assert.strictEqual(clues.length, 1);
  const [c] = clues;
  assert.deepStrictEqual([c.kind, c.label], ['went', 'WHERE THEY WENT']);
  assert.strictEqual(c.reading, READING.went);
  assert.strictEqual(READING.went.text, 'Who runs an address is usually a hosting or cloud company, not the app’s maker. Lookups sent the addresses, not what was in them.');
  assert.deepStrictEqual(c.lines, [
    'Talked to: Apple Inc. (3 apps), Cloudflare, Inc. (2), Google LLC (1)',
    'Safari: Apple Inc. (17.1.1.2:443), Google LLC (8.8.8.8:443), Cloudflare, Inc. (104.16.1.2:443)',
    'Mail: Apple Inc. (17.1.1.1:993), Cloudflare, Inc. (104.16.1.1:443)',
    'Music: Apple Inc. (17.1.1.3:443)',
    'Looking up stopped early.',
    'Only the busiest 150 addresses were looked up.',
    `Looked up with: ${SOURCES.join('; ')}.`,
  ]);
});

test('WHERE THEY WENT: owner precedence mirrors the engine; an unconfirmed hostname is labelled, a bare address stands alone', async () => {
  const { cluesFor, holderCompany } = await load();
  assert.strictEqual(holderCompany('GOOGLE - Google LLC'), 'Google LLC');
  assert.strictEqual(holderCompany('AKAMAI-ASN1 Akamai International B.V.'), 'Akamai International B.V.');
  assert.strictEqual(holderCompany('AMAZON-02'), 'AMAZON-02', 'a handle alone stays');
  assert.strictEqual(holderCompany('Hetzner Online GmbH'), 'Hetzner Online GmbH', 'no handle: the whole name');
  assert.strictEqual(holderCompany('X - '), 'X - ', 'nothing after the dash: the whole name');
  const [c] = cluesFor(group(app('App', [
    dst('1.1.1.1', 443, 9, who({ registrant: 'Registrant Ltd', hostname: 'one.example', hostname_confirmed: true })),
    dst('2.2.2.2', 443, 8, who({ hostname: 'host.example', hostname_confirmed: true })),
    dst('3.3.3.3', 443, 7, who({ hostname: 'claims-to-be.bank.example', hostname_confirmed: false })),
    dst('4.4.4.4', 443, 6, who({ unavailable: ['dns', 'owner', 'registry'] })),
    dst('2001:db8::1', 443, 5, null),
    dst('5.5.5.5', null, 4, null),
  ])));
  assert.strictEqual(c.lines[0], 'Talked to: Registrant Ltd (1 app), host.example (1)', 'an unverified hostname is never an owner');
  assert.strictEqual(c.lines[1], 'App: Registrant Ltd (1.1.1.1:443), host.example (2.2.2.2:443), '
    + 'claims-to-be.bank.example (unverified) (3.3.3.3:443), 4.4.4.4:443, [2001:db8::1]:443, 5.5.5.5');
});

test('WHERE THEY WENT: at most 8 places an app and 25 apps; top 5 owners; lookups off; no owners known', async () => {
  const { cluesFor } = await load();
  const many = Array.from({ length: 11 }, (_, i) => dst(`9.9.9.${i}`, 443, 20 - i, who({ as_name: `NET${i} - Owner ${i}` })));
  const [c] = cluesFor(group(app('Busy', many, { more: 4, not_stored: 2 })));
  assert.match(c.lines[1], /^Busy: Owner 0 \(9\.9\.9\.0:443\), .*Owner 7 \(9\.9\.9\.7:443\), and 9 more$/);
  assert.strictEqual(c.lines[0].split('), ').length, 5, 'five owners in the rollup');
  const apps = Array.from({ length: 27 }, (_, i) => app(`App${String(i).padStart(2, '0')}`, [dst('8.8.4.4', 53, 30 - i)]));
  const [d] = cluesFor(group(...apps));
  assert.strictEqual(d.lines[0], 'App00: 8.8.4.4:53', 'no owner known: no rollup line');
  assert.strictEqual(d.lines[24], 'App24: 8.8.4.4:53');
  assert.strictEqual(d.lines[25], 'And 2 more apps.');
  const [off] = cluesFor(group(app('Mail', [dst('17.1.1.1', 993, 3)], { lookup_sources: [] }),
    { module: 'connection_watch', code: 'network.connection_watch.watch_incomplete', data: { reasons: ['Looking up who runs each address was turned off.'] } }));
  assert.deepStrictEqual(off.lines, ['Mail: 17.1.1.1:993', 'Looking up who runs each address was turned off.', 'Not looked up (turned off).']);
  const [unknown] = cluesFor(group(app('unknown', [])));
  assert.strictEqual(unknown.lines[0], 'A program Reclaim City couldn’t name: no places listed');
});

test('WHERE THEY WENT: registry and DNS text is capped and stripped of control characters', async () => {
  const { cluesFor } = await load();
  const long = `Evil\u0007 Corp ${'x'.repeat(300)}`;
  const [c] = cluesFor(group(app('A', [dst('1.1.1.1', 443, 1, who({ registrant: long }))])));
  const name = c.lines[0].slice('Talked to: '.length).replace(/ \(1 app\)$/, '');
  assert.ok(name.length <= 80, `${name.length}`);
  assert.ok(name.endsWith('…'));
  assert.doesNotMatch(c.lines.join('\n'), /\u0007/);
});
