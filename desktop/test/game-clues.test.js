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
const group = (...watch) => ({ module: 'connection_watch', code: 'network.connection_watch.group', watch, incomplete: [] });
const gaps = (finding, incomplete) => ({ ...finding, incomplete });

test('WHERE THEY WENT: one clue, the rollup by apps, each app busiest first, the gaps and the sources', async () => {
  const { cluesFor, READING } = await load();
  const clues = cluesFor(gaps(group(
    app('Mail', [dst('17.1.1.1', 993, 3, APPLE), dst('104.16.1.1', 443, 1, CF)]),
    app('Safari', [dst('17.1.1.2', 443, 9, APPLE), dst('8.8.8.8', 443, 2, GOOGLE), dst('104.16.1.2', 443, 2, CF)]),
    app('Music', [dst('17.1.1.3', 443, 1, APPLE)]),
  ), ['Looking up stopped early.', 'Only the busiest 150 addresses were looked up.']));
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
  const [off] = cluesFor(gaps(group(app('Mail', [dst('17.1.1.1', 993, 3)], { lookup_sources: [] })),
    ['Looking up who runs each address was turned off.', 'The watch was stopped early, after 0.5 of 1 minute(s).']));
  assert.deepStrictEqual(off.lines, ['Mail: 17.1.1.1:993', 'The watch was stopped early, after 0.5 of 1 minute(s).', 'Not looked up (turned off).'],
    'turned off: said once');
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
  const [g] = cluesFor(gaps(group(app('A', [dst('1.1.1.1', 443, 1)], { lookup_sources: ['RIPE\u0000 NCC\u001b[31m'] })), ['Stopped\u0007 early.']));
  assert.deepStrictEqual(g.lines.slice(1), ['Stopped early.', 'Looked up with: RIPE NCC [31m.'], 'gaps and sources too');
});

// Network findings: direction, program, who, and one next step (engine `data.items`).
const lineText = (l) => (typeof l === 'string' ? l : l.text);
const SSH_ITEM = { direction: 'out', process: 'ssh', pid: 31674, ppid: 31627, proto: 'tcp', local_addr: '192.168.0.114', local_port: 49542,
  remote_addr: '87.5.113.252', remote_port: 64456, remote_scope: 'public', state: 'ESTABLISHED',
  command: 'ssh -T vast-tests bash /root/vast-run.sh', ssh_host: 'vast-tests' };
const UNCOMMON = (items, platform = 'darwin') => ({ title: 'Connections on uncommon ports (1)', severity: 'warning',
  code: 'security.network_connections_monitor.unusual_ports',
  description: 'We found 1 connection(s) using port numbers that are not typically used by standard apps:\nssh -> 87.5.113.252:64456',
  data: { check: 'unusual_ports', connections: ['ssh -> 87.5.113.252:64456'], items, platform },
  remediation: { title: 'Review active network connections', steps: [{ number: 3, title: 'Check connections on unusual ports', body: '…' }] } });

test('every next-step sentence and command template for network clues is in its walkthrough', async () => {
  const { NET_NEXT, NET_COMMANDS } = await load();
  for (const [k, n] of Object.entries(NET_NEXT)) {
    assert.ok(src(n.source).includes(norm(n.quote)), `${k}: its quote isn’t in ${n.source}`);
  }
  for (const [k, c] of Object.entries(NET_COMMANDS)) {
    const text = src(c.source);
    for (const cmd of [...c.darwin, ...c.linux]) assert.ok(text.includes(`\`${cmd}\``), `${k}: \`${cmd}\` isn’t in ${c.source}`);
    assert.ok(text.includes(norm(c.win32Quote)), `${k}: the Windows line isn’t in ${c.source}`);
  }
});

test('an outgoing SSH session: OUT, the program, its parent and command, the SSH settings match, and MINE as the next step', async () => {
  const { cluesFor } = await load();
  const clues = cluesFor(UNCOMMON([SSH_ITEM]));
  assert.deepStrictEqual(clues.map((c) => c.kind), ['conn', 'who', 'next'], 'no raw WHAT IT DOES text');
  const [conn, who, next] = clues.map((c) => ({ ...c, text: c.lines.map(lineText) }));
  assert.deepStrictEqual(conn.text, [
    'Your computer is connecting OUT to 87.5.113.252, port 64456.',
    'Program: ssh (PID 31674), started by PID 31627',
    'ssh -T vast-tests bash /root/vast-run.sh',
    '192.168.0.114:49542 → 87.5.113.252:64456 · ESTABLISHED',
  ]);
  assert.strictEqual(conn.lines[2].code, true, 'the command line is code');
  assert.deepStrictEqual(who.text, ['87.5.113.252: this matches “vast-tests” in your SSH settings (~/.ssh/config).']);
  assert.match(next.text[0], /^If you started this SSH session, it’s yours: tag it MINE\./);
  assert.deepStrictEqual(next.text.slice(2), ['ps -p 31674 -o pid,ppid,command', 'lsof -i :64456']);
  assert.ok(next.move, 'the next step offers the steps too');
  for (const c of clues) assert.strictEqual(c.reading, null, 'no how-to-read filler');
});

test('an incoming connection says IN and the local port; a public address says a watch can look it up', async () => {
  const { cluesFor } = await load();
  const inbound = { direction: 'in', process: 'sshd', pid: 901, proto: 'tcp', local_addr: '192.168.0.114', local_port: 2222,
    remote_addr: '203.0.113.9', remote_port: 51234, remote_scope: 'public', state: 'ESTABLISHED' };
  const [conn, who, next] = cluesFor(UNCOMMON([inbound], 'linux'));
  assert.strictEqual(lineText(conn.lines[0]), 'Something is connecting IN to your computer on port 2222, from 203.0.113.9.');
  assert.strictEqual(lineText(conn.lines[1]), 'Program: sshd (PID 901)');
  assert.strictEqual(lineText(conn.lines[2]), '203.0.113.9:51234 → 192.168.0.114:2222 · ESTABLISHED');
  assert.deepStrictEqual(who.lines, ['203.0.113.9: an address on the internet.', 'A checkup doesn’t look up who runs an address. A connection watch can.']);
  assert.match(next.lines[0], /^Another computer started this connection\./);
  assert.deepStrictEqual(next.lines.slice(2).map(lineText), ['ps -p 901 -o args=', 'ss -tnap'], 'Linux commands');
  const win = cluesFor(UNCOMMON([{ ...inbound, pid: null }], 'win32')).find((c) => c.kind === 'next');
  assert.match(lineText(win.lines[2]), /Resource Monitor/);
});

test('listening ports: the port, who can reach it, the program, and how to check it', async () => {
  const { cluesFor } = await load();
  const f = { title: 'A database service is open to your network (1 found)', severity: 'warning', code: 'security.open_ports_scan.exposed_risky_ports',
    description: 'raw', data: { check: 'exposed_risky_ports', platform: 'darwin',
      items: [{ port: 3306, address: '*', process: 'mysqld', pid: 321, service: 'MySQL', reach: 'network' }] } };
  const [listen, next] = cluesFor(f);
  assert.strictEqual(listen.kind, 'listen');
  assert.deepStrictEqual(listen.lines, ['Listening on port 3306 for other devices on your network (*).', 'Program: mysqld (PID 321) · port 3306 is usually MySQL']);
  assert.strictEqual(next.kind, 'next');
  assert.deepStrictEqual(next.lines.slice(2).map(lineText), ['lsof -i :3306', 'ps -p 321 -o pid,ppid,command']);
});

test('a finding with a walkthrough gets a plain next step; network text from the engine is cut and cleaned', async () => {
  const { cluesFor } = await load();
  const f = { title: 't', description: 'Plain words.', data: { program: '/opt/x' },
    remediation: { title: 'Review it', steps: [{ number: 1, title: 'Look at the file', body: '' }] } };
  const next = cluesFor(f).pop();
  assert.deepStrictEqual(next, { kind: 'next', label: 'WHAT TO DO NEXT', reading: null, move: true,
    lines: ['If you recognise it, it’s yours: tag it MINE.', 'If you don’t, start with: Look at the file.'] });
  const [conn] = cluesFor(UNCOMMON([{ ...SSH_ITEM, process: 'a\u0007b', command: 'x'.repeat(900) }]));
  assert.strictEqual(lineText(conn.lines[1]), 'Program: a b (PID 31674), started by PID 31627');
  assert.ok(lineText(conn.lines[2]).length <= 300);
});

test('Scout: a connection’s own evidence as the clue; silent when it agrees and has nothing to add', async () => {
  const { scoutRead } = await load();
  const sig = (finding, severity = 'warning') => ({ kind: 'real', severity, finding, marked: false });
  assert.match(scoutRead(sig(UNCOMMON([SSH_ITEM])), 'mine'), /One clue: it matches “vast-tests” in your SSH settings\./);
  assert.match(scoutRead(sig(UNCOMMON([{ ...SSH_ITEM, ssh_host: undefined, direction: 'in' }])), 'closer'), /another computer connected in/);
  assert.strictEqual(scoutRead(sig({}), 'closer'), '', 'nothing to add');
});
