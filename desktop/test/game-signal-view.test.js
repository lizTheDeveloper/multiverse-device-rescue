const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (f) => `<i data-scout="${f}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/signal.js')),
  ...(await import('../renderer/game/clues.js')),
  ...(await import('../renderer/game/views/training.js')),
});
const FINDING = { title: 'Helper', description: 'Starts at login.', data: { program: '/tmp/x' }, made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] };
const real = (extra = {}) => ({ id: 'm|c|program=/tmp/x', kind: 'real', severity: 'critical', title: 'Helper', districtId: 'gatehouse',
  finding: FINDING, missionId: 'm|c|program=/tmp/x', fixable: true, marked: false, stale: false, changed: false, tag: null, ...extra });
const DRILL = { id: 'x', district: 'gatehouse', severity: 'warning', title: 'Practice thing', setup: 'Practice setup: you use it.',
  clues: { maker: null, path: '/tmp/y', what: 'Runs.', when: null }, answer: 'threat', why: 'Because.' };
const drillSig = { id: 'drill:x', kind: 'drill', severity: 'warning', title: DRILL.title, districtId: 'gatehouse', drill: DRILL, missionId: null, tag: null };
async function panel(over = {}) {
  const v = await views();
  const signal = over.signal || real();
  const clues = signal.kind === 'drill' ? v.drillClues(signal.drill) : signal.kind === 'real' ? v.cluesFor(signal.finding) : [];
  return v.renderSignalPanel({ signal, districtName: 'The Gatehouse', clues, opened: [], tagged: null, right: false, read: '', points: 0,
    scout, mineHtml: '', range: null, ...over });
}

test('clues are locked until SCAN CLUE, then show with their how-to-read line', async () => {
  const shut = await panel();
  assert.match(shut, /role="region" aria-labelledby="sig-title"/);
  assert.match(shut, /CRITICAL[\s\S]*The Gatehouse[\s\S]*id="sig-title"[^>]*>Helper/);
  for (const k of ['maker', 'where', 'what']) assert.match(shut, new RegExp(`data-act="clue:${k}"`));
  assert.doesNotMatch(shut, /How to read this/);
  assert.match(shut, /data-act="tag:mine"[\s\S]*data-act="tag:closer"[\s\S]*data-act="tag:threat"/);
  assert.match(shut, /They change nothing on your computer/);
  const open = await panel({ opened: ['maker', 'where'] });
  assert.match(open, /WHO MADE IT[\s\S]*Unknown maker, not verified \(unsigned\)[\s\S]*How to read this:<\/b> Not verified/);
  assert.match(open, /WHERE IT LIVES[\s\S]*\/tmp\/x[\s\S]*temporary folder/);
  assert.match(open, /data-act="clue:what"/);
});

test('engine text is escaped everywhere in the panel', async () => {
  const evil = { title: EVIL, description: EVIL, data: { program: `/tmp/${EVIL}` }, made_by: [{ name: EVIL, verified: false, how: EVIL }] };
  const html = await panel({ signal: real({ title: EVIL, finding: evil }), opened: ['maker', 'where', 'what'], tagged: 'threat', read: EVIL });
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x/);
});

test('a couldn’t-check signal can only be NOTED, and links the lesson', async () => {
  const html = await panel({ signal: { id: 'couldnt|m', kind: 'couldnt', severity: 'couldnt', title: 'A check couldn’t run here',
    description: 'Needs permission.', districtId: 'wires', finding: null, missionId: null, tag: null } });
  assert.match(html, /COULDN’T CHECK/);
  assert.match(html, /Needs permission\./);
  assert.match(html, /That doesn’t mean it’s safe/);
  assert.match(html, /data-act="tag:noted"[^>]*>NOTED/);
  assert.match(html, /data-go="lesson:couldnt-check"/);
  assert.doesNotMatch(html, /data-act="tag:(mine|threat|closer)"|SCAN CLUE/);
});

test('a drill: stamped, practice-only, its setup shown, and never the real “It’s mine” step', async () => {
  const html = await panel({ signal: drillSig, mineHtml: '<b>MARK</b>' });
  assert.match(html, /class="sig-panel drill"/);
  assert.match(html, /DRILL<\/span> Practice\. This isn’t on your computer\./);
  assert.match(html, /Practice setup: you use it\./);
  assert.match(html, /data-act="clue:where"/);
  assert.doesNotMatch(html, /data-act="clue:maker"/, 'no maker in this drill, so no maker clue');
  const after = await panel({ signal: drillSig, tagged: 'mine', right: false, read: 'Not this time, and it costs you nothing. The tell: Because.', mineHtml: '<b>MARK</b>' });
  assert.doesNotMatch(after, /<b>MARK<\/b>/);
  assert.match(after, /The tell: Because\./);
  assert.match(after, /aria-disabled="true" disabled/, 'a drill takes one answer, and the keyboard cannot re-answer');
  assert.doesNotMatch(after, /RESPONSE XP/, 'a wrong answer scores nothing');
});

test('after tagging: Scout’s read, the points, and each tag’s next step', async () => {
  const mine = await panel({ tagged: 'mine', read: 'The checkup marked this critical.', points: 20, mineHtml: '<div data-mark-card>MARK IT</div>' });
  assert.match(mine, /The checkup marked this critical\./);
  assert.match(mine, /\+20 INCIDENT RESPONSE XP for looking at the clues/);
  assert.match(mine, /OPTIONAL: TELL RECLAIM CITY TOO[\s\S]*It asks first, and you can undo it\.[\s\S]*MARK IT/);
  assert.match(mine, /data-act="tag:mine" aria-pressed="true"/);
  const threat = await panel({ tagged: 'threat', read: 'r' });
  assert.match(threat, /ON YOUR THREAT BOARD[\s\S]*data-go="mission:m\|c\|program=\/tmp\/x"[^>]*>SEE THE FIX ▶/);
  assert.doesNotMatch(threat, /MARK IT/);
  assert.doesNotMatch(threat, /RESPONSE XP/);
  assert.match(await panel({ tagged: 'closer', read: 'r' }), /It stays in your queue/);
});

test('points show as soon as clues are looked at, before any tag; a drill’s only after its answer', async () => {
  const looked = await panel({ opened: ['maker', 'where', 'what'], points: 15 });
  assert.match(looked, /\+15 INCIDENT RESPONSE XP for looking at the clues/);
  assert.ok(looked.indexOf('RESPONSE XP') < looked.indexOf('YOUR CALL'), 'the points sit with the clues');
  assert.doesNotMatch(await panel({ opened: ['maker'], points: 0 }), /RESPONSE XP/);
  assert.doesNotMatch(await panel({ signal: drillSig, points: 15 }), /RESPONSE XP/, 'a drill pays on its answer');
});

test('network clues: code lines are copyable code, no how-to-read filler, and the next step offers the steps', async () => {
  const v = await views();
  const item = { direction: 'out', process: 'ssh', pid: 31674, ppid: 31627, local_addr: '192.168.0.114', local_port: 49542,
    remote_addr: '87.5.113.252', remote_port: 64456, remote_scope: 'public', state: 'ESTABLISHED', command: `ssh ${EVIL}`, ssh_host: 'vast-tests' };
  const finding = { title: 'Connections on uncommon ports (1)', description: 'raw', data: { check: 'unusual_ports', items: [item], platform: 'darwin' } };
  const signal = real({ severity: 'warning', title: finding.title, finding, missionId: 'n|u', fixable: false });
  const clues = v.cluesFor(finding);
  const html = await panel({ signal, clues, opened: clues.map((c) => c.kind) });
  assert.match(html, /THE CONNECTION[\s\S]*Your computer is connecting OUT to 87\.5\.113\.252, port 64456\./);
  assert.match(html, /<code class="clue-line code">ps -p 31674 -o pid,ppid,command<\/code>/);
  assert.match(html, /WHAT TO DO NEXT[\s\S]*data-go="mission:n\|u"[^>]*>SEE THE STEPS ▶/);
  assert.strictEqual((html.match(/data-go="mission:/g) || []).length, 1, 'offered once, in the clue');
  assert.doesNotMatch(html, /How to read this/);
  assert.ok(!html.includes('<img src=x'), 'the command line is escaped');
});

test('Scout stays out of it when there’s nothing to say', async () => {
  const html = await panel({ tagged: 'closer', read: '' });
  assert.doesNotMatch(html, /class="say"/);
});

test('the steps are one click away before any call, and offered once after THREAT', async () => {
  const before = await panel({});
  assert.match(before, /data-go="mission:m\|c\|program=\/tmp\/x"[^>]*>SEE THE FIX ▶[\s\S]*BACK TO THE DECK/);
  const threat = await panel({ tagged: 'threat', read: 'r' });
  assert.strictEqual((threat.match(/data-go="mission:/g) || []).length, 1);
  assert.doesNotMatch(await panel({ signal: drillSig }), /data-go="mission:/);
});

// Review Focus 2.
test('a finding with no clues says so, and can still be tagged', async () => {
  const html = await panel({ signal: real({ finding: { title: 'x', description: '', data: {} } }) });
  assert.match(html, /recorded no clues for this one/);
  assert.match(html, /data-act="tag:threat"/);
});

test('marked, changed since marking, and changed since tagging each say so', async () => {
  assert.match(await panel({ signal: real({ marked: true, tag: 'mine' }) }), /MARKED<\/span> You told Reclaim City this is yours\. It stays listed\./);
  assert.match(await panel({ signal: real({ stale: true }) }), /CHANGED SINCE YOU MARKED IT/);
  assert.match(await panel({ signal: real({ changed: true }) }), /CHANGED SINCE YOU TAGGED IT/);
});

test('the drill range: getting ready, nothing loaded, and a drill with next and back', async () => {
  const v = await views();
  assert.match(v.renderRange({ loaded: false, panelHtml: '', hasCity: false }), /THE DRILL RANGE[\s\S]*Getting the drills ready/);
  const empty = v.renderRange({ loaded: true, panelHtml: '', hasCity: true });
  assert.match(empty, /The drills couldn’t load/);
  assert.match(empty, /data-act="leave-range">BACK TO THE DECK/);
  const html = v.renderRange({ loaded: true, panelHtml: await panel({ signal: drillSig, range: { hasCity: false } }), hasCity: false });
  assert.match(html, /None of this is on your computer/);
  assert.match(html, /data-act="next-drill"[^>]*>NEXT DRILL ▶/);
  assert.match(html, /data-act="leave-range"[^>]*>BACK TO THE TRAINING GROUNDS/);
  assert.doesNotMatch(html, /data-act="close-signal"/);
});

test('the Training Grounds offer the DRILL RANGE, with or without a scan', async () => {
  const v = await views();
  const html = v.renderTraining({ ordered: { recommended: [], other: [] }, progress: { lessons: {} },
    scan: { running: false, index: 0, total: 0, error: null }, scout, lessonsLoaded: true });
  assert.match(html, /data-go="range"[^>]*>DRILL RANGE ▶/);
  assert.match(html, /Nothing in the range touches your computer/);
});

test('test_clue_escapes_registry_text: a looked-up name is shown as text in WHERE THEY WENT', async () => {
  const v = await views();
  const who = { hostname: EVIL, hostname_confirmed: false, as_name: null, registrant: EVIL, unavailable: [] };
  const note = { module: 'connection_watch', code: 'network.connection_watch.watch_summary', title: 'x', severity: 'info',
    data: { target: EVIL, destinations: [{ address: '1.2.3.4', port: 443, protocol: 'tcp', snapshots: 1, who }], lookup_sources: [EVIL] } };
  const finding = { module: 'connection_watch', code: 'network.connection_watch.group', watch: [note] };
  const signal = real({ id: 'connection_watch|group', severity: 'info', title: 'Connection watch: 1 app talked to 1 place', finding, missionId: null });
  const html = await panel({ signal, clues: v.cluesFor(finding), opened: ['went'] });
  assert.match(html, /WHERE THEY WENT/);
  assert.ok(!html.includes(EVIL), 'nothing from a registry or DNS is markup');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt;'));
});

test('WHERE THEY WENT: an unconfirmed hostname is never the owner, and a confirmed one is shown as text', async () => {
  const v = await views();
  const at = (address, who) => ({ address, port: 443, protocol: 'tcp', snapshots: 1, who });
  const note = { module: 'connection_watch', code: 'network.connection_watch.watch_summary', title: 'x', severity: 'info',
    data: { target: 'App', lookup_sources: [], destinations: [
      at('1.1.1.1', { hostname: EVIL, hostname_confirmed: false, as_name: null, registrant: null, unavailable: [] }),
      at('2.2.2.2', { hostname: `ok${EVIL}`, hostname_confirmed: true, as_name: null, registrant: null, unavailable: [] }),
    ] } };
  const finding = { module: 'connection_watch', code: 'network.connection_watch.group', watch: [note], incomplete: [] };
  const [clue] = v.cluesFor(finding);
  assert.strictEqual(clue.lines[0], `Talked to: ok${EVIL} (1 app)`, 'only the confirmed hostname is an owner');
  assert.strictEqual(clue.lines[1], `App: ${EVIL} (unverified) (1.1.1.1:443), ok${EVIL} (2.2.2.2:443)`);
  const signal = real({ id: 'connection_watch|group', severity: 'info', title: 'Connection watch: 1 app talked to 2 places', finding, missionId: null });
  const html = await panel({ signal, clues: [clue], opened: ['went'] });
  assert.ok(!html.includes(EVIL), 'neither hostname is markup');
  assert.ok(html.includes('&lt;img src=x onerror=alert(1)&gt; (unverified) (1.1.1.1:443)'));
  assert.ok(html.includes('ok&lt;img src=x onerror=alert(1)&gt; (2.2.2.2:443)'));
});
