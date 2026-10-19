// The command center against a stubbed window (no DOM library), like
// game-controller.test.js: a frame whose innerHTML the tests read, and clicks
// delivered as elements with attributes.
const test = require('node:test');
const assert = require('node:assert');
const { savedProfile, savedAsV3 } = require('./profile-read.js');

const STORE = 'device-rescue.game.v1';
const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };
const tick = () => new Promise((r) => setTimeout(r, 0));
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}: what it is.`, severity, category: 'security', data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const drill = (id, district, answer) => ({ id, district, severity: 'warning', modules: [], title: `Drill ${id}`, setup: '',
  clues: { maker: { name: 'Unknown maker', verified: false, how: 'unsigned' }, path: '/tmp/d', what: 'Practice only.', when: null },
  answer, why: `Why ${id}.`, sources: [] });
const DRILLS = [drill('gate-1', 'gatehouse', 'threat'), drill('gate-2', 'gatehouse', 'mine'), drill('junk-1', 'junkyard', 'closer')];
const DOC = scan(mod('a_mod', [
  f('Unsigned helper', 'critical', { plist: '/Users/ann/Library/LaunchAgents/x.plist', program: '/tmp/x' },
    { code: 'security.a_mod.unsigned', made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] }),
  f('Old note', 'info', { name: 'n' }),
]));
const queueOf = (html, end = 'deck-city') => html.split('INCOMING SIGNALS')[1].split(end)[0];

function stub(recheckDocs = []) {
  const listeners = [];
  const keyListeners = [];
  const calls = { startCheckup: 0, recheck: [], showList: 0, leaveGame: 0 };
  const focused = [];
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); if (type === 'keydown') keyListeners.push(fn); },
    querySelector: (sel) => {
      const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
      if (m && frame.innerHTML.includes(`${m[1]}="${m[2]}"`)) return { focus: () => focused.push(sel) };
      return null;
    },
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const hooks = {};
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: (_r, _a, h) => { hooks.fix = h; }, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: (_r, _a, h) => { hooks.mark = h; },
      markControlsHtml: (finding) => (finding && finding.markable ? '<div data-mark-card>MARK IT</div>' : '') },
    RescueHost: { showList() { calls.showList += 1; }, docChanged: () => true, wantsSafety: () => false,
      startCheckup() { calls.startCheckup += 1; }, scanTips: async () => [], leaveGame() { calls.leaveGame += 1; } },
    rescue: { recheckModule: async (name) => {
      calls.recheck.push(name);
      const doc = recheckDocs.shift();
      return { ok: true, doc, module: doc.modules.find((m) => m.name === name) };
    } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const focusOn = (attrs) => { shadow.activeElement = attrs ? { getAttribute: (k) => (k in attrs ? attrs[k] : null) } : null; };
  // A key press on the frame; `inside` is what the target's closest() finds.
  const key = (k, inside = null) => {
    const ev = { key: k, target: { closest: () => inside }, prevented: false, preventDefault() { ev.prevented = true; } };
    keyListeners.forEach((fn) => fn(ev));
    return ev;
  };
  return { win, frame, hooks, calls, click, focused, focusOn, key };
}

async function deckSetup(doc, { storage = memStore(), situation = { id: 'unsure' }, recheckDocs = [], drills = DRILLS } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const t = stub(recheckDocs);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => drills });
  await tick();
  if (doc) ctl.show(doc, situation);
  return { ...t, ctl, storage, html: () => t.frame.innerHTML, saved: () => savedAsV3(storage) };
}
async function ids(doc) {
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  return findingsToCity(doc).districts.flatMap((d) => d.missions.map((m) => m.id));
}

test('the deck is the city’s home: queue, city, instruments, log, and its own top bar', async () => {
  const t = await deckSetup(DOC);
  const html = t.html();
  assert.match(html, /INCOMING SIGNALS/);
  assert.match(html, /data-act="investigate-next"/);
  assert.match(html, /aria-label="Your computer as a city"/);
  assert.match(html, /data-go="filter:gatehouse"/);
  assert.match(html, /City integrity/);
  assert.match(html, /OPS LOG/);
  assert.match(html, /LOW-PRIORITY SIGNALS \(1\)/);
  assert.match(html, /data-act="resweep"/);
  assert.doesNotMatch(html, /class="hud">/, 'the deck’s top bar replaces the HUD');
});

test('INVESTIGATE NEXT opens the most important signal; clues unlock one at a time and pay once per scan', async () => {
  const t = await deckSetup(DOC);
  t.click({ 'data-act': 'investigate-next' });
  assert.match(t.html(), /id="sig-title"[^>]*>Unsigned helper/);
  assert.match(t.html(), /data-act="clue:maker"/);
  assert.doesNotMatch(t.html(), /How to read this/);
  t.click({ 'data-act': 'clue:maker' });
  assert.match(t.html(), /WHO MADE IT[\s\S]*Unknown maker, not verified \(unsigned\)[\s\S]*How to read this/);
  assert.strictEqual(t.saved().deck.points, 5);
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'close-signal' });
  assert.doesNotMatch(t.html(), /id="sig-title"/);
  t.click({ 'data-act': 'investigate-next' });
  assert.match(t.html(), /Unknown maker, not verified/, 'an opened clue stays open this scan');
  t.click({ 'data-act': 'clue:maker' });
  assert.strictEqual(t.saved().deck.points, 5, 'the same clue pays once per scan');
  t.click({ 'data-act': 'clue:when' });
  assert.strictEqual(t.saved().deck.points, 5, 'a clue the evidence doesn’t support can’t be opened');
});

test('tagging after two clues pays a bonus once; tags are keyed by identity; re-tagging pays nothing more', async () => {
  const [id] = await ids(DOC);
  const t = await deckSetup(DOC);
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'clue:where' });
  t.click({ 'data-act': 'tag:threat' });
  const saved = t.saved();
  assert.strictEqual(saved.deck.points, 5 + 5 + 10);
  assert.strictEqual(saved.deck.tags[id].tag, 'threat');
  assert.ok(!JSON.stringify(saved.deck.tags).includes('Unsigned helper'), 'tags keep identities, not titles');
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(t.saved().deck.points, 20);
  assert.match(t.html(), /OPS LOG[\s\S]*THREAT: Unsigned helper/);
  assert.doesNotMatch(t.html(), /\bwrong\b/i);
});

test('THREAT goes to the threat board with its next move; LOOK CLOSER stays in the queue; neither touches the computer', async () => {
  const two = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }, { fixable: true }), f('B', 'warning', { plist: '/b' })]));
  const [ia, ib] = await ids(two);
  const t = await deckSetup(two);
  t.click({ 'data-go': `signal:${ia}` });
  t.click({ 'data-act': 'tag:threat' });
  assert.match(t.html(), /ON YOUR THREAT BOARD[\s\S]*data-go="mission:[^"]*"[^>]*>SEE THE FIX ▶/);
  t.click({ 'data-act': 'close-signal' });
  assert.match(t.html(), /THREAT BOARD \(1\)/);
  t.click({ 'data-go': `signal:${ib}` });
  t.click({ 'data-act': 'tag:closer' });
  t.click({ 'data-act': 'close-signal' });
  assert.match(queueOf(t.html(), 'THREAT BOARD'), /data-go="signal:[^"]*"[\s\S]*?LOOK CLOSER/);
  assert.deepStrictEqual(t.calls.recheck, [], 'tags never touch the computer');
});

test('MINE offers the real “It’s mine” step only for a finding that has one, and only as an option', async () => {
  const doc = scan(mod('a_mod', [f('Mine?', 'warning', { plist: '/m' }, { markable: { id: 'abcdef012345', kind: 'background_task' } }),
    f('Plain', 'warning', { plist: '/p' })]));
  const [im, ip] = await ids(doc);
  const t = await deckSetup(doc);
  t.click({ 'data-go': `signal:${im}` });
  t.click({ 'data-act': 'tag:mine' });
  assert.match(t.html(), /OPTIONAL: TELL RECLAIM CITY TOO[\s\S]*MARK IT/);
  t.click({ 'data-go': `signal:${ip}` });
  t.click({ 'data-act': 'tag:mine' });
  assert.doesNotMatch(t.html(), /MARK IT/);
  assert.deepStrictEqual(t.calls.recheck, [], 'nothing was marked: the person didn’t press it');
});

test('a couldn’t-check signal can only be NOTED, and links the lesson', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]), mod('broken', [], { status: 'error', error: 'Needs Full Disk Access.' })));
  t.click({ 'data-go': 'signal:couldnt|broken' });
  assert.match(t.html(), /Needs Full Disk Access\./);
  assert.match(t.html(), /data-act="tag:noted"/);
  assert.match(t.html(), /data-go="lesson:couldnt-check"/);
  assert.doesNotMatch(t.html(), /data-act="tag:(mine|threat|closer)"/);
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(t.saved().deck.tags['couldnt|broken'], undefined);
  t.click({ 'data-act': 'tag:noted' });
  assert.strictEqual(t.saved().deck.tags['couldnt|broken'].tag, 'noted');
  assert.match(t.html(), /That doesn’t mean it’s safe/);
});

test('clicking a district filters the queue to it; SHOW ALL brings back the rest', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('Gate thing', 'warning', { plist: '/a' })]),
    { ...mod('b_mod', [f('Wire thing', 'warning', { path: '/b' })]), category: 'network' }));
  t.click({ 'data-go': 'filter:wires' });
  assert.match(t.html(), /SHOWING THE WIRES/);
  assert.match(queueOf(t.html()), /Wire thing/);
  assert.doesNotMatch(queueOf(t.html()), /Gate thing/);
  assert.match(t.html(), /data-go="district:wires"/);
  t.click({ 'data-go': 'filter:all' });
  assert.match(queueOf(t.html()), /Gate thing/);
});

// Review Focus 5.
test('low-priority signals stay folded; THESE ARE ALL FINE sorts every one and pays nothing', async () => {
  const t = await deckSetup(scan(mod('a_mod', Array.from({ length: 120 }, (_, i) => f(`Note ${i}`, 'info', { name: `n${i}` })))));
  assert.match(t.html(), /LOW-PRIORITY SIGNALS \(120\)/);
  assert.doesNotMatch(t.html(), /Note 7\b/, 'folded');
  t.click({ 'data-act': 'toggle-low' });
  assert.strictEqual((t.html().match(/data-go="signal:a_mod/g) || []).length, 50);
  assert.match(t.html(), /And 70 more\. THESE ARE ALL FINE sorts all 120, including the ones not shown\./);
  t.click({ 'data-act': 'batch-fine' });
  const saved = t.saved();
  assert.strictEqual(Object.keys(saved.deck.tags).length, 120);
  assert.strictEqual(saved.deck.points, 0);
  assert.doesNotMatch(t.html(), /LOW-PRIORITY SIGNALS/);
  assert.match(t.html(), /<b>120<\/b> <small>SORTED<\/small>/);
});

test('marked by the person: pre-tagged MINE with a MARKED badge, still visible; changed since: back in the queue', async () => {
  const marked = f('Mine', 'info', { plist: '/m', marked_by_user: true, original_severity: 'warning', known_item_id: 'k1' });
  const stale = f('Stale', 'info', { plist: '/s', marked_by_user: true, mark_stale: true, original_severity: 'warning', known_item_id: 'k2' });
  const t = await deckSetup(scan(mod('a_mod', [marked, stale])));
  const queue = queueOf(t.html(), 'KNOWN AND NOTED');
  assert.doesNotMatch(queue, />Mine</);
  assert.match(queue, /CHANGED SINCE YOU MARKED IT[\s\S]*Stale/);
  assert.match(t.html(), /KNOWN AND NOTED \(1\)[\s\S]*MARKED[\s\S]*>Mine</);
  assert.match(t.html(), /<b>1<\/b> <small>SORTED<\/small>/);
});

test('monitoring checks never become signals, and nothing about them is stored', async () => {
  const t = await deckSetup(scan(mod('stalkerware_scan', [f('No monitoring apps found', 'info')]), mod('a_mod', [f('Other', 'info', { name: 'o' })])));
  assert.doesNotMatch(t.html(), /No monitoring apps found/);
  t.click({ 'data-act': 'toggle-low' });
  t.click({ 'data-act': 'batch-fine' });
  assert.doesNotMatch(JSON.stringify(savedProfile(t.storage)), /stalkerware|monitoringSeen/);
});

test('drills join the queue: about one per four real signals, from the same districts, stamped DRILL', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const t = await deckSetup(five);
  const drills = queueOf(t.html()).match(/data-go="signal:drill:[^"]+"/g) || [];
  assert.strictEqual(drills.length, 2);
  assert.ok(drills.every((d) => /gate-/.test(d)), 'only drills from the districts in the queue');
});

test('a drill: right pays drill points, wrong pays nothing and gives the tell; neither touches integrity or the bars', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const t = await deckSetup(five);
  const integrity = () => t.html().match(/City integrity[^<]*/)[0];
  const before = integrity();
  t.click({ 'data-go': 'signal:drill:gate-1' });
  assert.match(t.html(), /DRILL[\s\S]*Practice\. This isn’t on your computer\./);
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'clue:where' });
  assert.strictEqual(t.saved().deck.points, 0, 'drill clues pay nothing on their own');
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(t.saved().deck.points, 15 + 5);
  assert.deepStrictEqual(t.saved().deck.drills, { right: 1, tried: 1 });
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(t.saved().deck.drills.tried, 1, 'a drill takes one answer');
  t.click({ 'data-act': 'close-signal' });
  assert.doesNotMatch(t.html(), /signal:drill:gate-1/, 'an answered drill leaves the queue');
  t.click({ 'data-go': 'signal:drill:gate-2' });
  t.click({ 'data-act': 'tag:threat' });
  assert.match(t.html(), /The tell: Why gate-2\./);
  assert.strictEqual(t.saved().deck.points, 20);
  t.click({ 'data-act': 'close-signal' });
  assert.strictEqual(integrity(), before);
  assert.match(t.html(), /<b>0<\/b> <small>SORTED<\/small>/);
  assert.deepStrictEqual(t.saved().deck.tags, {}, 'drills are never tagged in the store');
});

test('a rank-up is a moment and a log entry', async () => {
  const { emptyDeck } = await import('../renderer/game/progress.js');
  const storage = memStore();
  storage.setItem(STORE, JSON.stringify({ version: 3, missions: {}, lessons: {}, deck: { ...emptyDeck(), points: 95 } }));
  const t = await deckSetup(DOC, { storage });
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'clue:maker' });
  assert.match(t.html(), /class="moment moment-rank" role="status"><b>RANK UP<\/b> You’re now SIGNAL ANALYST/);
  assert.match(t.html(), /RANK UP<\/span> SIGNAL ANALYST/);
  t.click({ 'data-act': 'clue:where' });
  assert.doesNotMatch(t.html(), /class="moment/, 'a moment shows once');
});

test('zero findings: a clear board and the DRILL RANGE', async () => {
  const t = await deckSetup(scan(mod('a_mod', [])));
  assert.match(t.html(), /CLEAR BOARD/);
  assert.match(t.html(), /data-go="range"/);
  assert.doesNotMatch(t.html(), /data-act="investigate-next"/);
});

// Review Focus 1.
test('every check errored: no reading, never a clear board, and the couldn’t-check signals', async () => {
  const t = await deckSetup(scan(mod('a', [], { status: 'error', error: 'x' }),
    { ...mod('b', [], { supported: false, unsupported_reason: 'Mac only' }), category: 'network' }));
  const html = t.html();
  assert.match(html, /NOTHING COULD BE CHECKED/);
  assert.match(html, /City integrity: no reading/);
  assert.doesNotMatch(html, /CLEAR BOARD|100%/);
  assert.match(html, /data-go="signal:couldnt\|a"/);
  assert.doesNotMatch(html, /signal:drill:/, 'no drills without real signals');
});

test('redraws on the deck keep keyboard focus', async () => {
  const t = await deckSetup(DOC);
  t.focusOn({ 'data-act': 'toggle-low' });
  t.click({ 'data-act': 'toggle-low' });
  assert.deepStrictEqual(t.focused, ['[data-act="toggle-low"]']);
});

// Task 7 review: a drill takes exactly one answer, even if it's opened again.
test('an answered drill ignores a second answer, even after it is opened again', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const t = await deckSetup(five);
  t.click({ 'data-go': 'signal:drill:gate-2' });
  t.click({ 'data-act': 'tag:threat' });
  assert.deepStrictEqual(t.saved().deck.drills, { right: 0, tried: 1 });
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'close-signal' });
  t.click({ 'data-go': 'signal:drill:gate-2' });
  assert.match(t.html(), /The tell: Why gate-2\./, 'reopened, it shows the answer already given');
  t.click({ 'data-act': 'tag:mine' });
  assert.deepStrictEqual(t.saved().deck.drills, { right: 0, tried: 1 }, 'no second answer');
  assert.strictEqual(t.saved().deck.points, 0, 'no second score');
  assert.match(t.html(), /data-act="tag:threat" aria-pressed="true"/, 'the first answer stands');
});

// Task 6 review: the known pile's <details> stays open across redraws.
test('the KNOWN AND NOTED pile stays open across redraws', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('Mine', 'info', { plist: '/m', marked_by_user: true, original_severity: 'warning', known_item_id: 'k1' }),
    f('Other', 'info', { name: 'o' })])));
  const inner = t.frame.querySelector;
  const opened = [];
  t.frame.querySelector = (sel) => {
    if (sel === 'details.known') {
      if (!t.html().includes('class="panel known"')) return null;
      const el = { open: opened.length === 0 };
      opened.push(el);
      return el;
    }
    return inner(sel);
  };
  t.click({ 'data-act': 'toggle-low' });
  assert.strictEqual(opened.length >= 2, true, 'the pile was read before the redraw and found after it');
  assert.strictEqual(opened[opened.length - 1].open, true, 'and opened again');
});

// Task 7 review: after a tag, focus lands on Scout's read.
test('after a tag, focus moves to Scout’s read (real signals and drills)', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const [id] = await ids(five);
  const t = await deckSetup(five);
  const inner = t.frame.querySelector;
  const reads = [];
  t.frame.querySelector = (sel) => {
    if (sel === '.sig-panel .say') {
      if (!/class="sig-panel[\s\S]*class="say"/.test(t.html())) return null;
      const el = { attrs: {}, focused: false, setAttribute(k, v) { this.attrs[k] = v; }, focus() { this.focused = true; } };
      reads.push(el);
      return el;
    }
    return inner(sel);
  };
  t.click({ 'data-go': `signal:${id}` });
  assert.strictEqual(reads.length, 0, 'no read before a tag');
  t.click({ 'data-act': 'tag:closer' });
  assert.strictEqual(reads.length, 1);
  assert.deepStrictEqual([reads[0].focused, reads[0].attrs.tabindex], [true, '-1']);
  t.click({ 'data-go': 'signal:drill:gate-1' });
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(reads.length, 2);
  assert.strictEqual(reads[1].focused, true);
});

test('RE-SWEEP runs the same game checkup, and only once at a time', async () => {
  const t = await deckSetup(DOC);
  assert.match(t.html(), /OPS LOG[\s\S]*SWEEP<\/span> \d+ checks?:/);
  t.click({ 'data-act': 'resweep' });
  assert.strictEqual(t.calls.startCheckup, 1);
  t.ctl.showBoss();
  t.click({ 'data-act': 'resweep' });
  assert.strictEqual(t.calls.startCheckup, 1, 'not while a checkup runs');
});

test('a re-sweep: tags carry over, a gone finding is NO LONGER SEEN with no points, and isn’t CONFIRMED', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }), f('B', 'warning', { plist: '/b' })]));
  const [ia, ib] = await ids(before);
  const t = await deckSetup(before);
  t.click({ 'data-go': `signal:${ia}` }); t.click({ 'data-act': 'tag:threat' });
  t.click({ 'data-go': `signal:${ib}` }); t.click({ 'data-act': 'tag:mine' });
  const points = t.saved().deck.points;
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })])), { id: 'unsure' });
  const saved = t.saved();
  assert.strictEqual(saved.deck.tags[ia].tag, 'threat', 'carried over by identity');
  assert.strictEqual(saved.deck.tags[ib], undefined);
  assert.strictEqual(saved.deck.points, points, 'gone is not a fix: no points');
  assert.deepStrictEqual(saved.deck.confirmed, {});
  assert.strictEqual(saved.deck.sweeps.length, 2);
  assert.ok(saved.deck.sweeps.every((w) => Object.keys(w).every((k) => k === 'at' || typeof w[k] === 'number')), 'dates and counts only');
  assert.match(t.html(), /NO LONGER SEEN<\/span> B/);
  assert.match(t.html(), /<b>0<\/b> <small>CONFIRMED<\/small>/);
  assert.match(t.html(), /City integrity 0%, the same as last sweep\./);
});

test('the same scan shown twice is one sweep', async () => {
  const t = await deckSetup(DOC);
  t.click({ 'data-act': 'list' });
  t.ctl.show(DOC, { id: 'unsure' });
  assert.strictEqual(t.saved().deck.sweeps.length, 1);
});

test('a re-check that proves a fix is CONFIRMED, secures the district, and pays once, ever', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }, { fixable: true })]));
  const after = scan(mod('a_mod', []));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [after, before, after] });
  t.click({ 'data-go': `mission:${ia}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'a_mod', result: { quarantine_id: 'q' }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.match(t.html(), /RECLAIMED/);
  let saved = t.saved();
  assert.strictEqual(saved.deck.points, 50);
  assert.ok(saved.deck.confirmed[ia]);
  t.click({ 'data-go': 'map' });
  assert.match(t.html(), /<b>1<\/b> <small>CONFIRMED<\/small>/);
  assert.match(t.html(), /CONFIRMED<\/span> A/);
  assert.match(t.html(), /class="moment moment-secured" role="status"><b>DISTRICT SECURED<\/b>/);
  assert.match(t.html(), /SECURED<\/span> The Gatehouse/);
  // Undo puts it back: no longer confirmed. Fixing it again is confirmed again, and pays nothing more.
  t.hooks.fix.onResult({ kind: 'undo', module: 'a_mod', result: { restored: true }, described: { restored: true } });
  await tick(); await tick();
  assert.deepStrictEqual(t.saved().deck.confirmed, {});
  t.click({ 'data-go': `mission:${ia}` });
  t.hooks.fix.onResult({ kind: 'fix', module: 'a_mod', result: { quarantine_id: 'q2' }, described: { tone: 'success' } });
  await tick(); await tick();
  saved = t.saved();
  assert.strictEqual(saved.deck.points, 50);
  assert.ok(saved.deck.confirmed[ia]);
});

test('a clean sweep: the re-sweep that clears the board gets the moment and the bonus; the next clean one doesn’t', async () => {
  const t = await deckSetup(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })])));
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [])), { id: 'unsure' });
  assert.match(t.html(), /class="moment moment-clean" role="status"><b>CLEAN SWEEP<\/b>/);
  assert.match(t.html(), /CLEAN SWEEP<\/span>/);
  assert.strictEqual(t.saved().deck.points, 40);
  t.click({ 'data-go': 'map' });
  assert.doesNotMatch(t.html(), /class="moment/, 'a moment shows once');
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [])), { id: 'unsure' });
  assert.strictEqual(t.saved().deck.points, 40);
});

test('the DRILL RANGE runs without a scan, from the Training Grounds', async () => {
  const t = await deckSetup(null);
  t.ctl.showTraining({ id: 'unsure', title: 'Not sure' });
  assert.match(t.html(), /data-go="range"/);
  t.click({ 'data-go': 'range' });
  assert.match(t.html(), /THE DRILL RANGE/);
  assert.match(t.html(), /data-act="next-drill"/);
  const title = () => /id="sig-title"[^>]*>([^<]+)/.exec(t.html())[1];
  const first = title();
  t.click({ 'data-act': 'tag:closer' });
  assert.match(t.html(), /The tell:|Right\./);
  t.click({ 'data-act': 'next-drill' });
  assert.notStrictEqual(title(), first);
  t.click({ 'data-act': 'leave-range' });
  assert.match(t.html(), /THE TRAINING GROUNDS/);
});

test('the DRILL RANGE from a clear board, and back to the deck', async () => {
  const t = await deckSetup(scan(mod('a_mod', [])));
  t.click({ 'data-go': 'range' });
  assert.match(t.html(), /THE DRILL RANGE[\s\S]*BACK TO THE DECK/);
  t.click({ 'data-act': 'leave-range' });
  assert.match(t.html(), /INCOMING SIGNALS/);
});

test('a re-check that closes the gate stops the deck: nothing is scored', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [scan(mod('a_mod', []))] });
  t.win.RescueHost.docChanged = () => false;
  t.click({ 'data-go': `mission:${ia}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.strictEqual(t.saved().deck.points, 0);
  assert.deepStrictEqual(t.saved().deck.confirmed, {});
});

// Task 9 (from the Task 8 review): on the DRILL RANGE an answer holds while that
// drill is open; the range is practice, so a later turn round can answer it again,
// but a drill pays once, ever (the ledger keys it).
test('the DRILL RANGE: one answer while a drill is open, practice again later, paid once', async () => {
  const t = await deckSetup(null);
  t.ctl.showTraining({ id: 'unsure', title: 'Not sure' });
  t.click({ 'data-go': 'range' });
  const title = () => /id="sig-title"[^>]*>([^<]+)/.exec(t.html())[1];
  const answerOf = (ttl) => DRILLS.find((d) => `Drill ${d.id}` === ttl.trim()).answer;
  const first = title();
  const right = answerOf(first);
  const wrong = ['mine', 'threat', 'closer'].find((x) => x !== right);
  t.click({ 'data-act': `tag:${right}` });
  const paid = t.saved().deck.points;
  assert.ok(paid > 0);
  assert.deepStrictEqual(t.saved().deck.drills, { right: 1, tried: 1 });
  t.click({ 'data-act': `tag:${wrong}` });
  assert.deepStrictEqual(t.saved().deck.drills, { right: 1, tried: 1 }, 'no second answer while it is open');
  assert.match(t.html(), new RegExp(`data-act="tag:${right}" aria-pressed="true"`));
  for (let i = 0; i < DRILLS.length; i += 1) t.click({ 'data-act': 'next-drill' });
  assert.strictEqual(title(), first, 'round again');
  t.click({ 'data-act': `tag:${right}` });
  assert.strictEqual(t.saved().deck.drills.tried, 2, 'practice counts as a try');
  assert.strictEqual(t.saved().deck.points, paid, 'a drill pays once, ever');
});

test('a drill answered in the queue can still be practised on the DRILL RANGE', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const t = await deckSetup(five);
  t.click({ 'data-go': 'signal:drill:gate-2' });
  t.click({ 'data-act': 'tag:mine' });
  const points = t.saved().deck.points;
  assert.deepStrictEqual(t.saved().deck.drills, { right: 1, tried: 1 });
  t.click({ 'data-go': 'range' });
  const title = () => /id="sig-title"[^>]*>([^<]+)/.exec(t.html())[1].trim();
  for (let i = 0; i < DRILLS.length && title() !== 'Drill gate-2'; i += 1) t.click({ 'data-act': 'next-drill' });
  assert.strictEqual(title(), 'Drill gate-2');
  t.click({ 'data-act': 'tag:mine' });
  assert.deepStrictEqual(t.saved().deck.drills, { right: 2, tried: 2 }, 'the buttons work there');
  assert.strictEqual(t.saved().deck.points, points, 'and pay nothing more');
  t.click({ 'data-act': 'leave-range' });
  t.click({ 'data-go': 'signal:drill:gate-2' });
  t.click({ 'data-act': 'tag:threat' });
  assert.deepStrictEqual(t.saved().deck.drills, { right: 2, tried: 2 }, 'the queue still holds its one answer');
});

// Final review 1: SCAN CLUE replaces its button with text, so focus moves on.
test('after SCAN CLUE, focus moves to the next locked clue, and to the opened clue when none is left', async () => {
  const t = await deckSetup(DOC);
  t.click({ 'data-act': 'investigate-next' });
  t.focusOn({ 'data-act': 'clue:where' });
  t.click({ 'data-act': 'clue:where' });
  assert.deepStrictEqual(t.focused.slice(-1), ['[data-act="clue:what"]'], 'the next locked clue after this one');
  t.focusOn({ 'data-act': 'clue:what' });
  t.click({ 'data-act': 'clue:what' });
  assert.deepStrictEqual(t.focused.slice(-1), ['[data-act="clue:maker"]'], 'then from the top');
  t.focusOn({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'clue:maker' });
  assert.deepStrictEqual(t.focused.slice(-1), ['[data-clue="maker"]'], 'none locked: the clue just opened');
  assert.match(t.html(), /<li class="clue open" data-clue="maker" tabindex="-1">/);
});

// Final review 1: closing the panel removes the button the person was on.
test('BACK TO THE DECK puts focus on the signal’s row, or else INVESTIGATE NEXT', async () => {
  const five = scan(mod('a_mod', Array.from({ length: 5 }, (_, i) => f(`W${i}`, 'warning', { plist: `/w${i}` }))));
  const [id] = await ids(five);
  const t = await deckSetup(five);
  t.click({ 'data-go': `signal:${id}` });
  t.focusOn({ 'data-act': 'close-signal' });
  t.click({ 'data-act': 'close-signal' });
  assert.deepStrictEqual(t.focused.slice(-1), [`[data-go="signal:${id}"]`]);
  t.click({ 'data-go': 'signal:drill:gate-1' });
  t.click({ 'data-act': 'tag:threat' });
  t.click({ 'data-act': 'close-signal' });
  assert.doesNotMatch(t.html(), /signal:drill:gate-1/, 'an answered drill left the queue');
  assert.deepStrictEqual(t.focused.slice(-1), ['[data-act="investigate-next"]']);
});

// Final review 4: Escape closes the panel; the deck behind it is inert while it's open.
test('Escape closes the Signal or Noise panel like BACK TO THE DECK; the deck behind is inert while it is open', async () => {
  const [id] = await ids(DOC);
  const t = await deckSetup(DOC);
  assert.doesNotMatch(t.html(), /\binert\b/);
  t.click({ 'data-go': `signal:${id}` });
  assert.match(t.html(), /<header class="hud deck-top" inert>/);
  assert.match(t.html(), /<div class="deck" inert>/);
  assert.doesNotMatch(t.html(), /class="sig-panel[^"]*"[^>]*inert/, 'the panel itself is live');
  // Inside a mark card, Escape is that card's (it closes its own question).
  t.key('Escape', { 'data-mark-card': '' });
  assert.match(t.html(), /id="sig-title"/);
  t.key('Enter');
  assert.match(t.html(), /id="sig-title"/);
  const ev = t.key('Escape');
  assert.strictEqual(ev.prevented, true);
  assert.doesNotMatch(t.html(), /id="sig-title"/);
  assert.doesNotMatch(t.html(), /\binert\b/);
  assert.deepStrictEqual(t.focused.slice(-1), [`[data-go="signal:${id}"]`]);
  t.key('Escape');
  assert.match(t.html(), /INCOMING SIGNALS/, 'nothing open: Escape does nothing');
});

// Final review 2: nothing about monitoring software is logged, as confirmFix
// scores nothing. In city mode it is held (held.js): never a mission, so there
// is nothing to re-check, confirm or mark, even once it is gone.
test('a monitoring finding is never a mission, and logs no CONFIRMED and no MARKED when it goes', async () => {
  const mon = (data) => mod('stalkerware_scan', [f('Monitoring app', 'critical', { path: '/m', ...data })]);
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]), mon());
  const id = (await ids(before)).find((x) => x.startsWith('stalkerware_scan|'));
  assert.ok(id, 'findingsToCity alone would make it a mission');
  const t = await deckSetup(before);
  t.click({ 'data-go': `mission:${id}` });
  assert.doesNotMatch(t.html(), /Monitoring app/, 'no briefing for it: the controller held it');
  assert.match(t.html(), /INCOMING SIGNALS/);
  const gone = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]), mod('stalkerware_scan', []));
  t.ctl.show(gone, { id: 'unsure' });
  const marked = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]),
    mon({ marked_by_user: true, original_severity: 'critical', known_item_id: 'k1', path: '/m2' }));
  t.ctl.show(marked, { id: 'unsure' });
  assert.doesNotMatch(t.html(), /MARKED<\/span>|CONFIRMED<\/span>|Monitoring app/);
  assert.deepStrictEqual(t.saved().deck.confirmed, {});
  assert.strictEqual(t.saved().deck.points, 0);
  assert.doesNotMatch(JSON.stringify(t.saved()), /stalkerware|Monitoring app|\/m2?\b/);
  // Neither its going nor its coming back is a moment or a log line.
  const log = t.html().split('OPS LOG')[1];
  assert.doesNotMatch(log, /SECURED|CLEAN SWEEP|NO LONGER SEEN|Monitoring app/);
  assert.doesNotMatch(t.html(), /DISTRICT SECURED|CLEAN SWEEP/);
});

// Final review 3: an id with a newline and a quote (a path can hold both)
// still finds its row again, and never knocks the person out of the game.
test('a signal id with a newline and a quote keeps focus across redraws and on close', async () => {
  const doc = scan(mod('a_mod', [f('Odd path', 'warning', { plist: '/Users/ann/a "b"\nc.plist' }), f('Low', 'info', { name: 'n' })]));
  const [id] = await ids(doc);
  assert.match(id, /\n/);
  const t = await deckSetup(doc);
  const unesc = (x) => x.replace(/&quot;/g, '"').replace(/&#39;/g, "'").replace(/&lt;/g, '<').replace(/&gt;/g, '>').replace(/&amp;/g, '&');
  // Like a real DOM: a selector with a raw newline or a stray quote throws.
  t.frame.querySelector = (sel) => {
    if (/[\n]/.test(sel) || (sel.match(/"/g) || []).length > 2) throw new SyntaxError(`bad selector ${sel}`);
    const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
    if (m && t.html().includes(`${m[1]}="${m[2]}"`)) return { focus: () => t.focused.push(sel) };
    return null;
  };
  t.frame.querySelectorAll = (sel) => {
    const m = /^\[(data-[a-z]+)\]$/.exec(sel);
    if (!m) return [];
    return [...t.html().matchAll(new RegExp(`${m[1]}="([^"]*)"`, 'g'))].map(([, v]) => ({
      getAttribute: (k) => (k === m[1] ? unesc(v) : null), focus: () => t.focused.push(`walk:${unesc(v)}`) }));
  };
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'close-signal' });
  assert.deepStrictEqual(t.focused.slice(-1), [`walk:signal:${id}`]);
  t.focusOn({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'toggle-low' });
  assert.deepStrictEqual(t.focused.slice(-1), [`walk:signal:${id}`]);
  assert.strictEqual(t.calls.leaveGame, 0, 'still in the game');
});

test('findByAttr: plain values use a selector; others use CSS.escape, or walk the elements', async () => {
  const { findByAttr } = await import('../renderer/game/controller.js');
  const { createDocument } = require('./mini-dom.js');
  const doc = createDocument();
  const odd = 'signal:a|"b"\nc\\d';
  const a = doc.body.add('button', { 'data-go': 'signal:plain' });
  const b = doc.body.add('button', { 'data-go': odd });
  assert.strictEqual(findByAttr(doc.body, 'data-go', 'signal:plain', null), a);
  assert.strictEqual(findByAttr(doc.body, 'data-go', odd, null), b, 'no CSS.escape: the walk');
  const seen = [];
  const css = { escape: (v) => { seen.push(v); return 'escaped'; } };
  assert.strictEqual(findByAttr(doc.body, 'data-go', odd, css), b, 'CSS.escape finds nothing here, so the walk');
  assert.deepStrictEqual(seen, [odd]);
  const throwing = { querySelector: () => { throw new SyntaxError('x'); }, querySelectorAll: () => { throw new SyntaxError('y'); } };
  assert.strictEqual(findByAttr(throwing, 'data-go', odd, css), null, 'never throws');
  assert.strictEqual(findByAttr(doc.body, 'data-go', 'signal:none', null), null);
});

// Final review (deferred b): moments queue up; a rank-up is never lost.
test('a clean sweep that also ranks up shows both moments, with the district secured', async () => {
  const { emptyDeck } = await import('../renderer/game/progress.js');
  const storage = memStore();
  storage.setItem(STORE, JSON.stringify({ version: 3, missions: {}, lessons: {}, deck: { ...emptyDeck(), points: 70 } }));
  const t = await deckSetup(scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })])), { storage });
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [])), { id: 'unsure' });
  const html = t.html();
  assert.match(html, /<div class="moments">[\s\S]*moment-secured[\s\S]*moment-rank" role="status"><b>RANK UP<\/b> You’re now SIGNAL ANALYST[\s\S]*moment-clean" role="status"><b>CLEAN SWEEP<\/b>/);
  t.click({ 'data-go': 'map' });
  assert.doesNotMatch(t.html(), /class="moment/, 'each shows once');
});

test('more moments than fit: the oldest go first, and the rank-up stays', async () => {
  const { emptyDeck } = await import('../renderer/game/progress.js');
  const storage = memStore();
  storage.setItem(STORE, JSON.stringify({ version: 3, missions: {}, lessons: {}, deck: { ...emptyDeck(), points: 70 } }));
  const cats = ['security', 'network', 'integrity', 'performance', 'bloatware'];
  const busy = scan(...cats.map((c, i) => ({ ...mod(`m${i}`, [f(`W${i}`, 'warning', { plist: `/w${i}` })]), category: c })));
  const clear = scan(...cats.map((c, i) => ({ ...mod(`m${i}`, []), category: c })));
  const t = await deckSetup(busy, { storage });
  t.ctl.showBoss();
  t.ctl.scanDone(clear, { id: 'unsure' });
  const kinds = [...t.html().matchAll(/class="moment moment-([a-z]+)"/g)].map((m) => m[1]);
  assert.strictEqual(kinds.length, 4);
  assert.deepStrictEqual(kinds.slice(-2), ['rank', 'clean']);
  assert.deepStrictEqual(kinds.slice(0, 2), ['secured', 'secured']);
  // (The log shows its newest twelve lines; the Gatehouse's is just past them.)
  for (const name of ['The Wires', 'The Foundations', 'The Engine Room', 'The Junkyard']) {
    assert.match(t.html(), new RegExp(`SECURED</span> ${name}`), `${name} is still in the log`);
  }
});

// The merge of the command center into Reclaim City: in city mode a monitoring
// finding is held. The deck gives it no signal, so no MINE or THREAT and no
// points, yet city integrity still counts its district as open.
test('city mode: a held monitoring finding has no signal and no points, and integrity still counts it as open', async () => {
  const held = scan(mod('stalkerware_scan', [f('Monitoring app', 'critical', { path: '/m' })]));
  const id = (await ids(held))[0];
  assert.match(id, /^stalkerware_scan\|/);
  const t = await deckSetup(null);
  t.win.RescueHost.mode = () => 'city';
  t.ctl.show(held, { id: 'unsure' });
  assert.match(t.html(), /INCOMING SIGNALS/, 'the game stays on');
  assert.doesNotMatch(queueOf(t.html()), /Monitoring app|stalkerware/);
  assert.doesNotMatch(t.html(), /Monitoring app/);
  // Asking for its signal opens nothing, so there is nothing to tag MINE or THREAT.
  t.click({ 'data-go': `signal:${id}` });
  assert.doesNotMatch(t.html(), /id="sig-title"|data-act="tag:/);
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(t.saved().deck.points, 0);
  assert.deepStrictEqual(t.saved().deck.tags, {});
  assert.doesNotMatch(JSON.stringify(t.saved()), /stalkerware|Monitoring app/);
  // Integrity: its district was checked and is not secure while it is there.
  assert.match(t.html(), /<b>0%<\/b>/);
  assert.match(t.html(), /City integrity 0%/);
  t.ctl.show(scan(mod('stalkerware_scan', [])), { id: 'unsure' });
  assert.match(t.html(), /<b>100%<\/b>/, 'once it is gone, the district is secure');
  // Its going is not a win: no DISTRICT SECURED, no CLEAN SWEEP, no points,
  // and no log line saying where it was.
  assert.doesNotMatch(t.html(), /DISTRICT SECURED|CLEAN SWEEP/);
  assert.doesNotMatch(t.html().split('OPS LOG')[1], /SECURED|CLEAN SWEEP|Monitoring app/);
  assert.strictEqual(t.saved().deck.points, 0);
  // Nor the next sweep, clean again.
  t.ctl.show(scan(mod('stalkerware_scan', [])), { id: 'unsure' });
  assert.doesNotMatch(t.html(), /DISTRICT SECURED|CLEAN SWEEP/);
  assert.strictEqual(t.saved().deck.points, 0);
});

// Task 8 (merge review): a held finding's mission can't be opened, so I DID IT
// has nothing to re-check, and nothing is confirmed, paid or logged.
test('city mode: I DID IT on a held finding re-checks nothing and confirms nothing', async () => {
  const held = scan(mod('stalkerware_scan', [f('Monitoring app', 'critical', { path: '/m' })]));
  const id = (await ids(held))[0];
  const t = await deckSetup(null, { recheckDocs: [scan(mod('stalkerware_scan', []))] });
  t.win.RescueHost.mode = () => 'city';
  t.ctl.show(held, { id: 'unsure' });
  t.click({ 'data-go': `mission:${id}` });
  assert.doesNotMatch(t.html(), /Monitoring app|data-act="i-did-it"/);
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.recheck, []);
  assert.deepStrictEqual(t.saved().deck.confirmed, {});
  assert.strictEqual(t.saved().deck.points, 0);
  assert.doesNotMatch(t.html().split('OPS LOG')[1], /CONFIRMED|MARKED|SECURED|Monitoring app/);
});

// --- A check that ran but didn't finish ("complete": false) is never clean.

test('an open mission and a re-sweep whose check didn’t finish: still open, no award, the district partial', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]));
  const [ia] = await ids(before);
  const t = await deckSetup(before);
  // The person said they did it, but the re-check is what pays: here a re-sweep.
  const points = t.saved().deck.points;
  t.ctl.showBoss();
  t.ctl.scanDone(scan(mod('a_mod', [f('Couldn’t finish', 'info')], { complete: false })), { id: 'unsure' });
  const saved = t.saved();
  assert.strictEqual(saved.missions[ia].status, 'open', 'not reclaimed on an unfinished check’s word');
  assert.deepStrictEqual(saved.deck.confirmed, {});
  assert.strictEqual(saved.deck.points, points);
  const html = t.html();
  assert.match(html, /class="district partial[^"]*" data-go="filter:gatehouse"/);
  assert.match(html, /1 DIDN’T FINISH/);
  assert.doesNotMatch(html, /NOTHING FOUND|What was found here before is gone now|CLEAN SWEEP|SECURED<\/span> The Gatehouse/);
  assert.doesNotMatch(html, /NO LONGER SEEN<\/span> A/);
  assert.match(html, /SWEEP<\/span> 1 check: 0 critical, 0 warning, 0 couldn’t check, 1 didn’t finish\./);
  assert.ok(saved.deck.sweeps.every((w) => !('unfinished' in w)), 'the count is said, never stored');
});

test('I DID IT MYSELF, then a re-check whose check didn’t finish: COULDN’T RE-CHECK, no CONFIRMED, still open', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' })]));
  const unfinished = scan(mod('a_mod', [], { complete: false }));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [unfinished] });
  t.click({ 'data-go': `mission:${ia}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick();
  const html = t.html();
  assert.match(html, /COULDN’T RE-CHECK/);
  assert.match(html, /didn’t finish, so this wasn’t checked to the end/);
  assert.doesNotMatch(html, /RECLAIMED/);
  const saved = t.saved();
  assert.strictEqual(saved.missions[ia].status, 'open');
  assert.deepStrictEqual(saved.deck.confirmed, {});
  assert.strictEqual(saved.deck.points, 0);
});

// --- A change refused mid-scan tried nothing.

test('a fix refused because a sweep is running: no re-check, no outcome screen, not the last fix', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }, { fixable: true })]));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [scan(mod('a_mod', []))] });
  t.click({ 'data-go': `mission:${ia}` });
  const { fixRefusal, markRefusal } = require('../scan-gate.js');
  t.hooks.fix.onResult({ kind: 'fix', module: 'a_mod', result: fixRefusal('a_mod'), described: { tone: 'info' } });
  t.hooks.mark.onResult({ kind: 'marked', result: markRefusal(), described: { done: false } });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.recheck, []);
  assert.doesNotMatch(t.html(), /RECLAIMED|COULDN’T RE-CHECK|NOT YET/);
  assert.match(t.html(), /data-act="i-did-it"/, 'still on the briefing');
});

test('while a sweep runs, a mission shows no fix, mark or I DID IT MYSELF, and no re-check starts', async () => {
  const before = scan(mod('a_mod', [f('A', 'warning', { plist: '/a' }, { markable: true })]));
  const [ia] = await ids(before);
  const t = await deckSetup(before, { recheckDocs: [scan(mod('a_mod', []))] });
  t.click({ 'data-go': `mission:${ia}` });
  assert.match(t.html(), /MARK IT/);
  t.ctl.showBoss();
  t.click({ 'data-go': `mission:${ia}` });
  let html = t.html();
  assert.doesNotMatch(html, /MARK IT|data-act="i-did-it"/);
  assert.match(html, /data-scan-running/);
  assert.match(html, /The sweep is still running\. You can act on this once it’s done\./);
  assert.doesNotMatch(html, /minute|second|hour|soon/i);
  t.hooks.fix.onResult({ kind: 'fix', module: 'a_mod', result: { status: 'fixed' }, described: { tone: 'success' } });
  await tick();
  assert.deepStrictEqual(t.calls.recheck, [], 'no re-check while the sweep runs');
  t.ctl.scanDone(before, { id: 'unsure' });
  t.click({ 'data-go': `mission:${ia}` });
  html = t.html();
  assert.match(html, /MARK IT/);
  assert.match(html, /data-act="i-did-it"/);
});
