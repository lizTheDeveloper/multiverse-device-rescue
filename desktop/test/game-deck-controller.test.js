// The command center against a stubbed window (no DOM library), like
// game-controller.test.js: a frame whose innerHTML the tests read, and clicks
// delivered as elements with attributes.
const test = require('node:test');
const assert = require('node:assert');

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
  const calls = { startCheckup: 0, recheck: [], showList: 0 };
  const focused = [];
  const frame = {
    innerHTML: '',
    addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
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
      startCheckup() { calls.startCheckup += 1; }, scanTips: async () => [], leaveGame() {} },
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
  return { win, frame, hooks, calls, click, focused, focusOn };
}

async function deckSetup(doc, { storage = memStore(), situation = { id: 'unsure' }, recheckDocs = [], drills = DRILLS } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const t = stub(recheckDocs);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => drills });
  await tick();
  if (doc) ctl.show(doc, situation);
  return { ...t, ctl, storage, html: () => t.frame.innerHTML, saved: () => JSON.parse(storage.getItem(STORE) || 'null') };
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
  assert.match(t.html(), /OPTIONAL: TELL DEVICE RESCUE TOO[\s\S]*MARK IT/);
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
  assert.match(t.html(), /And 70 more/);
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
  assert.doesNotMatch(t.storage.getItem(STORE), /stalkerware|monitoringSeen/);
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
