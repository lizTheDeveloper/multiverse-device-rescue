// The guided walkthrough (guided.js), FOUND SO FAR on the sweep (live.js),
// cases opened in their own row, "what is it for?", UNDO and CHECK AGAIN.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const STORE = 'device-rescue.game.v1';
const tick = () => new Promise((r) => setTimeout(r, 0));
const memStore = (seed = {}) => { const s = { ...seed }; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const task = (n, extra = {}) => ({ title: `Helper ${n} starts at login`, description: `Helper ${n}: what it is.`, severity: 'warning', category: 'security',
  code: 'security.launch_agent_audit.suspicious_path', data: { program: `/Users/me/.x/helper${n}`, label: `com.example.h${n}` },
  made_by: [{ subject: `/Users/me/.x/helper${n}`, name: 'Zoom Video Communications', verified: true, how: 'Developer ID' }], ...extra });
const DOC = scan(mod('launch_agent_audit', [task(1), task(2), task(3)]));
const SPY = mod('stalkerware_scan', [{ title: 'Stalkerware found: mSpy', description: 'd', severity: 'critical', category: 'security', data: {} }]);
const seasoned = (sorts, level, extra = {}) => memStore({
  'device-rescue.level': level,
  [STORE]: JSON.stringify({ version: 3, missions: {}, lessons: extra.lessons || {}, deck: { points: 0, rank: 0, drills: { right: 0, tried: 0 }, tags: {},
    confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [], sorts } }),
});

function stub(recheckDocs = []) {
  const listeners = [];
  const frame = { innerHTML: '', className: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const calls = { recheck: [] };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async (name) => { calls.recheck.push(name); const doc = recheckDocs.shift(); return { ok: true, doc, module: doc.modules.find((m) => m.name === name) }; } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, click, calls, html: () => frame.innerHTML };
}

async function setup(storage, { doc = DOC, lessons = [], recheckDocs = [] } = {}) {
  const { createController } = await game('controller.js');
  const t = stub(recheckDocs);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons, loadDrillBank: async () => [] });
  await tick();
  if (doc) ctl.show(doc, { id: 'unsure' });
  const { findingIdentity } = await game('findings-to-city.js');
  const idOf = (n) => findingIdentity({ ...task(n), module: 'launch_agent_audit' });
  return { ...t, ctl, storage, idOf, deck: () => JSON.parse(storage.getItem(STORE)).deck };
}

test('the walkthrough fades with the lifetime sorts count, and never runs for technical, drills or blind spots', async () => {
  const { guideMode, FADE } = await game('guided.js');
  const real = { kind: 'real' };
  const at = (level, sorts, sig = real) => guideMode(level, { sorts }, sig);
  assert.deepStrictEqual([0, 2, 3, 5, 6].map((n) => at('new', n)), ['full', 'full', 'light', 'light', 'none']);
  assert.deepStrictEqual([0, 1, 2, 3, 4].map((n) => at('everyday', n)), ['full', 'full', 'light', 'light', 'none']);
  assert.strictEqual(at('technical', 0), 'none');
  assert.strictEqual(at('new', 0, { kind: 'drill' }), 'none');
  assert.strictEqual(at('new', 0, { kind: 'couldnt' }), 'none');
  assert.strictEqual(guideMode('new', null, real), 'full', 'an old deck has no count yet');
  assert.ok(FADE.new.full > FADE.everyday.full, 'someone new gets more steps');
});

test('the steps come from the clues there are: what, who made it, one about what it does, then the call', async () => {
  const { guideSteps } = await game('guided.js');
  const c = (kind) => ({ kind, label: kind, lines: [kind] });
  assert.deepStrictEqual(guideSteps([c('maker'), c('when'), c('where'), c('what'), c('next')]).map((x) => [x.id, x.clue && x.clue.kind]),
    [['what', 'what'], ['maker', 'maker'], ['does', 'where'], ['call', null]]);
  assert.deepStrictEqual(guideSteps([]).map((x) => x.id), ['call'], 'nothing invented');
});

test('live: a finished check’s result adds once; a monitoring detection stops everything for the sweep', async () => {
  const { liveInit, liveApply, liveDoc, liveSignals } = await game('live.js');
  const ev = (m) => ({ phase: 'done', module: m.name, result: m });
  let l = liveApply(liveInit(), ev(mod('launch_agent_audit', [task(1)])));
  l = liveApply(l, ev(mod('launch_agent_audit', [task(1)])));
  l = liveApply(l, { phase: 'done', module: 'other', result: mod('launch_agent_audit', []) });
  l = liveApply(l, { phase: 'start', module: 'x', result: mod('x', []) });
  assert.strictEqual(l.modules.length, 1, 'once, and only a done line whose result is its own module');
  assert.strictEqual(liveDoc(l, 'darwin').modules.length, 1);
  const held = liveApply(l, ev(SPY));
  assert.deepStrictEqual(held, { modules: [], held: true });
  assert.strictEqual(liveDoc(held, 'darwin'), null);
  assert.strictEqual(liveApply(held, ev(mod('launch_agent_audit', [task(2)]))).modules.length, 0, 'nothing more arrives');
  const sigs = liveSignals([{ kind: 'real', severity: 'warning', missionId: 'm', fixable: true }, { kind: 'real', severity: 'info' },
    { kind: 'real', severity: 'critical', marked: true }, { kind: 'drill', severity: 'warning' }]);
  assert.deepStrictEqual(sigs, [{ kind: 'real', severity: 'warning', missionId: null, fixable: false, live: true }]);
});

test('the deck keeps a bare sorts count; UNDO puts back only a valid tag', async () => {
  const { cleanDeck, emptyDeck, validDeck } = await game('progress.js');
  const { countSort, restoreTag, setTag } = await game('ledger.js');
  const d = countSort(countSort(emptyDeck()));
  assert.strictEqual(cleanDeck(d).sorts, 2);
  assert.strictEqual(validDeck({ ...d, sorts: -1 }), false);
  assert.strictEqual('sorts' in cleanDeck(emptyDeck()), false);
  const tagged = setTag(emptyDeck(), 'a|b', 'mine', 'fp', 'now', 'work');
  assert.deepStrictEqual(restoreTag(tagged, 'a|b', null).tags, {});
  const back = restoreTag(emptyDeck(), 'a|b', tagged.tags['a|b']);
  assert.deepStrictEqual(back.tags['a|b'], { tag: 'mine', at: 'now', fp: 'fp', cat: 'work' });
  assert.deepStrictEqual(restoreTag(emptyDeck(), 'a|b', { tag: 'mine', at: 'now', fp: 'fp', cat: 'secret name' }).tags, {});
});

test('the incident report line leaves out zeros and never names a finding', async () => {
  const { reportLine, recapText } = await game('views/scoreboard.js');
  assert.strictEqual(reportLine({ unidentified: 3, doorsOpen: 1, blind: 0, identified: 2, threats: 0, investigating: 0 }),
    '3 leads to identify · 1 open door · 2 identified');
  assert.strictEqual(reportLine({}), 'No open cases.');
  assert.strictEqual(recapText({ checks: 195, cases: 1, sortedOnSweep: 2, lessons: 1 }), '195 checks · 1 case to look at · 2 sorted while it ran · 1 lesson done');
});

test('everyday, first time: a case opens guided in its row; each step pays its clue as it shows; the call is the person’s', async () => {
  const t = await setup(seasoned(0, 'everyday'));
  t.click({ 'data-go': `signal:${t.idOf(1)}` });
  assert.match(t.html(), /<li class="open-row">[\s\S]*sig-panel guided g-full inline/);
  assert.match(t.html(), /STEP 1 OF 4[\s\S]*WHAT IT IS[\s\S]*data-act="guide-next"/);
  const p0 = t.deck().points;
  assert.ok(p0 > 0, 'the first step’s clue paid');
  t.click({ 'data-act': 'guide-next' });
  assert.match(t.html(), /WHO MADE IT/);
  assert.ok(t.deck().points > p0);
  t.click({ 'data-act': 'guide-call' });
  assert.match(t.html(), /What do you make of it\?[\s\S]*data-act="tag:mine"[\s\S]*data-act="tag:closer"[\s\S]*data-act="tag:threat"/);
  assert.doesNotMatch(t.html().split('g-calls')[1], /btn-p/, 'no verdict is pushed');
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(t.deck().tags[t.idOf(1)].tag, 'mine');
  assert.strictEqual(t.deck().sorts, 1);
  assert.match(t.html(), /WHAT IS IT FOR\?[\s\S]*cat-chip suggested" data-act="cat:chat"/);
  const before = t.deck().points;
  t.click({ 'data-act': 'cat:chat' });
  assert.strictEqual(t.deck().tags[t.idOf(1)].cat, 'chat');
  assert.strictEqual(t.deck().points, before + 10, 'identify pays: the clues were looked at');
  assert.match(t.html(), /data-act="guide-another"/, 'NEXT ONE where NEXT was');
});

test('everyday, later: MINE on a lead asks what it is for in the verdict’s place, then the next case opens in the same place, with UNDO', async () => {
  const t = await setup(seasoned(10, 'everyday'));
  t.click({ 'data-go': `signal:${t.idOf(1)}` });
  assert.match(t.html(), /case-inline[\s\S]*g-verdict[\s\S]*data-act="tag:mine"/);
  assert.doesNotMatch(t.html(), /class="sig-panel(?! inline)/, 'no panel across the screen');
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(t.deck().tags[t.idOf(1)], undefined, 'nothing kept until it’s said what it is for');
  assert.match(t.html(), /MINE\. WHAT IS IT FOR\?/);
  t.click({ 'data-act': 'cat:work' });
  assert.deepStrictEqual([t.deck().tags[t.idOf(1)].tag, t.deck().tags[t.idOf(1)].cat], ['mine', 'work']);
  const open = t.html().split('<li class="open-row">')[1];
  assert.ok(open, 'the next case is already open');
  assert.match(open, /g-done[\s\S]*MINE[\s\S]*Work and office[\s\S]*data-act="sort-undo"/);
  assert.match(open, /Helper [23] starts at login/);
  t.click({ 'data-act': 'sort-undo' });
  assert.strictEqual(t.deck().tags[t.idOf(1)], undefined, 'UNDO takes the tag back');
  assert.match(t.html().split('<li class="open-row">')[1], /Helper 1 starts at login/, 'and opens it again');
  // THREAT moves straight on.
  t.click({ 'data-act': 'tag:threat' });
  assert.strictEqual(t.deck().tags[t.idOf(1)].tag, 'threat');
  assert.match(t.html(), /<b>THREAT<\/b>/);
});

test('saying what it is for pays only after looking at its clues; without clues it still files, for nothing', async () => {
  const bare = scan(mod('launch_agent_audit', [{ title: 'Bare thing', description: '', severity: 'warning', category: 'security', data: {},
    markable: { kind: 'background_task', id: '0a0a0a0a0a01' } }]));
  const t = await setup(seasoned(10, 'everyday'), { doc: bare });
  const { findingIdentity } = await game('findings-to-city.js');
  const id = findingIdentity({ ...bare.modules[0].findings[0], module: 'launch_agent_audit' });
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'tag:mine' });
  assert.match(t.html(), /Open its clues first to earn XP/);
  t.click({ 'data-act': 'cat:dev' });
  assert.strictEqual(t.deck().tags[id].cat, 'dev');
  assert.strictEqual(t.deck().points, 0);
});

test('CHECK AGAIN in the row: gone from a check that ran is CONFIRMED, once; still there says so in place', async () => {
  const gone = scan(mod('launch_agent_audit', [task(2), task(3)]));
  const t = await setup(seasoned(10, 'everyday'), { recheckDocs: [DOC, gone] });
  t.click({ 'data-go': `signal:${t.idOf(1)}` });
  assert.match(t.html(), /data-act="check-again"/);
  t.click({ 'data-act': 'check-again' });
  await tick(); await tick();
  assert.match(t.html(), /Checked again: still there\./);
  t.click({ 'data-act': 'check-again' });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.recheck, ['launch_agent_audit', 'launch_agent_audit']);
  assert.match(t.html(), /Checked again: gone\. Helper 1 starts at login · \+50 XP/);
  assert.ok(t.deck().confirmed[t.idOf(1)]);
});

test('the sweep: technical opens what arrives at once; calm waits for a lesson; something held stops it all', async () => {
  const lesson = { id: 'l1', title: 'L', briefing: '', whatTheScanLooksFor: 'x', districts: [], questions: [] };
  const ev = (m, i) => ({ type: 'progress', phase: 'done', index: i, total: 9, module: m.name, category: m.category, findings: m.findings.length, result: m });
  for (const [level, lessons, expect] of [['technical', {}, /arrivals fast[\s\S]*data-go="signal:/], ['everyday', {}, /Finish the short lesson first/],
    ['everyday', { l1: { completedAt: 'x' } }, /LOOK AT IT WITH ME/]]) {
    const t = await setup(seasoned(0, level, { lessons }), { doc: null, lessons: [lesson] });
    t.ctl.showBoss();
    t.ctl.scanEvent(ev(mod('launch_agent_audit', [task(1), task(2)]), 1));
    assert.match(t.html(), expect, level);
    t.ctl.scanEvent(ev(SPY, 2));
    assert.doesNotMatch(t.html(), /FOUND SO FAR|Helper 1/, `${level}: held stops the arrivals`);
    assert.doesNotMatch(t.html(), /mSpy/);
  }
});

test('sorting on the sweep counts, and its XP isn’t paid again once the sweep is done', async () => {
  const t = await setup(seasoned(10, 'technical'), { doc: null });
  t.ctl.showBoss();
  const m = mod('launch_agent_audit', [task(1)]);
  t.ctl.scanEvent({ type: 'progress', phase: 'done', index: 1, total: 1, module: m.name, category: m.category, findings: 1, result: m });
  t.click({ 'data-go': `signal:${t.idOf(1)}` });
  assert.match(t.html(), /Found during the sweep[\s\S]*BACK TO THE SWEEP/);
  assert.doesNotMatch(t.html(), /data-act="mine:/, 'marking in Reclaim City waits for the finished scan');
  t.click({ 'data-act': 'tag:threat' });
  const paid = t.deck().points;
  assert.ok(paid > 0);
  assert.strictEqual(t.deck().tags[t.idOf(1)].tag, 'threat');
  t.ctl.scanDone(scan(m), { id: 'unsure' });
  t.click({ 'data-go': `signal:${t.idOf(1)}` });
  assert.strictEqual(t.deck().points, paid, 'the same clues pay once');
});

test('the radar: an SVG picture with the same numbers in a table, and a plain line before anything is filed', async () => {
  const { renderRadar } = await game('views/radar.js');
  const empty = renderRadar({ counts: {} });
  assert.doesNotMatch(empty, /<svg/);
  assert.match(empty, /say what it’s for/);
  const html = renderRadar({ counts: { dev: 3, chat: 1, other: 2 }, running: { dev: 2 } });
  assert.match(html, /<svg class="radar-svg"[^>]*role="img" aria-labelledby="radar-title" aria-describedby="radar-table"/);
  assert.match(html, /<g aria-hidden="true">/);
  assert.match(html, /Developer tools<\/th><td>3<\/td><td>2<\/td>/);
  assert.match(html, /Chat and calls<\/th><td>1<\/td><td>0<\/td>/);
  assert.match(html, /Something else<\/th><td>2<\/td>/);
  assert.doesNotMatch(html, /Media and games/, 'only what was filed');
});
