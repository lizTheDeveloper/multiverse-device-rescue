// UX round 5, the city: a stopped checkup handed to the city, one fix counted
// once in YOUR FILE, the mission's YOUR MOVE, the narrow Scout column, the
// NOT CHECKED chip, the help-district button and district row evidence.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const NotChecked = require('../renderer/not-checked.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const ticks = async (n = 20) => { for (let i = 0; i < n; i++) await tick(); };
const memStore = () => { const s = {}; return { data: s, getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; } }; };
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/&#39;/g, '\'').replace(/\s+/g, ' ');

function stub({ mode = 'city', recheck = null } = {}) {
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); },
    querySelector: (sel) => (sel === 'h2' ? { focus() {}, setAttribute() {}, hasAttribute: () => false } : null),
    querySelectorAll: () => [] };
  const shadow = { activeElement: null, innerHTML: '', getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener: () => {},
    QuietNotes: require('../renderer/quiet-notes.js'),
    FixFlow: { attach() {}, fixControlsHtml: () => '<button data-fix>FIX</button>', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '<button data-mark>MINE</button>' },
    RescueHost: { mode: () => mode, citySeed: () => 7, showList() {}, docChanged: () => true,
      wantsSafety: () => true, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async (name) => (recheck ? recheck(name) : { ok: false, message: 'no' }), runScan: async () => null },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, click, html: () => frame.innerHTML };
}

async function setup(doc, opts = {}) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const storage = memStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  if (doc) ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, ctl, storage };
}

// One background task reported by two checks (the engine's same_key): one mission.
const task = (module, plist) => ({ title: `Background task runs from a hidden folder (${module})`, description: 'x', severity: 'warning', category: 'security',
  code: `security.${module}.suspicious_path`, same_key: 'task:ai.example.agent:suspicious_path', data: { plist } });
const PLIST = '/Users/x/Library/LaunchAgents/ai.example.agent.plist';

test('YOUR FILE: one fix of a mission two checks reported counts once (it said "2 fixed and confirmed")', async () => {
  let cur = scan(mod('launch_agent_audit', [task('launch_agent_audit', PLIST)]), mod('launchd_persistence_audit', [task('launchd_persistence_audit', PLIST)]));
  const recheck = (name) => {
    cur = { ...cur, modules: cur.modules.map((m) => (m.name === name ? { ...m, findings: [] } : m)) };
    return { ok: true, module: cur.modules.find((m) => m.name === name), doc: cur };
  };
  const t = await setup(cur, { recheck });
  const { findingsToCity } = await game('findings-to-city.js');
  const missions = findingsToCity(cur).districts.flatMap((d) => d.missions);
  assert.strictEqual(missions.length, 1);
  t.click({ 'data-go': `mission:${missions[0].id}` });
  t.click({ 'data-act': 'i-did-it' });
  await ticks();
  assert.match(text(t.html()), /1 CONFIRMED/);
  t.click({ 'data-go': 'profile' });
  await ticks(5);
  assert.match(text(t.html()), /1 fixed and confirmed/);
});

test('reconcile: a merged item whose first check dropped it keeps one record under its new id', async () => {
  const { reconcile, emptyProgress, countReclaimed } = await game('progress.js');
  const { findingsToCity, findingIdentity } = await game('findings-to-city.js');
  const both = scan(mod('a_check', [task('a_check', PLIST)]), mod('b_check', [task('b_check', PLIST)]));
  const city1 = findingsToCity(both);
  let p = reconcile(emptyProgress(), city1, new Set(['a_check', 'b_check']), 't1').progress;
  const sameAs = new Map(city1.districts.flatMap((d) => d.missions).flatMap((m) => m.findings.map((f) => [findingIdentity(f), m.id])));
  const onlyB = scan(mod('a_check', []), mod('b_check', [task('b_check', PLIST)]));
  p = reconcile(p, findingsToCity(onlyB), new Set(['a_check']), 't2', sameAs).progress;
  assert.strictEqual(countReclaimed(p), 0, 'still reported by the other check: not gone');
  assert.strictEqual(Object.keys(p.missions).length, 1);
  p = reconcile(p, findingsToCity(scan(mod('a_check', []), mod('b_check', []))), new Set(['b_check']), 't3').progress;
  assert.strictEqual(countReclaimed(p), 1);
});

// The stopped fixtures: the fresh scan's modules streamed, then the engine
// stopped (all of them: 'assembly'; the first half: 'early'), through
// engine-runner's own stoppedDocOf, as app.js hands it over.
const { stoppedDocOf } = require('../engine-runner.js');
const fresh = () => JSON.parse(require('fs').readFileSync(path.join(__dirname, 'fixtures', 'fresh-round3.json'), 'utf8'));
function stoppedFixture(stage) {
  const doc = fresh();
  const plan = { modules: doc.modules.map((m) => ({ module: m.name, category: m.category })) };
  const streamed = stage === 'assembly' ? doc.modules : doc.modules.slice(0, Math.floor(doc.modules.length / 2));
  return stoppedDocOf(streamed, plan, { platform: 'darwin', reason: 'exit', exit_code: 1 });
}

for (const stage of ['assembly', 'early']) {
  test(`a stopped checkup (${stage}) handed to the city: its stopped deck, what it found, nothing to fix or mark`, async () => {
    const doc = stoppedFixture(stage);
    assert.strictEqual(doc.stopped.stage, stage);
    const t = await setup(null);
    t.ctl.showBoss();
    assert.notStrictEqual(t.ctl.scanFailed('The checkup stopped before it finished.', doc), false);
    const deck = t.html();
    assert.match(deck, stage === 'assembly' ? /THE SWEEP STOPPED AT THE END/ : /THE SWEEP STOPPED EARLY/);
    // The deck, never the Training Grounds with "start it again".
    assert.match(deck, /INCOMING SIGNALS/);
    assert.doesNotMatch(deck, /You can start it again/);
    // What it found is there to look at.
    const c = NotChecked.scanCounts(doc, { mode: 'city' });
    assert.ok(c.items > 0);
    assert.match(deck, /data-go="signal:/);
    // Its missions offer no fix and no mark.
    const id = /data-go="(mission:[^"]+)"/.exec(deck) || /data-go="signal:([^"]+)"/.exec(deck);
    assert.ok(id);
    const { findingsToCity } = await game('findings-to-city.js');
    const m = findingsToCity(doc).districts.flatMap((d) => d.missions).find((x) => x.fixable) || findingsToCity(doc).districts.flatMap((d) => d.missions)[0];
    t.click({ 'data-go': `mission:${m.id}` });
    const mission = t.html();
    assert.doesNotMatch(mission, /data-fix>|data-mark>/);
    assert.match(mission, /stopped before its report was done/);
  });
}

test('a checkup that stopped with nothing found: the error, as before (no document to show)', async () => {
  const t = await setup(null);
  t.ctl.showBoss();
  t.ctl.scanFailed('The checkup stopped before it finished. Nothing on your computer was changed.');
  assert.match(t.html(), /THE (SWEEP|CHECKUP) STOPPED/);
  // A document with no modules is no better than none.
  t.ctl.showBoss();
  t.ctl.scanFailed('x', { stopped: { stage: 'early' }, modules: [] });
  assert.doesNotMatch(t.html(), /INCOMING SIGNALS/);
});

test('YOUR MOVE: the finding’s own prose or the numbered steps, never both', async () => {
  const { renderBriefing, yourMove } = await game('views/briefing.js');
  const fs = require('fs');
  const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'game.css'), 'utf8');
  const step = { number: 1, title: 'Remove high-risk background tasks', body: 'Run this:\n\n```\nlaunchctl bootout gui/501 <path-to-plist>\n```' };
  const primary = { title: 't', description: "A task.\n\nWhat to do: Open System Settings > General > Login Items. Turn off 'ai.example.agent'.",
    remediation: { steps: [step] }, data: { plist: PLIST } };
  const m = { id: 'x', districtId: 'gatehouse', severity: 'warning', title: 't', description: primary.description, steps: [step],
    findings: [primary], primary };
  const html = renderBriefing({ mission: m, status: 'open', controlsHtml: '', scout: () => '<img>', busy: false, wantsSafety: false });
  const move = html.slice(html.indexOf('YOUR MOVE'), html.indexOf('class="controls"'));
  assert.match(move, /Open System Settings/);
  assert.doesNotMatch(move, /Remove high-risk background tasks/);
  assert.doesNotMatch(move, /class="step-n"/);
  assert.match(move, /FOR TECH HELPERS/);
  // Several steps: behind STEP BY STEP, the prose leads.
  const two = yourMove([step, { ...step, number: 2, title: 'Check again', body: 'Run the checkup again.' }], 'Turn it off.');
  assert.match(two, /^<div class="step-body todo">/);
  assert.match(two, /<details class="tech steps-more"><summary>STEP BY STEP \(2\)/);
  // No prose: the steps are the move.
  assert.match(yourMove([step], ''), /^<ol class="steps">/);
  // The Scout column: one column at 800px, the Scout a row above the mission.
  assert.match(css, /@media \(max-width: 800px\) \{ \.brief \{ grid-template-columns: minmax\(0,1fr\); \} \}/);
  assert.match(css, /\.brief-side \{ order: -1;/);
});

test('NOT CHECKED: the chip names each part, and its filter reaches every check the banner counts', async () => {
  const doc = fresh();
  const { districtIdFor } = await game('findings-to-city.js');
  const { notCheckedChip } = await game('signals.js');
  const c = NotChecked.scanCounts(doc, { mode: 'city', districtOf: districtIdFor });
  assert.ok(c.unfinished > 0 && c.notStarted > 0, 'the fresh scan has unfinished checks and a waiting one');
  const t = await setup(doc);
  const deck = t.html();
  const label = notCheckedChip(c);
  assert.match(label, new RegExp(`${c.unfinished} DIDN’T FINISH`));
  assert.match(label, new RegExp(`${c.notStarted} NOT STARTED`));
  assert.ok(deck.includes(`>NOT CHECKED: ${label}<`));
  // TO DO is the list's number of items, never plus the not-checked rows.
  assert.match(deck, new RegExp(`INCOMING SIGNALS · ${c.items} TO DO`));
  t.click({ 'data-act': 'sev:couldnt' });
  const rows = [...t.html().matchAll(/data-go="signal:([^"]+)"/g)].map((m) => m[1]);
  assert.strictEqual(rows.length, c.couldntRun + c.unfinished + c.notStarted);
  assert.strictEqual((t.html().match(/>DIDN’T FINISH</g) || []).length, c.unfinished);
  // An unfinished row says it may have missed something, not that it checked nothing.
  const u = rows.find((id) => id.startsWith('couldnt|'));
  t.click({ 'data-go': `signal:${u}` });
  assert.match(t.html(), /stopped before the end, so it may have missed something/);
  assert.doesNotMatch(t.html(), /checked nothing/);
  // A mission's HUD: the same TO DO and NOT CHECKED.
  t.click({ 'data-act': 'close-signal' });
  t.click({ 'data-go': 'district:gatehouse' });
  const h = text(t.html());
  assert.match(h, new RegExp(`${c.items} TO DO`));
  assert.match(h, new RegExp(`${c.couldntRun + c.unfinished + c.notStarted} NOT CHECKED`));
});

test('the help district’s tile is never a bare button: a quiet label and the place’s greeting, nothing that gives it away', async () => {
  const { sideTileHtml, TILE_LABEL } = await game('views/side-district.js');
  const { pickDistrict, GIVEAWAY } = await game('district-names.js');
  for (const seed of [1, 7, 42, 999]) {
    const d = pickDistrict(seed);
    const html = sideTileHtml(d, 0);
    assert.ok(html.includes(TILE_LABEL));
    assert.ok(html.includes(d.voice.hello.replace(/'/g, '&#39;')) || html.includes(d.voice.hello));
    assert.doesNotMatch(text(html), GIVEAWAY);
  }
  // On the deck too.
  const t = await setup(fresh());
  assert.match(t.html(), /ALSO IN TOWN<\/span>\s*<button type="button" class="btn-s" data-go="side">/);
});

test('LOW-PRIORITY SIGNALS shows the shared notes count once NotChecked gives one', async () => {
  const { renderDeck } = await game('views/deck.js');
  const base = { title: 'X', rank: { name: 'R', points: 0 }, low: [{ id: 'a', kind: 'real', severity: 'info', title: 'n', districtId: 'gatehouse' }] };
  assert.match(renderDeck(base), /LOW-PRIORITY SIGNALS \(1\)/);
  assert.match(renderDeck({ ...base, lowCount: 291 }), /LOW-PRIORITY SIGNALS \(291\)/);
});
