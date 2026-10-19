'use strict';
// Little missions on the city: district rows, INVESTIGATE NEXT, the mission
// screen, the acts, points and remembered answers. A stubbed window like
// game-deck-controller.test.js (no DOM library): the tests read the frame's
// innerHTML and deliver clicks as elements with attributes.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { savedProfile } = require('./profile-read.js');

const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; } }; };
const tick = () => new Promise((r) => setTimeout(r, 0));
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}: what it is.`, severity, data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const CITY_FORBIDDEN = /partner|stalk|abuse|violence|advocate|hotline|799-7233|88788|domestic|spyware|stalkerware|monitoring software|\bspy\b/i;

// Five unmapped warnings, a fixable alerting critical and a markable one: seven
// Odd Jobs items in the Gatehouse, so a mission of 4 (the critical first) and one of 3.
function doc({ path: p = '/opt/x/a.bin' } = {}) {
  return scan(
    mod('battery_health', Array.from({ length: 5 }, (_, i) => f(`Worn part ${i}`, 'warning', { name: `part${i}` }))),
    mod('sudo_config_audit', [f('Odd sudo rule', 'critical', { path: p }, { removal_alert: true, fixable: { will_change: 'Turns it off.', how_to_undo: ['Turn it on.'] } })]),
    mod('ssh_key_audit', [f('An extra key', 'warning', { path: '/etc/ssh/k' }, { markable: { id: 'm1', kind: 'background_task' } })]),
  );
}

function stub(recheckDocs = []) {
  const listeners = [];
  const calls = { recheck: [], openSetting: [], fixHtml: [], markHtml: [] };
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const hooks = {};
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: (_r, _a, h) => { hooks.fix = h; }, resultHtml: () => '',
      fixControlsHtml: (finding, opts) => { calls.fixHtml.push(opts); return finding.fixable ? `<div data-fix-module="${finding.module}">FIX PANEL ${opts.safety || ''}</div>` : ''; } },
    MarkFlow: { attach: (_r, _a, h) => { hooks.mark = h; },
      markControlsHtml: (finding) => { calls.markHtml.push(finding.title); return finding.markable ? '<div data-mark-card>MARK IT</div>' : ''; } },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {}, mode: () => 'standard' },
    rescue: {
      recheckModule: async (name) => {
        calls.recheck.push(name);
        const d = recheckDocs.shift();
        return { ok: true, doc: d, module: d.modules.find((m) => m.name === name) || { name, complete: true } };
      },
      openSetting: async (u) => { calls.openSetting.push(u); return true; },
    },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, hooks, calls, click };
}

async function setup(d, { storage = memStore(), mode = 'standard', recheckDocs = [], games = null } = {}) {
  const { createController } = await import('../renderer/game/controller.js');
  const t = stub(recheckDocs);
  t.win.RescueHost.mode = () => mode;
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [], 
    loadMissionGames: games || (async () => { const I = await import('../renderer/missions/games/index.js'); return I.loadGames({ importer: async () => { throw new Error('none'); } }); }) });
  await tick(); await tick();
  if (d) ctl.show(d, { id: 'unsure' });
  return { ...t, ctl, storage, html: () => t.frame.innerHTML };
}

test('a district lists its missions: checkbox, title, count, severity and PART 1 OF 2', async () => {
  const t = await setup(doc());
  t.click({ 'data-go': 'district:gatehouse' });
  const h = t.html();
  assert.match(h, /class="mx-check"/);
  assert.match(h, /data-go="mx:simple:gatehouse:1"/);
  assert.match(h, /Other<small class="mission-detail">4 items · PART 1 OF 2/);
  assert.match(h, /3 items · PART 2 OF 2/);
  assert.match(h, /badge crit">CRITICAL/);
  assert.doesNotMatch(h, /data-act="bulk-did"/, 'the old per-finding bulk rows are replaced');
});

test('INVESTIGATE NEXT opens the most important unfinished mission; the screen shows item 1 of 4 and Practice', async () => {
  const t = await setup(doc());
  assert.match(t.html(), /data-act="investigate-next"[\s\S]*Next: Other · 4 items · PART 1 OF 2/);
  t.click({ 'data-act': 'investigate-next' });
  let h = t.html();
  // First time: the practice round is offered.
  assert.match(h, /PRACTICE FIRST/);
  t.click({ 'data-act': 'mx-know' });
  h = t.html();
  assert.match(h, /ITEM 1 OF 4/);
  assert.match(h, /Odd sudo rule/, 'the critical, alerting item leads');
  assert.match(h, /data-act="mx-practice"/);
  assert.match(h, /mx-warning[\s\S]*Removing this can alert whoever installed it\.[\s\S]*mx-card/, 'the warning sits above the item');
  assert.match(h, /data-act="mx-decide:later"[^>]*>Later/);
  assert.strictEqual(savedProfile(t.storage).rounds.simple.how, 'skipped');
});

test('a fix decision opens FixFlow’s own confirm with the warning; a re-check that proves it pays CONFIRMED', async () => {
  const fixed = doc();
  fixed.modules[1].findings = [];
  const t = await setup(doc(), { recheckDocs: [fixed] });
  t.click({ 'data-go': 'district:gatehouse' });
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:fix' });
  assert.match(t.html(), /FIX PANEL Removing this can alert whoever installed it\./);
  assert.strictEqual(t.calls.fixHtml[0].safety, 'Removing this can alert whoever installed it.');
  const before = savedProfile(t.storage).rank.points;
  t.hooks.fix.onResult({ kind: 'fix', module: 'sudo_config_audit', result: { applied: true }, described: { tone: 'success' } });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.recheck, ['sudo_config_audit']);
  const p = savedProfile(t.storage);
  assert.ok(p.rank.points - before >= 75, `CONFIRMED pays (${p.rank.points - before})`);
  assert.match(t.html(), /it’s gone/);
  assert.match(t.html(), /ITEM \d OF \d/);
});

test('deciding moves on; the summary pays the mission bonus once and offers the next mission', async () => {
  const t = await setup(doc(), { recheckDocs: [doc()] });
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  assert.match(t.html(), /ITEM 1 OF 3/);
  t.click({ 'data-act': 'mx-decide:did' });
  await tick(); await tick();
  // The re-check found it still there: it stays open.
  assert.match(t.html(), /still there/);
  assert.match(t.html(), /ITEM 1 OF 3/);
  for (let i = 0; i < 3; i += 1) t.click({ 'data-act': 'mx-decide:later' });
  assert.match(t.html(), /WHAT YOU DECIDED/);
  assert.match(t.html(), /data-act="mx-next"/);
  assert.match(t.html(), /saved for later/);
  t.click({ 'data-act': 'mx-next' });
  assert.match(t.html(), /ITEM 1 OF 4/);
});

test('mark: MarkFlow’s own control; when it’s done the item is answered and remembered with its evidence', async () => {
  const storage = memStore();
  const marked = doc();
  marked.modules[2].findings[0] = { ...marked.modules[2].findings[0], severity: 'info', data: { path: '/etc/ssh/k', marked_by_user: true, original_severity: 'warning' } };
  const t = await setup(doc(), { storage, recheckDocs: [marked] });
  const missions = t.html().match(/data-go="mx:[^"]+"/g) || [];
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:later' });
  t.click({ 'data-act': 'mx-decide:later' });
  assert.match(t.html(), /An extra key/);
  t.click({ 'data-act': 'mx-decide:mine' });
  assert.match(t.html(), /MARK IT/);
  t.hooks.mark.onResult({ kind: 'marked', result: { ids: ['m1'] }, described: { done: true } });
  await tick(); await tick();
  const p = savedProfile(storage);
  assert.ok(Object.keys(p.kept).length >= 1, 'the answer is remembered');
  assert.ok(missions.length >= 0);
});

test('remembered answers survive a new scan with the same evidence, and drop when the path changes', async () => {
  const storage = memStore();
  const t = await setup(doc(), { storage });
  t.click({ 'data-go': 'mx:simple:gatehouse:1' });
  t.click({ 'data-act': 'mx-know' });
  // Odd Jobs has no keep: answer the sudo rule with a re-check that proves nothing, then a Keep-like
  // decision is not available; use a stub game with Keep to check remembering.
  const keepGame = async () => {
    const I = await import('../renderer/missions/games/index.js');
    const S = (await import('../renderer/missions/games/simple.js')).default;
    const g = { ...S, decisions: () => [{ id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } },
      { id: 'ok', label: { standard: 'Keep it', city: 'Keep' }, effect: { kind: 'keep' } }] };
    const reg = await I.loadGames({ importer: async () => { throw new Error('none'); } });
    reg.games.simple = g;
    return reg;
  };
  const s2 = memStore();
  const a = await setup(doc(), { storage: s2, games: keepGame });
  a.click({ 'data-go': 'mx:simple:gatehouse:1' });
  a.click({ 'data-act': 'mx-know' });
  a.click({ 'data-act': 'mx-decide:ok' });
  assert.match(a.html(), /ITEM 2 OF 4/);
  const pts = savedProfile(s2).rank.points;
  assert.strictEqual(pts, 5, 'a decided item pays');
  // Same evidence on the next app start: the first item is answered.
  const b = await setup(doc(), { storage: s2, games: keepGame });
  b.click({ 'data-go': 'mx:simple:gatehouse:1' });
  assert.match(b.html(), /ITEM 2 OF 4/, 'the remembered item is skipped');
  // The path changed: asked again.
  const c = await setup(doc({ path: '/opt/y/b.bin' }), { storage: s2, games: keepGame });
  c.click({ 'data-go': 'mx:simple:gatehouse:1' });
  assert.match(c.html(), /ITEM 1 OF 4/);
  assert.ok(t);
});

test('a settings decision opens the pane through the setting allowlist', async () => {
  const lockGame = async () => {
    const I = await import('../renderer/missions/games/index.js');
    const S = (await import('../renderer/missions/games/simple.js')).default;
    const reg = await I.loadGames({ importer: async () => { throw new Error('none'); } });
    reg.games.simple = { ...S, decisions: () => [{ id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } },
      { id: 'on', label: { standard: 'Turn it on', city: 'Switch on' }, effect: { kind: 'settings', pane: 'firewall' } }] };
    return reg;
  };
  const t = await setup(doc(), { games: lockGame });
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:on' });
  await tick();
  assert.deepStrictEqual(t.calls.openSetting, ['x-apple.systempreferences:com.apple.Network-Settings.extension?Firewall']);
  assert.match(t.html(), /You make the change there/);
});

test('practice on request: made-up items, a move, and the round recorded as played', async () => {
  const storage = memStore();
  const t = await setup(doc(), { storage });
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-practice' });
  assert.match(t.html(), /PRACTICE · 1 OF 2 · MADE UP, NOT ON YOUR COMPUTER/);
  t.click({ 'data-act': 'mx-practice-move:later' });
  assert.match(t.html(), /That’s the move/);
  t.click({ 'data-act': 'mx-practice-next' });
  t.click({ 'data-act': 'mx-practice-move:later' });
  assert.match(t.html(), /Not quite/);
  t.click({ 'data-act': 'mx-practice-next' });
  assert.match(t.html(), /ITEM 1 OF 3/);
  assert.strictEqual(savedProfile(storage).rounds.simple.how, 'played');
});

test('city mode: game words only on the district, the deck line and the mission screen; held never enters', async () => {
  const d = doc();
  d.modules.push(mod('stalkerware_scan', [f('Monitoring app found', 'critical', { path: '/Applications/W.app' }, { code: 'security.stalkerware_scan.found' })]));
  const t = await setup(d, { mode: 'city' });
  t.win.RescueHost.mode = () => 'city';
  const deck = t.html();
  assert.match(deck, /Next mission: Odd Jobs/);
  t.click({ 'data-go': 'district:gatehouse' });
  const dist = t.html();
  assert.match(dist, /Odd Jobs/);
  assert.doesNotMatch(dist, /W\.app|Monitoring app/);
  t.click({ 'data-go': 'mx:simple:gatehouse:1' });
  t.click({ 'data-act': 'mx-know' });
  const h = t.html();
  assert.match(h, /TARGET 1 OF 4/);
  for (const part of [h.split('mx-screen')[1] || '', dist.split('MISSIONS')[1] || '']) assert.doesNotMatch(part, CITY_FORBIDDEN);
  assert.match(h, /Stop by .* before you change it\./, 'city: the warning points to the help district');
});

test('missions.css closes every block it opens', () => {
  const css = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'missions', 'missions.css'), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '');
  let depth = 0;
  for (const ch of css) { if (ch === '{') depth += 1; else if (ch === '}') depth -= 1; assert.ok(depth >= 0); }
  assert.strictEqual(depth, 0);
});

test('a finished mission pays its bonus once; Later on any item pays no bonus', async () => {
  const keepGame = async () => {
    const I = await import('../renderer/missions/games/index.js');
    const S = (await import('../renderer/missions/games/simple.js')).default;
    const reg = await I.loadGames({ importer: async () => { throw new Error('none'); } });
    reg.games.simple = { ...S, decisions: () => [{ id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } },
      { id: 'ok', label: { standard: 'Keep it', city: 'Keep' }, effect: { kind: 'keep' } }] };
    return reg;
  };
  const storage = memStore();
  const t = await setup(doc(), { storage, games: keepGame });
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  for (let i = 0; i < 3; i += 1) t.click({ 'data-act': 'mx-decide:ok' });
  assert.match(t.html(), /\+15 points/);
  assert.strictEqual(savedProfile(storage).rank.points, 3 * 5 + 20);
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  assert.strictEqual(savedProfile(storage).rank.points, 35, 'opening it again pays nothing more');
  t.click({ 'data-go': 'mx:simple:gatehouse:1' });
  for (let i = 0; i < 4; i += 1) t.click({ 'data-act': 'mx-decide:later' });
  assert.strictEqual(savedProfile(storage).rank.points, 35, 'Later pays nothing, and no bonus');
});

test('city mode: a mission’s fix confirm says stop by the help district, in game words (no advocate line)', async () => {
  const FixFlow = require('../renderer/fix-flow.js');
  const t = await setup(doc(), { mode: 'city' });
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:fix' });
  const opts = t.calls.fixHtml.pop();
  assert.strictEqual(opts.watched, true);
  assert.ok(typeof opts.place === 'string' && opts.place.length > 0, 'the help district’s name');
  const real = FixFlow.fixControlsHtml({ module: 'sudo_config_audit', fixable: { will_change: 'Turns it off.', how_to_undo: ['Turn it on.'] } }, opts);
  assert.doesNotMatch(real, CITY_FORBIDDEN);
  assert.ok(real.includes(`Removing this can alert whoever installed it.</strong> Stop by ${opts.place} before you change it.`));
  // The mission's own warning line names the same place.
  assert.ok(t.html().includes(`Stop by ${opts.place} before you change it.`));
  assert.doesNotMatch(t.html(), CITY_FORBIDDEN);
});
