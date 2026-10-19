'use strict';
// The notes mini-game: Signal or Noise in batches of good-to-know notes.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const R = path.join(__dirname, '..', 'renderer', 'missions');
const loadC = () => import(pathToFileURL(path.join(R, 'contract.js')).href);
const loadN = () => import(pathToFileURL(path.join(R, 'games', 'notes.js')).href);
const FIX = require('./fixtures/missions/notes-batch.json');
// A practice step's best move (`expect` is one id or a list, the best first).
const first = (e) => (Array.isArray(e) ? e[0] : e);

async function setup() {
  const C = await loadC();
  const N = await loadN();
  const items = FIX.notes.map(({ area, unfinished, ...f }) => C.makeItem({ severity: 'info', ...f }, { district: area, unfinished: !!unfinished }));
  return { C, N, game: N.default, items };
}
const byTitle = (items, re) => items.find((i) => re.test(i.finding.title));

test('notes passes every contract check on its fixtures and practice', async () => {
  const { C, game, items } = await setup();
  assert.deepStrictEqual(C.runContractChecks(game, items), []);
});

test('covers every info finding not claimed by another game', async () => {
  const { N, game } = await setup();
  assert.deepStrictEqual(N.covers, [{ module: '*', severities: ['info'] }]);
  assert.strictEqual(game.covers, N.covers);
  assert.strictEqual(game.type, 'notes');
  assert.deepStrictEqual(game.title, { standard: 'Good to know', city: 'Signal or Noise' });
});

test('two decisions: Normal (note) first, Odd (odd) carrying what the runner needs', async () => {
  const { C, game, items } = await setup();
  const item = items[0];
  for (const mode of ['standard', 'city']) {
    const d = game.decisions(item, C.testContext({ mode }));
    assert.deepStrictEqual(d.map((x) => x.id), ['normal', 'odd']);
    assert.deepStrictEqual(d[0].effect, { kind: 'note', key: item.key });
    assert.deepStrictEqual(d[1].effect, { kind: 'odd', key: item.key, module: 'scheduled_tasks_audit', code: 'security.scheduled_tasks_audit.launch_agent_info' });
  }
  const d = game.decisions(item, C.testContext());
  assert.deepStrictEqual(d.map((x) => x.label.standard), ['Looks normal', 'Looks odd']);
  assert.deepStrictEqual(d.map((x) => x.label.city), ['Noise, normal', 'Signal, odd']);
});

test('research: evidence rows from ctx, a settings pane, a look-up and the lesson', async () => {
  const { C, game, items } = await setup();
  const rows = [{ label: 'Label', value: 'com.example.sync-agent' }];
  const ctx = C.testContext({ evidenceRows: (f, o) => (f.title.startsWith('Background') && o.mode === 'standard' ? rows : []) });
  const r = game.research(items[0], ctx);
  assert.deepStrictEqual(r.rows, rows);
  assert.strictEqual(r.what, 'Example Sync: keeps a folder in step with the cloud.');
  assert.deepStrictEqual(r.links, [
    { kind: 'settings', pane: 'login-items' },
    { kind: 'lookup', source: 'web', query: 'com.example.sync-agent' },
    { kind: 'lesson', concept: 'where-it-lives' },
  ]);
  assert.strictEqual(r.copy, true);
  const mic = game.research(byTitle(items, /^Microphone/), ctx);
  assert.deepStrictEqual(mic.links[0], { kind: 'settings', pane: 'privacy-microphone' });
});

test('Windows: notes from win_* checks get ms-settings panes', async () => {
  const { C, N, game, items } = await setup();
  const win = byTitle(items, /^Startup program/);
  assert.deepStrictEqual(game.research(win, C.testContext({ platform: 'win32' })).links[0], { kind: 'settings', pane: 'startup-apps' });
  assert.strictEqual(N.paneFor({ module: 'win_temp_cleanup' }, 'win32'), 'windows-storage');
  assert.strictEqual(N.paneFor({ module: 'win_windows_update_status' }, 'win32'), 'windows-update');
  assert.strictEqual(N.paneFor({ module: 'privacy_permissions_audit', data: { service: 'kTCCServiceCamera' } }, 'win32'), 'windows-privacy');
  assert.strictEqual(N.paneFor({ module: 'scheduled_tasks_audit' }, 'linux'), null);
});

test('render shows the clues, borrowing a scheduled task’s command as where it lives', async () => {
  const { C, N, game } = await setup();
  const ctx = C.testContext();
  const [, odd] = N.practice.items;
  const html = game.render({ item: odd, research: game.research(odd, ctx), decisions: game.decisions(odd, ctx), index: 1, total: 5 }, ctx);
  assert.match(html, /WHERE IT LIVES/);
  assert.match(html, /~\/\.hidden\/updater\.sh/);
  assert.match(html, /One clue: it lives in a hidden folder\./);
  assert.match(html, /Note 2 of 5/);
  assert.doesNotMatch(html, /data-decision|<button/, 'the runner renders the decision buttons');
  const multi = C.makeItem({ severity: 'info', title: 'x', description: 'Line one\nLine two' });
  assert.match(game.render({ item: multi, research: game.research(multi, ctx), decisions: [], index: 0, total: 1 }, ctx), /Line one Line two/);
});

test('an unfinished check says so; nothing reads clean', async () => {
  const { C, game, items } = await setup();
  const dns = byTitle(items, /^DNS/);
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const r = game.research(dns, ctx);
    assert.strictEqual(r.unfinished, true);
    const html = game.render({ item: dns, research: r, decisions: [], index: 0, total: 1 }, ctx);
    assert.match(html, /didn’t finish/i);
    assert.doesNotMatch(html, /all clear|nothing (?:to worry|wrong)|you(?:’|')re safe/i);
  }
});

test('city mode: a monitoring check’s note stays in game words, with no evidence, look-up or clipboard', async () => {
  const { C, game, items } = await setup();
  const phone = byTitle(items, /iPhone backup/);
  const ctx = C.testContext({ mode: 'city', evidenceRows: () => [{ label: 'Check', value: 'spyware scan' }] });
  const r = game.research(phone, ctx);
  assert.deepStrictEqual(r.rows, []);
  assert.strictEqual(r.copy, false);
  assert.ok(!r.links.some((l) => l.kind === 'lookup'));
  const html = game.render({ item: phone, research: r, decisions: game.decisions(phone, ctx), index: 0, total: 1 }, ctx);
  assert.deepStrictEqual(C.checkCityWords(html), []);
  assert.match(html, /A quiet check left a note/);
  // Standard mode keeps the scan's own words.
  const s = C.testContext();
  assert.match(game.render({ item: phone, research: game.research(phone, s), decisions: [], index: 0, total: 1 }, s), /iPhone backup can be checked/);
});

test('city mode never prints a non-game word from scan text', async () => {
  const { C, game } = await setup();
  const leak = C.makeItem({ severity: 'info', module: 'dns_config', title: 'Partner tool note', description: 'stalkerware words', data: { path: '/tmp/spy/x' } });
  const ctx = C.testContext({ mode: 'city' });
  const html = game.render({ item: leak, research: game.research(leak, ctx), decisions: [], index: 0, total: 1 }, ctx);
  assert.deepStrictEqual(C.checkCityWords(html), []);
});

test('practice: three made-up notes, normal / odd / normal, scripted in both modes', async () => {
  const { N } = await setup();
  const { items, script } = N.practice;
  assert.strictEqual(items.length, 3);
  assert.deepStrictEqual(script.map((s) => first(s.expect)), ['normal', 'odd', 'normal']);
  assert.deepStrictEqual(script.map((s) => s.item), [0, 1, 2]);
  for (const s of script) for (const m of ['standard', 'city']) assert.ok(s.say[m] && s.say[m].length < 220);
  assert.ok(items.every((i) => i.severity === 'info' && i.practice === true));
  assert.match(items[0].finding.data.location, /^\/System\/Library\/LaunchDaemons\//);
  assert.match(items[1].finding.data.command, /^~\/\.hidden\//);
  assert.strictEqual(items[2].finding.module, 'privacy_permissions_audit');
  assert.doesNotMatch(JSON.stringify(items), /\/Users\/|\/home\//);
});

test('practice render shows the banner and the step', async () => {
  const { C, N, game } = await setup();
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode, practice: true });
    const step = N.practice.script[1];
    const item = N.practice.items[step.item];
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 1, total: 3, practice: true, step }, ctx);
    assert.match(html, mode === 'city' ? /DRILL/ : /PRACTICE/);
    assert.ok(html.includes(ctx.esc(step.say[mode])));
    assert.deepStrictEqual(C.checkCityWords(mode === 'city' ? html : ''), []);
  }
});

test('summary: batch points, overall and area progress, and the area bonus', async () => {
  const { C, game, items } = await setup();
  const results = [
    { item: items[0], decision: 'normal', effect: { kind: 'note' }, points: 10 },
    { item: items[1], decision: 'normal', effect: { kind: 'note' }, points: 10 },
    { item: items[2], decision: 'odd', effect: { kind: 'odd' }, points: 10 },
  ];
  const ctx = C.testContext({ notes: { sorted: 120, total: 394, areaSorted: 12, areaTotal: 40, batchPoints: 20 } });
  const s = game.summary(results, ctx);
  assert.match(s, /3 notes sorted: 2 normal, 1 odd\./);
  assert.match(s, /The odd one became a mission of its own/);
  assert.match(s, /\+50 points for this batch/);
  assert.match(s, /120 of 394 sorted/);
  assert.match(s, /12 of 40 in The Gatehouse/);
  assert.doesNotMatch(s, /bonus/i);
  const big = game.summary(results, C.testContext({ notes: { sorted: 1200, total: 4837, areaSorted: 40, areaTotal: 40, cleared: true, bonus: 100 } }));
  assert.match(big, /1,200 of 4,837 sorted/);
  assert.match(big, /You sorted every note in The Gatehouse\. \+100 bonus points\./);
  assert.doesNotMatch(big + s, /all clear/i);
  const city = game.summary(results, C.testContext({ mode: 'city', notes: { sorted: 5, total: 9, cleared: true, bonus: 100 } }));
  assert.match(city, /2 noise, 1 signal/);
  assert.match(city, /\+30 POINTS/);
  assert.match(city, /\+100 BONUS/);
  assert.deepStrictEqual(C.checkCityWords(city), []);
});

test('summary reads progress from results.progress too, and copes with nothing sorted', async () => {
  const { C, game } = await setup();
  const rs = [];
  rs.progress = { sorted: 3, total: 7 };
  const s = game.summary(rs, C.testContext());
  assert.match(s, /No notes sorted in this batch\./);
  assert.match(s, /3 of 7 sorted/);
  assert.doesNotMatch(s, /points/);
});

test('summary words: no time words or estimates', async () => {
  const { C, game, items } = await setup();
  const all = ['standard', 'city'].map((mode) => game.summary([{ item: items[0], decision: 'odd', points: 5 }], C.testContext({ mode, notes: { sorted: 1, total: 2 } }))).join(' ');
  assert.doesNotMatch(all, /\b(?:minute|second|hour|soon|quick|later|now|whenever|today)\b/i);
});

test('batchNotes: batches of five per area, in order, held and to-do items left out', async () => {
  const { C, N, items } = await setup();
  const held = C.makeItem({ severity: 'info', title: 'held' }, { district: 'The Gatehouse', held: true });
  const todo = C.makeItem({ severity: 'warning', title: 'todo' }, { district: 'The Gatehouse' });
  const b = N.batchNotes([...items, held, todo]);
  assert.deepStrictEqual(b.map((x) => [x.area, x.part, x.parts, x.items.length]), [
    ['The Gatehouse', 1, 2, 5], ['The Gatehouse', 2, 2, 1], ['Harbor Row', 1, 1, 3],
  ]);
  assert.strictEqual(b[0].items[0], items[0]);
  assert.strictEqual(N.BATCH_SIZE, 5);
  assert.deepStrictEqual(N.batchNotes(items, { areaOf: () => 'x', size: 4 }).map((x) => x.items.length), [4, 4, 1]);
});

test('engine wording becomes one plain headline; the evidence keeps the details', async () => {
  const C = await loadC();
  const N = await loadN();
  const f = { module: 'ai_threat_indicators', severity: 'info', category: 'security', title: 'Found process with AI reference: /Users/example/tools/blender-mcp --serve',
    description: 'Review these entries to ensure they are legitimate.', data: { process: '/Users/example/tools/blender-mcp --serve' } };
  const item = C.makeItem(f);
  const rows = [{ label: 'Program', value: f.data.process }];
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode, evidenceRows: () => rows });
    const r = N.default.research(item, ctx);
    assert.deepStrictEqual(r.rows, rows, 'the evidence is untouched');
    const html = N.default.render({ item, research: r, index: 0, total: 1 }, ctx);
    assert.match(html, /A running program mentions AI: blender-mcp/);
    assert.doesNotMatch(html, /Found process with AI reference|\/Users\/example/);
    assert.deepStrictEqual(C.checkInert(html), []);
  }
  assert.strictEqual(N.plainTitle('Screen Recording access: 3 app(s)'), 'Screen Recording access: 3 apps');
  assert.strictEqual(N.plainTitle('Found 1 leftover user profile(s)'), '1 leftover user profile');
  assert.strictEqual(N.plainTitle('Background item: com.example.x'), 'Background item: com.example.x');
});
