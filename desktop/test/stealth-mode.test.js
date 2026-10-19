const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { page, monitoring } = require('./page-harness.js');
const { forbiddenWrites } = require('./disk-words.js');

const KEY = 'device-rescue.display';

test('city mode opens straight into the game, under a plain title', () => {
  const p = page({ store: { [KEY]: 'city' } });
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.deepStrictEqual(p.calls.game, ['showTraining']);
  const [situation] = p.calls.last.args;
  assert.strictEqual(situation.id, 'city');
  assert.doesNotMatch(situation.title, /watch|partner|safe/i);
  assert.deepStrictEqual(p.calls.scans, [], 'no scan until the person starts one');
});

test('city mode waits for the game to load, then opens it', () => {
  const p = page({ store: { [KEY]: 'city' }, ready: false });
  assert.deepStrictEqual(p.shown(), ['welcome']);
  p.sandbox.RescueGame.isReady = true;
  p.fire('rescue-game-ready');
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('standard mode and a first launch open on the welcome screen', () => {
  for (const store of [{ [KEY]: 'standard' }, {}]) {
    const p = page({ store });
    assert.deepStrictEqual(p.shown(), ['welcome']);
    assert.deepStrictEqual(p.calls.game, []);
  }
});

test('"I think someone is watching me" goes straight into the game, without the question', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.deepStrictEqual(p.storage.writes.filter(([k]) => k === KEY), [[KEY, 'city']]);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.shown(), ['city']);
});

test('the scan screen in city mode names no worry', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.sandbox.RescueHost.leaveGame();
  assert.deepStrictEqual(p.shown(), ['scan']);
  assert.strictEqual(p.byId('scan-situation').textContent, 'Checking your computer');
});

test('a city-mode person who picks a different worry later stays in the game, with no question', async () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.sandbox.RescueHost.leaveGame(); // PLAIN VIEW
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('wifi');
  assert.ok(!p.shown().includes('question'));
  assert.deepStrictEqual(p.calls.game.slice(-2), ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['home_network_intrusion']);
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['city'], 'monitoring software doesn’t take them out of the game');
  assert.strictEqual(p.storage.getItem(KEY), 'city');
  const list = p.byId('results-groups').innerHTML;
  assert.match(list, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.doesNotMatch(list, /\[FIX IT\]|\[IT IS MINE\]/);
});

test('rather not say, then monitoring software: asked once, and "No, I don’t" switches to city', async () => {
  const p = page({ store: {} });
  p.byId('btn-play-game').click();
  p.pick('unsure');
  p.answer('rather-not');
  assert.strictEqual(p.storage.getItem(KEY), 'standard');
  await p.finish(monitoring);
  assert.deepStrictEqual(p.shown(), ['question']);
  assert.match(p.byId('question-card').innerHTML, /We found something that can be used to watch a computer/);
  assert.ok(!p.calls.game.includes('scanDone'), 'nothing lands until they answer');
  p.answer('unknown');
  assert.strictEqual(p.storage.getItem(KEY), 'city');
  assert.ok(p.calls.game.includes('scanDone'));
  assert.deepStrictEqual(p.shown(), ['city']);
  const list = p.byId('results-groups').innerHTML;
  assert.match(list, /Don’t remove it yet\. Talk to an advocate first\./, 'the list was redrawn for city mode');
  assert.doesNotMatch(list, /\[FIX IT\]|\[IT IS MINE\]/, 'no fix and no “It’s mine” for monitoring software');
  assert.doesNotMatch(list, /Removing this can alert/);
});

test('rather not say, then "Yes, I know about it": still standard, the game stays, and the card has the one line', async () => {
  const p = page({ store: {} });
  p.byId('btn-play-game').click();
  p.pick('unsure');
  p.answer('rather-not');
  await p.finish(monitoring);
  p.answer('known');
  assert.strictEqual(p.storage.getItem(KEY), 'standard');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.match(p.byId('results-groups').innerHTML, /Removing this can alert whoever installed it\. Read this first\./);
});

test('nothing the app writes says why, on any route', async () => {
  const runs = [];
  { const p = page({ store: {} }); p.byId('btn-get-started').click(); p.pick('watched'); await p.finish(monitoring); runs.push(p); }
  { const p = page({ store: {} }); p.byId('btn-play-game').click(); p.pick('unsure'); p.answer('yes'); await p.finish(monitoring); runs.push(p); }
  { const p = page({ store: {} }); p.byId('btn-play-game').click(); p.pick('hacked'); p.answer('rather-not'); await p.finish(monitoring); p.answer('unknown'); runs.push(p); }
  { const p = page({ store: { [KEY]: 'city' } }); p.byId('btn-something-changed').click(); p.answer('no'); runs.push(p); }
  for (const p of runs) {
    assert.deepStrictEqual(forbiddenWrites(p.storage), []);
    for (const [k, v] of p.storage.writes) {
      assert.ok(['device-rescue.display', 'device-rescue.city-seed', 'device-rescue.view'].includes(k), k);
      if (k === KEY) assert.ok(['city', 'standard'].includes(v), v);
    }
  }
});

test('the app never shows a notification or calls attention to itself', () => {
  const root = path.join(__dirname, '..');
  const walk = (dir) => fs.readdirSync(dir, { withFileTypes: true })
    .flatMap((e) => (e.isDirectory() ? walk(path.join(dir, e.name)) : [path.join(dir, e.name)]));
  const sources = [path.join(root, 'main.js'), path.join(root, 'preload.js'), ...walk(path.join(root, 'renderer')).filter((f) => f.endsWith('.js'))];
  for (const f of sources) {
    assert.doesNotMatch(fs.readFileSync(f, 'utf8'), /\bNotification\b|showNotification|setBadge|dock\.bounce|requestAttention|flashFrame/, f);
  }
});

// Handed over from earlier reviews.

const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { recordingStore } = require('./disk-words.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const SPY_PATH = '/Library/Application Support/mSpyAgent/agent.app';
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', supported: true, error: null, findings });
const spyDoc = (withRemote = true) => ({ schema_version: 1, platform: 'darwin', modules: [
  mod('stalkerware_scan', [{ severity: 'critical', title: 'Stalkerware found: mSpy', category: 'security', code: 'security.stalkerware_scan.monitoring_software_found',
    description: 'mSpy can record what you type.', data: { path: SPY_PATH, process: 'mSpyAgent' },
    remediation: { steps: [{ number: 1, title: 'Remove it', body: 'Uninstall it with its own uninstaller.' }] } }]),
  mod('remote_login_check', withRemote ? [{ severity: 'warning', title: 'Remote Login is on', category: 'security', description: 'On.', data: {} }] : []),
] });
const NAMES_IT = /mSpy|stalkerware|monitor|spy/i;

test('reconcile never records monitoring software, even if a city ever held it, and drops an old record of it', async () => {
  const { findingsToCity } = await game('findings-to-city.js');
  const { reconcile, setStatus, emptyProgress, ranOkModules } = await game('progress.js');
  const doc = spyDoc();
  const raw = findingsToCity(doc); // without splitHeld: the monitoring mission is in it
  const spy = raw.districts.flatMap((d) => d.missions).find((m) => m.module === 'stalkerware_scan');
  assert.ok(spy, 'the test city does carry a monitoring mission');
  const old = { ...emptyProgress(), missions: { 'stalkerware_scan|old': { status: 'later', module: 'stalkerware_scan', districtId: 'gatehouse', title: 'Stalkerware found: mSpy', updatedAt: 'x' } } };
  const { progress } = reconcile(old, raw, ranOkModules(doc), '2026-10-18T00:00:00Z');
  assert.deepStrictEqual(Object.values(progress.missions).map((r) => r.module), ['remote_login_check']);
  assert.doesNotMatch(JSON.stringify(progress), NAMES_IT);
  assert.ok(!JSON.stringify(progress).includes(SPY_PATH));
  const later = setStatus(progress, spy.id, 'later', 'stalkerware_scan', 'now', { districtId: spy.districtId, title: spy.title });
  assert.doesNotMatch(JSON.stringify(later), NAMES_IT, '"Later" on it records nothing either');
});

// The controller against a stubbed window, as in game-controller.test.js.
async function stealthController(mode, recheckDocs = []) {
  const { createController } = await import('../renderer/game/controller.js');
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); }, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const calls = { list: 0 };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '[FIX IT]', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '[IT IS MINE]' },
    RescueHost: { showList() { calls.list += 1; }, docChanged: () => true, wantsSafety: (f) => Q.noteFor(mode, f) === 'line',
      mode: () => mode, citySeed: () => 777, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async (name) => { const d = recheckDocs.shift() || spyDoc(); return { ok: true, doc: d, module: d.modules.find((m) => m.name === name) }; } },
  };
  const storage = recordingStore();
  const ctl = createController({ win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}), loadTraining: async () => [] });
  const click = (attrs) => { const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) }; clicks.forEach((fn) => fn({ target: { closest: () => el } })); };
  return { ctl, frame, storage, click, calls };
}

test('a stealth session with monitoring software found: nothing written names it or its path', async () => {
  const { findingsToCity } = await game('findings-to-city.js');
  const t = await stealthController('city', [spyDoc(false)]);
  t.ctl.showTraining({ id: 'city', title: 'Take back the city' });
  t.ctl.showBoss();
  t.ctl.scanDone(spyDoc(), { id: 'city' });
  const remote = findingsToCity(spyDoc()).districts.flatMap((d) => d.missions).find((m) => m.module === 'remote_login_check');
  t.click({ 'data-go': 'map' });
  t.click({ 'data-go': `district:${remote.districtId}` });
  t.click({ 'data-go': `mission:${remote.id}` });
  t.click({ 'data-act': 'later' });
  t.click({ 'data-go': `mission:${remote.id}` });
  t.click({ 'data-act': 'i-did-it' });
  await new Promise((r) => setTimeout(r, 0)); await new Promise((r) => setTimeout(r, 0));
  t.ctl.show(spyDoc(), { id: 'city' });
  assert.ok(t.storage.writes.length > 0, 'progress was saved along the way');
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
  for (const [k, v] of t.storage.writes) {
    assert.doesNotMatch(`${k}=${v}`, NAMES_IT, k);
    assert.ok(!v.includes(SPY_PATH) && !v.includes('mSpyAgent'), k);
  }
  assert.doesNotMatch(JSON.stringify(t.storage.data), NAMES_IT);
});

// Task 8: in city mode the generated district takes the interim map note's
// place. The deck names only the place; the hold line, how to keep a quiet
// record and who can help are in the district. (A host that can't say its
// mode keeps the plain map note: see "a host without mode()" below.)
test('what stealth shows (the city): the deck names only the district; in there, the hold line and a quiet record, never a fix, a mark or "Removing this"', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await stealthController('city');
  t.ctl.show(spyDoc(), { id: 'city' });
  const deck = t.frame.innerHTML;
  const name = pickDistrict(777).name;
  assert.ok(deck.includes(`Something new in ${name}`), 'the notice names the place');
  assert.doesNotMatch(deck, /class="panel held"/, 'the interim map note is gone in city mode');
  assert.doesNotMatch(deck, /mSpy|Stalkerware found|stalker|advocate|799-7233|hotline|Don’t remove|Removing this/i, 'nothing on the deck gives it away');
  t.click({ 'data-go': 'side' });
  const html = t.frame.innerHTML;
  assert.match(html, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.match(html, /write down the name the scan found/, 'how to keep a quiet record');
  assert.match(html, /1-800-799-7233/);
  assert.match(html, /Stalkerware found: mSpy/, 'in there, what was found');
  assert.doesNotMatch(html, /Removing this can alert|\[FIX IT\]|\[IT IS MINE\]|Uninstall|data-fix-module|data-mark-card/);
  t.click({ 'data-act': 'side-back' });
  assert.match(t.frame.innerHTML, /INCOMING SIGNALS/);
});

// The list's promise ("Open the city to see how to keep a quiet record of
// it") leads somewhere real: in city mode the deck's notice opens the district,
// which has the record steps.
test('the list’s "Open the city" leads to the district and its quiet record', async () => {
  assert.match(Q.HELD_MORE, /Open the city/);
  const t = await stealthController('city');
  t.ctl.show(spyDoc(), { id: 'city' });
  assert.match(t.frame.innerHTML, /<p class="link-notice" role="status">Something new in [^<]*<button type="button" class="btn-t" data-go="side">/);
  t.click({ 'data-go': 'side' });
  assert.match(t.frame.innerHTML, /On paper or on another device, write down the name the scan found/);
});

test('standard mode in the city: monitoring software is still said on the map, with the one line and its note', async () => {
  const t = await stealthController('standard');
  t.ctl.show(spyDoc(), { id: 'unsure' });
  const html = t.frame.innerHTML;
  assert.match(html, /Stalkerware found: mSpy/);
  assert.match(html, /<details class="finding-card__note"><summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/);
  assert.match(html, /talk to an advocate before you remove anything/);
  assert.doesNotMatch(html, /Don’t remove it yet/);
});

test('the briefing on monitoring software: the line and the full note (standard); the hold line, the help and nothing to act on (city)', async () => {
  const { findingsToCity } = await game('findings-to-city.js');
  const { renderBriefing } = await game('views/briefing.js');
  const { briefingNote } = await game('held.js');
  const m = findingsToCity(spyDoc()).districts.flatMap((d) => d.missions).find((x) => x.module === 'stalkerware_scan');
  assert.ok(!m.safetyNote, 'the engine gives stalkerware no safety_note');
  const brief = (mode) => renderBriefing({ mission: m, status: 'open', controlsHtml: '[FIX IT][IT IS MINE]', scout: () => '', busy: false,
    wantsSafety: Q.noteFor(mode, m.primary) === 'line', note: briefingNote(Q, mode, m.primary) });
  const std = brief('standard');
  assert.match(std, /Removing this can alert whoever installed it\. Read this first\./);
  assert.match(std, /talk to an advocate before you remove anything/, 'the full note behind it');
  const city = brief('city');
  assert.match(city, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.match(city, /write down the name the scan found/);
  assert.doesNotMatch(city, /Removing this can alert|YOUR MOVE|Uninstall|I DID IT|\[FIX IT\]|\[IT IS MINE\]/);
  // Anything else is as before.
  const other = findingsToCity(spyDoc()).districts.flatMap((d) => d.missions).find((x) => x.module === 'remote_login_check');
  const none = briefingNote(Q, 'city', other.primary);
  assert.deepStrictEqual([none.kind, none.html], ['none', '']);
});

test('the list in city mode: the hold line with its help, no points, and no removal steps in "Copy for any AI"', async () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  await p.finish(spyDoc());
  const list = p.byId('results-groups').innerHTML;
  const spyCard = /<li class="finding-card finding-card--critical"[^>]*>[\s\S]*?Stalkerware found: mSpy[\s\S]*?<\/li>\s*<\/ul>/.exec(list)[0];
  assert.match(spyCard, /data-card-counts="0"/, 'no points for it');
  assert.match(spyCard, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.match(spyCard, /How to keep a quiet record, and who can help/);
  assert.doesNotMatch(spyCard, /\[FIX IT\]|\[IT IS MINE\]|Uninstall|Show me how|What to do/);
  assert.match(list, /data-card-counts="1"[\s\S]*Remote Login is on/, 'other findings still count');
  const picks = JSON.parse(p.run('JSON.stringify(copyAiRegistry)'));
  const spy = picks.find((x) => x.module === 'stalkerware_scan');
  assert.ok(spy && !('remediation' in spy) && !('data' in spy), 'its copy has no removal steps and no evidence');
});

// Fix round 1.

// Independent of QuietNotes.ACTS on purpose: any word that tells the person to
// act on the software.
const ACT_WORDS = /remov|uninstall|delet|disabl|\bmov(?:e|es|ed|ing)\b|\b(?:turn|switch)\w*\b(?:\s+\S+){0,4}?\s+off\b|what to do|get rid/i;
const REAL = require('./fixtures/monitoring-descriptions.json');

test('the fixture of real monitoring descriptions covers every monitoring check, and is the one the engine writes', () => {
  const mods = new Set(REAL.map((r) => r.module));
  assert.deepStrictEqual([...mods].sort(), [...Q.MONITORING_MODULES].sort());
  assert.ok(REAL.filter((r) => ACT_WORDS.test(r.description)).length >= 10, 'the engine’s own text does tell people to act on it');
  // tests/test_monitoring_descriptions.py fails when it is stale.
});

test('a held card says only what the software is: no removal or turn-off sentence from any real description survives', () => {
  for (const r of REAL.filter((x) => Q.isDetection(x))) {
    const f = { module: r.module, code: r.code, title: 'x', description: r.description,
      remediation: { steps: [{ number: 1, title: 'Remove it', body: 'Uninstall it.' }] } };
    const card = Q.cardText('city', f);
    assert.strictEqual(card.note, 'held');
    assert.deepStrictEqual(card.steps, []);
    assert.doesNotMatch(card.description, ACT_WORDS, `${r.code}: ${card.description}`);
    assert.doesNotMatch(card.description, /799-7233|advocate|hotline/i, r.code);
    assert.ok(card.description.trim().length > 0, r.code);
    assert.ok(!card.description.includes('\n\n'), `${r.code}: the first paragraph only`);
  }
  // What it is stays: the real keylogger critical keeps its first paragraph.
  const kl = REAL.find((r) => r.code === 'security.keylogger_indicators.known_keyloggers');
  const card = Q.cardText('city', { module: kl.module, description: kl.description });
  assert.match(card.description, /These apps can secretly record everything you type/);
  assert.doesNotMatch(card.description, /Input Monitoring and turn off|move the app folders/);
  // Standard mode is as Task 6 left it: the description, steps and the one line.
  const std = Q.cardText('standard', { module: kl.module, description: kl.description, remediation: { steps: [{ title: 'Remove it', body: 'b' }] } });
  assert.strictEqual(std.note, 'line');
  assert.match(std.description, /What to do: If you are safe to proceed/);
  assert.strictEqual(std.steps.length, 1);
});

test('the list in city mode, with every real description: outside the hold line and its help, no card says to act on it', async () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  const byMod = {};
  REAL.filter((x) => Q.isDetection(x)).forEach((r, i) => (byMod[r.module] = byMod[r.module] || []).push({ severity: 'critical', title: `Item ${i}`, code: r.code, category: 'security',
    description: r.description, data: {}, remediation: { steps: [{ number: 1, title: 'Remove it', body: 'Uninstall it.' }] } }));
  await p.finish({ schema_version: 1, platform: 'darwin', modules: Object.entries(byMod).map(([n, fs]) => mod(n, fs)) });
  const list = p.byId('results-groups').innerHTML;
  const cards = list.split('<li class="finding-card').slice(1);
  assert.strictEqual(cards.length, REAL.filter((x) => Q.isDetection(x)).length);
  for (const c of cards) {
    const rest = c.replace(/<p class="finding-card__note" role="note">[\s\S]*?<\/p>/, '')
      .replace(/<details class="finding-card__held-help">[\s\S]*?<\/details>/, '');
    assert.match(c, /Don’t remove it yet/);
    assert.doesNotMatch(rest, ACT_WORDS, rest.slice(0, 400));
  }
});

test('the briefing on a real held finding says what it is, not the engine’s steps', async () => {
  const { renderBriefing } = await game('views/briefing.js');
  const { findingsToCity } = await game('findings-to-city.js');
  const { briefingNote } = await game('held.js');
  const kl = REAL.find((r) => r.code === 'security.keylogger_indicators.known_keyloggers');
  const doc = { modules: [mod('keylogger_indicators', [{ severity: 'critical', title: 'Known keylogger app found', description: kl.description, category: 'security', data: {} }])] };
  const m = findingsToCity(doc).districts.flatMap((d) => d.missions)[0];
  const html = renderBriefing({ mission: m, status: 'open', controlsHtml: '', scout: () => '', busy: false, wantsSafety: false, note: briefingNote(Q, 'city', m.primary) });
  const whatItIs = /WHAT IT IS<\/div><p class="intel">([\s\S]*?)<\/p>/.exec(html)[1];
  assert.match(whatItIs, /secretly record everything you type/);
  assert.doesNotMatch(whatItIs, ACT_WORDS);
});

test('"Copy for any AI" and "Ask about this" on a held card: the card’s own text, no path, and the instruction', async () => {
  const { buildAiPrompt, HELD_NOTE } = require('../ai-prompt.js');
  const { buildAskBody } = require('../ask-about.js');
  const p = page({ store: { [KEY]: 'city' } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  await p.finish(spyDoc());
  const NOTE = 'Don’t suggest removing or disabling it; the person may be at risk if it’s removed. Suggest documenting it and talking to an advocate.';
  assert.strictEqual(HELD_NOTE, NOTE);
  assert.strictEqual(Q.HELD_AI_NOTE, NOTE);
  const picks = JSON.parse(p.run('JSON.stringify(copyAiRegistry)'));
  const spy = picks.find((x) => x.module === 'stalkerware_scan');
  assert.deepStrictEqual(Object.keys(spy).sort(), ['category', 'code', 'description', 'held', 'module', 'severity', 'title']);
  const text = buildAiPrompt({ findings: [spy], platform: 'darwin' }, { home: '/Users/x', user: 'x', hostnames: [] });
  assert.ok(text.includes(`Please note: ${NOTE}`), 'the copy carries the instruction');
  assert.ok(!text.includes(SPY_PATH) && !text.includes('mSpyAgent'), 'no path, no process');
  assert.doesNotMatch(text.split('# What the checkup found')[1], /Uninstall|fix steps|Evidence:/);
  const remote = buildAiPrompt({ findings: [picks.find((x) => x.module === 'remote_login_check')] }, { home: '/Users/x', user: 'x', hostnames: [] });
  assert.ok(!remote.includes('Please note:'), 'other findings are as before');
  const asks = JSON.parse(p.run('JSON.stringify(askRegistry)'));
  const ask = asks.find((x) => /mSpy/.test(x.title));
  assert.ok(ask.description.endsWith(NOTE), 'the ask carries the instruction');
  assert.ok(!ask.description.includes(SPY_PATH) && !/Uninstall/.test(ask.description));
  const body = buildAskBody({ finding: ask }, { home: '/Users/x', user: 'x', hostnames: [] });
  assert.ok(body && body.finding.description.includes(NOTE), 'and it survives the ask’s own checks');
  // Standard mode is unchanged: the raw finding, its steps and evidence.
  const s = page({ store: { [KEY]: 'standard' } });
  s.byId('btn-get-started').click();
  s.pick('hacked');
  s.byId('btn-run-scan').click();
  await s.finish(spyDoc());
  s.answer('known');
  const sp = JSON.parse(s.run('JSON.stringify(copyAiRegistry)')).find((x) => x.module === 'stalkerware_scan');
  assert.ok(sp.remediation && sp.data && !sp.held);
});

test('a host that doesn’t say its mode: the game holds monitoring software, as in city mode', async () => {
  const { createController } = await import('../renderer/game/controller.js');
  const frame = { innerHTML: '', addEventListener: () => {}, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) }, QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '[FIX IT]', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '[IT IS MINE]' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, scanTips: async () => [], leaveGame() {} }, // no mode()
    rescue: { recheckModule: async () => ({ ok: false }) },
  };
  const ctl = createController({ win, storage: recordingStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}), loadTraining: async () => [] });
  ctl.show(spyDoc(), { id: 'unsure' });
  assert.match(frame.innerHTML, /SOMETHING THE CHECKUP FOUND/);
  assert.doesNotMatch(frame.innerHTML, /Stalkerware found|Removing this can alert/);
  const { briefingNote } = await game('held.js');
  assert.strictEqual(briefingNote(Q, 'city', { module: 'keylogger_indicators' }).kind, 'held');
});
