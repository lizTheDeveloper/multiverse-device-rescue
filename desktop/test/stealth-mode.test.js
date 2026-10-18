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
      mode: () => mode, scanTips: async () => [], leaveGame() {} },
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

test('what stealth shows now (the city map): the hold line and the help, never a fix, a mark or "Removing this"', async () => {
  const t = await stealthController('city');
  t.ctl.show(spyDoc(), { id: 'city' });
  const html = t.frame.innerHTML;
  assert.match(html, /Don’t remove it yet\. Talk to an advocate first\./);
  assert.match(html, /write down the name the scan found/, 'how to keep a quiet record');
  assert.match(html, /talk to an advocate before you remove anything\. In the US: National Domestic Violence Hotline, 1-800-799-7233/);
  assert.match(html, /<details class="finding-card__held-help" open>/, 'the help is open, not behind a click');
  assert.match(html, /data-act="list"/, 'and the way to the list, where the same card is');
  assert.doesNotMatch(html, /Open the city/, 'already in the city');
  assert.doesNotMatch(html, /Removing this can alert/);
  assert.doesNotMatch(html, /\[FIX IT\]|\[IT IS MINE\]|Uninstall/);
  t.click({ 'data-act': 'list' });
  assert.strictEqual(t.calls.list, 1);
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
  assert.deepStrictEqual(briefingNote(Q, 'city', other.primary), { kind: 'none', html: '' });
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
  assert.ok(spy && !('remediation' in spy), 'its copy has no removal steps');
});
