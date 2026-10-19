// The "removing it can alert them" warning survives on every finding that
// carries it, outside the three monitoring checks too, in both display modes:
// on the city's LIST (read-only), in the game's briefing, and in the fix panel
// (the missions' own; the LIST has none).
// Run against the engine's real TeamViewer finding (scripts/remote_access_fixture.py).
const test = require('node:test');
const assert = require('node:assert');
const Q = require('../renderer/quiet-notes.js');
const FixFlow = require('../renderer/fix-flow.js');
const { page } = require('./page-harness.js');
const { recordingStore } = require('./disk-words.js');
const REAL = require('./fixtures/remote-access-finding.json');

const ALERT = /removing it can alert them/;
const DV = /799-7233|88788|advocate|domestic\s+violence/i;
// The contract's stealth words (missions/contract.js CITY_FORBIDDEN), read from its source.
const CITY_FORBIDDEN = (() => {
  const src = require('fs').readFileSync(require('path').join(__dirname, '..', 'renderer', 'missions', 'contract.js'), 'utf8');
  const m = /export const CITY_FORBIDDEN = \/(.+)\/([a-z]*);/.exec(src);
  return new RegExp(m[1], m[2]);
})();
// What a fix the engine can do would offer (an action fix), so the panel is real.
const FIXABLE = { action: 'disable_launch_agent', target: '/Library/LaunchAgents/com.teamviewer.service.plist',
  will_change: 'Stops TeamViewer starting by itself.', how_to_undo: ['Turn it back on.'] };

// A module fix (no engine action): what app_fixes.json offers.
const MODULE_FIX = { will_change: 'Turns off TeamViewer\u2019s background service.', how_to_undo: ['Turn it back on in TeamViewer.'] };

function doc({ fixable = false } = {}) {
  const finding = JSON.parse(JSON.stringify(REAL.finding));
  if (fixable === 'module') finding.fixable = MODULE_FIX;
  else if (fixable) finding.fixable = FIXABLE;
  return { schema_version: 1, platform: 'win32', modules: [{ name: REAL.name, category: REAL.category, status: 'ok', supported: true, findings: [finding] }] };
}

test('the fixture is the engine’s real TeamViewer finding, with its warning and its safety note', () => {
  assert.strictEqual(REAL.finding.code, 'security.win_remote_access_audit.teamviewer_installed');
  assert.match(REAL.finding.description, ALERT);
  assert.match(REAL.finding.description, /select Uninstall/);
  assert.match(REAL.finding.remediation.safety_note, ALERT);
  assert.ok(!Q.MONITORING_MODULES.has(REAL.name), 'not one of the monitoring checks');
});

async function listHtml(mode, fixable = true) {
  const p = page({ store: { 'device-rescue.display': mode }, ready: false });
  p.sandbox.FixFlow.fixControlsHtml = FixFlow.fixControlsHtml;
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(doc({ fixable }));
  assert.deepStrictEqual(p.shown(), ['results'], mode);
  return p.byId('results-groups').innerHTML;
}

test('the LIST, standard mode: the one line on the card, the note once above the list; no hotline wording on its face; no fix', async () => {
  const html = await listHtml('standard');
  // On its face, with "Read this first" pointing at the note above the list (round 5).
  assert.match(html, /<p class="finding-card__note finding-card__note--first" role="note" data-safety-line><strong>Removing this can alert whoever installed it\.<\/strong> <button type="button" class="link-button" data-safety-jump>Read this first<\/button><\/p>/);
  assert.doesNotMatch(html, /data-fix-open|data-fix-confirm/, 'the LIST is read-only: the fix (and its confirm\'s warning) is the mission\'s');
  assert.ok(html.indexOf('id="results-safety"') < html.indexOf('data-card-key'), 'the banner is above the list');
  const note = /<details data-safety-details>[\s\S]*?<\/details>/.exec(html)[0];
  assert.match(note, ALERT, 'the full note behind "Read this first" in the banner');
  assert.doesNotMatch(html.replace(note, ''), DV);
  assert.match(html, /select Uninstall/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'the extra warning is city mode’s');
});

test('the LIST, city mode: nothing quieted, the safety note in full; no fix panel (the mission\'s carries the extra warning)', async () => {
  const html = await listHtml('city');
  assert.match(html, /If you think a partner, ex, or family member installed this to monitor you, removing it can alert them\./);
  assert.match(html, /<div class="finding-card__note" role="note"><p>Before you remove or turn anything off: if you think someone close to you set this up to watch you, removing it can alert them\./, 'the safety note on its face');
  assert.doesNotMatch(html, /data-fix-open/);
});

async function gameBriefing(mode, fixable = true) {
  const { createController } = await import('../renderer/game/controller.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); }, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const seen = [];
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: (f, opts) => { seen.push(['fix', opts && opts.watched]); return FixFlow.fixControlsHtml(f, opts); }, resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: (_f, opts) => { seen.push(['mark', opts && opts.watched]); return ''; } },
    RescueHost: { mode: () => mode, citySeed: () => 777, showList() {}, docChanged: () => true,
      wantsSafety: (f) => ['line', 'full'].includes(Q.noteFor(mode, f)), scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }) },
  };
  const ctl = createController({ win, storage: recordingStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  const d = doc({ fixable });
  ctl.show(d, { id: mode === 'city' ? 'city' : 'unsure' });
  const m = findingsToCity(d).districts.flatMap((x) => x.missions)[0];
  const click = (attrs) => { const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) }; clicks.forEach((fn) => fn({ target: { closest: () => el } })); };
  click({ 'data-go': `district:${m.districtId}` });
  click({ 'data-go': `mission:${m.id}` });
  return { html: frame.innerHTML, seen };
}

test('the game, standard mode: the briefing keeps the one line with the warning behind it', async () => {
  const { html, seen } = await gameBriefing('standard');
  assert.match(html, /TeamViewer is installed/);
  assert.match(html, /<summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/);
  const note = /<details class="finding-card__note">[\s\S]*?<\/details>/.exec(html)[0];
  assert.match(note, ALERT);
  assert.doesNotMatch(html.replace(note, ''), DV);
  assert.deepStrictEqual(seen, [['fix', false], ['mark', false]]);
  // The fix confirm says it too (moved here from the retired Plain cards).
  assert.match(/<div class="fix-panel"[\s\S]*?data-fix-confirm/.exec(html)[0], /data-fix-safety><strong>Removing this can alert whoever installed it\.<\/strong>/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'the extra warning is city mode’s');
});

test('the game, city mode: the help lives in the help district; the mission keeps one warning line before the fix, and the fix panel says stop by it, in game words', async () => {
  const { html, seen } = await gameBriefing('city');
  // UX round 1 ruling (P1-3): no hotline or advocate wording in a city mission, the fix panel included.
  assert.doesNotMatch(html, DV);
  assert.doesNotMatch(html, CITY_FORBIDDEN);
  assert.match(html, /<b>Removing this can alert whoever installed it\.<\/b>/);
  assert.match(html, /data-go="side"/, 'the way to the help district');
  assert.ok(html.indexOf('Removing this can alert whoever installed it') < html.indexOf('data-fix-module'), 'the warning comes before the fix');
  assert.match(html, /TeamViewer is installed/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'never the advocate line in the city');
  const panel = /<div class="fix-panel"[\s\S]*?data-fix-confirm/.exec(html)[0];
  assert.match(panel, /data-fix-city><strong>Removing this can alert whoever installed it\.<\/strong> Stop by [A-Z][^<.]+ before you change it\./);
  assert.deepStrictEqual(seen, [['fix', true], ['mark', true]]);
});

test('a fix with no engine action: the warning in city mode, in the game; not in standard mode', async () => {
  for (const mode of ['city', 'standard']) {
    const game = (await gameBriefing(mode, 'module')).html;
    for (const [where, html] of [['game', game]]) {
      assert.match(html, /data-fix-module="win_remote_access_audit"/, `${mode} ${where}: the fix is offered`);
      assert.doesNotMatch(html, /data-fix-action=/, `${mode} ${where}: no engine action`);
      assert.ok(!html.includes(FixFlow.WATCHED_WARNING), `${mode} ${where}: never the advocate line in the game`);
      assert.strictEqual(/data-fix-city><strong>Removing this can alert whoever installed it\.<\/strong> Stop by /.test(html), mode === 'city', `${mode} ${where}`);
    }
  }
  assert.ok(FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: true }).includes(FixFlow.WATCHED_WARNING));
  assert.ok(!FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: false }).includes(FixFlow.WATCHED_WARNING));
  // With the help district's name (the game in city mode): the game words, never the advocate line.
  const city = FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: true, place: 'The <Old> Mill' });
  assert.ok(!city.includes(FixFlow.WATCHED_WARNING));
  assert.doesNotMatch(city, CITY_FORBIDDEN);
  assert.ok(city.includes(`${FixFlow.CITY_WARNING}</strong> Stop by The &lt;Old&gt; Mill before you change it.`));
});
