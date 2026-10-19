// The "removing it can alert them" warning survives on every finding that
// carries it, outside the three monitoring checks too, in both display modes:
// in the list, in the game's briefing, and (city mode) in the fix panel.
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

test('the list, standard mode: the one line, with the warning behind it; no hotline wording on the card', async () => {
  const html = await listHtml('standard');
  // On its face, before the fix button (P1-8), with the full note behind "Read this first".
  assert.match(html, /<p><strong>Removing this can alert whoever installed it\.<\/strong><\/p><details><summary>Read this first<\/summary>/);
  assert.ok(html.indexOf('Removing this can alert whoever installed it.') < html.indexOf('data-fix-open'), 'the warning comes before the fix button');
  // And in the fix confirm itself.
  assert.match(/<div class="fix-panel"[\s\S]*?data-fix-confirm/.exec(html)[0], /data-fix-safety><strong>Removing this can alert whoever installed it\.<\/strong>/);
  const note = /<div class="finding-card__note finding-card__note--first"[\s\S]*?<\/details><\/div>/.exec(html)[0];
  assert.match(note, ALERT, 'the full note behind the line');
  assert.doesNotMatch(html.replace(note, ''), DV);
  assert.match(html, /select Uninstall/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'the extra warning is city mode’s');
});

test('the list, city mode: nothing quieted, the safety note in full, and the fix panel carries the extra warning', async () => {
  const html = await listHtml('city');
  assert.match(html, /If you think a partner, ex, or family member installed this to monitor you, removing it can alert them\./);
  assert.match(html, /<div class="finding-card__note" role="note"><p>Before you remove or turn anything off: if you think someone close to you set this up to watch you, removing it can alert them\./, 'the safety note on its face');
  assert.ok(html.includes(FixFlow.WATCHED_WARNING), 'WATCHED_WARNING in the fix panel');
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
});

test('the game, city mode: the briefing is unquieted, shows the safety note, and the fix panel carries the extra warning', async () => {
  const { html, seen } = await gameBriefing('city');
  assert.match(html, /If you think a partner, ex, or family member installed this to monitor you, removing it can alert them\./);
  assert.match(html, /<div class="panel safety"><div class="finding-card__note" role="note"><p>Before you remove or turn anything off/);
  assert.ok(html.includes(FixFlow.WATCHED_WARNING), 'WATCHED_WARNING in the fix panel');
  assert.deepStrictEqual(seen, [['fix', true], ['mark', true]]);
});

test('a fix with no engine action: the warning in city mode, in the list and the game; not in standard mode', async () => {
  for (const mode of ['city', 'standard']) {
    const list = await listHtml(mode, 'module');
    const game = (await gameBriefing(mode, 'module')).html;
    for (const [where, html] of [['list', list], ['game', game]]) {
      assert.match(html, /data-fix-module="win_remote_access_audit"/, `${mode} ${where}: the fix is offered`);
      assert.doesNotMatch(html, /data-fix-action=/, `${mode} ${where}: no engine action`);
      assert.strictEqual(html.includes(FixFlow.WATCHED_WARNING), mode === 'city', `${mode} ${where}`);
    }
  }
  assert.ok(FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: true }).includes(FixFlow.WATCHED_WARNING));
  assert.ok(!FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: false }).includes(FixFlow.WATCHED_WARNING));
});
