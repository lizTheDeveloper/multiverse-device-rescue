// The "removing it can alert them" warning survives on every finding that
// carries it, outside the three monitoring checks too, in both display modes:
// on the LIST (read-only), on the game's mission screen (a remote tool is the
// Guest Book's quiz in standard mode: the warning on every question and at the
// outcome, before any removal), in the fix panel, and, in city mode, in the help
// district, where a remote tool is held and never a mission.
// Run against the engine's real AnyDesk finding (remote_access_tools; scripts/remote_access_fixture.py).
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

test('the fixture is the engine’s real AnyDesk finding, with its warning and its safety note', () => {
  assert.strictEqual(REAL.finding.code, 'security.remote_access_tools.tool_found');
  assert.strictEqual(REAL.finding.removal_alert, true, 'the warning is decided by code (rescue/safety_scope.py)');
  assert.doesNotMatch(REAL.finding.description, DV, 'the check’s own words never name a relationship or a hotline');
  assert.match(REAL.finding.description, /What to do:/);
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
  if (mode === 'standard') {
    // A remote-access tool can be how someone watches a screen (app.js CITY_HELD_MODULES), so standard mode
    // asks the follow-up once, as for monitoring software; "Yes, I know about it" stays in standard mode.
    assert.deepStrictEqual(p.shown(), ['question'], mode);
    assert.match(p.byId('question-card').innerHTML, /something that can be used to watch a computer/);
    p.answer('known');
  }
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
  assert.match(html, /AnyDesk lets someone else see and control this computer/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'the extra warning is city mode’s');
});

test('the LIST, city mode: nothing quieted, the safety note in full; no fix panel (the mission\'s carries the extra warning)', async () => {
  const html = await listHtml('city');
  assert.match(html, /AnyDesk lets someone else see and control this computer/);
  assert.match(html, /<div class="finding-card__note" role="note"><p>Before you remove or turn anything off: if you think someone close to you set this up to watch you, removing it can alert them\./, 'the safety note on its face');
  assert.doesNotMatch(html, /data-fix-open/);
});

// The mission screen (game/missions-city.js renderMissionScreen through the mission desk), and the
// fix confirm FixFlow draws there when the person picks the fixing decision. `moves`: the decisions in order;
// `item` is the screen before the last one, `steps` every screen before it (a remote tool is the Guest Book's
// quiz: "I installed it", "No", then "Remove it"). In city mode a remote tool is held, never a mission: cityScreens.
const GUESTBOOK_REMOVE = ['installed', 'nouse', 'remove'];
function harness(mode) {
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
  const click = (attrs) => { const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) }; clicks.forEach((fn) => fn({ target: { closest: () => el } })); };
  return { frame, seen, win, click };
}
async function controllerFor(mode, theDoc) {
  const { createController } = await import('../renderer/game/controller.js');
  const h = harness(mode);
  const ctl = createController({ win: h.win, storage: recordingStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await new Promise((r) => setTimeout(r, 10));
  ctl.show(theDoc, { id: mode === 'city' ? 'city' : 'unsure' });
  return h;
}
async function missionScreen(mode, fixable = true, theDoc = null, moves = GUESTBOOK_REMOVE) {
  const { frame, seen, click } = await controllerFor(mode, theDoc || doc({ fixable }));
  click({ 'data-go': 'district:gatehouse' });
  const id = /data-go="mx:([^"]+)"/.exec(frame.innerHTML)[1];
  click({ 'data-go': `mx:${id}` });
  if (/data-act="mx-know"/.test(frame.innerHTML)) click({ 'data-act': 'mx-know' });
  const steps = [];
  for (const m of moves.slice(0, -1)) {
    steps.push(frame.innerHTML);
    assert.match(frame.innerHTML, new RegExp(`data-act="mx-decide:${m}"`), `${mode}: ${m} is offered`);
    click({ 'data-act': `mx-decide:${m}` });
  }
  const item = frame.innerHTML;
  if (!moves.length) return { steps, item, html: item, seen, frame, click };
  const last = moves[moves.length - 1];
  assert.match(item, new RegExp(`data-act="mx-decide:${last}"`), `${mode}: ${last} is offered`);
  click({ 'data-act': `mx-decide:${last}` });
  return { steps, item, html: frame.innerHTML, seen, frame, click };
}

// City mode: the map, the remote tool's district, and the help district (data-go="side").
async function cityScreens(fixable = true) {
  const { frame, seen, click } = await controllerFor('city', doc({ fixable }));
  const map = frame.innerHTML;
  click({ 'data-go': 'district:gatehouse' });
  const district = frame.innerHTML;
  click({ 'data-go': 'side' });
  return { map, district, side: frame.innerHTML, seen };
}

const LINE_NOTE = /<summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/;
const noteOf = (html) => /<details class="finding-card__note">[\s\S]*?<\/details>/.exec(html)[0];
// Standard mode in the game: behind the line, the install's own help district by name (the harness's citySeed 777),
// one step away; the hotline and advocate text are in that district, never on a mission screen.
const PLACE = 'The Roundhouse';
const PLACE_NOTE = new RegExp(`<p>${PLACE} has a note about this\\. Read it before you remove anything\\.</p>`);
// The district it leads to: the hotline and the advocate note, in full.
function assertHelpOneStepAway(frame, click, where) {
  const before = frame.innerHTML;
  assert.match(noteOf(before), /data-go="side"/, `${where}: the way to ${PLACE}, in the note`);
  click({ 'data-go': 'side' });
  const side = frame.innerHTML;
  assert.match(side, /id="side-title"[^>]*>THE ROUNDHOUSE</, `${where}: ${PLACE} opens`);
  assert.match(side, /National Domestic Violence Hotline: 1-800-799-7233/, `${where}: the hotline is there`);
  assert.match(side, /advocate/i, `${where}: and the advocate note`);
  click({ 'data-act': 'side-back' });
  assert.match(frame.innerHTML, /mx-screen/, `${where}: back where they were`);
}

test('the mission screen, standard mode: the Guest Book quiz carries the line and the note on every step; at Not needed the fix confirm says it too', async () => {
  const { steps, item, html, seen } = await missionScreen('standard');
  // Each question (Q1 "how did this get here?", Q2 "do you still use it?") and the outcome: the line, the note behind it, first.
  assert.strictEqual(steps.length, 2);
  assert.match(steps[0], /How did this get here\?/);
  assert.match(steps[1], /Do you still use it\?/);
  assert.match(item, /gb-stage-notneeded/, 'the walk ends at Not needed');
  for (const [i, h] of [...steps, item].entries()) {
    assert.match(h, /AnyDesk/, `step ${i}`);
    assert.match(h, LINE_NOTE, `step ${i}: the line`);
    const note = noteOf(h);
    assert.match(note, PLACE_NOTE, `step ${i}: behind "Read this first", the help district by name`);
    assert.match(note, /data-go="side"/, `step ${i}: one step to it`);
    assert.ok(h.indexOf(note) < h.indexOf('mx-decisions'), `step ${i}: the note comes before the decisions`);
    assert.doesNotMatch(h, DV, `step ${i}: no hotline wording on the screen, the note included`);
  }
  // The removing decision never leads: "Later" first, "Remove it" after it.
  const bar = /<div class="mx-decisions"[\s\S]*?<\/div>/.exec(item)[0];
  assert.ok(bar.indexOf('mx-decide:later') < bar.indexOf('mx-decide:remove'), 'removal never first');
  assert.deepStrictEqual(seen, [['fix', false]]);
  // The fix confirm says it too.
  assert.match(/<div class="fix-panel"[\s\S]*?data-fix-confirm/.exec(html)[0], /data-fix-safety><strong>Removing this can alert whoever installed it\.<\/strong>/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'the extra warning is city mode’s');
});

test('city mode: the remote tool is held in the help district, never a mission; the warning is there; no hotline words anywhere else', async () => {
  for (const fixable of [true, 'module', false]) {
    const { map, district, side, seen } = await cityScreens(fixable);
    // Never a mission: no mission link, no fix or mark flow drawn, no tool name outside the help district.
    for (const [where, h] of [['map', map], ['district', district]]) {
      assert.doesNotMatch(h, /data-go="mx:/, `${where}: no mission`);
      assert.doesNotMatch(h, /AnyDesk/, `${where}: never named outside the help district`);
      assert.doesNotMatch(h, DV, `${where}`);
      assert.doesNotMatch(h, CITY_FORBIDDEN, `${where}`);
      assert.doesNotMatch(h, /data-fix-|data-mark-/, `${where}: nothing to fix or mark`);
    }
    assert.deepStrictEqual(seen, [], 'no fix or mark flow was ever drawn');
    assert.match(map, /data-go="side"/, 'the way to the help district');
    // The help district: the tool's card, under "Don't remove it yet", and why (removing it can tip them off).
    assert.match(side, /<h3 class="side-h">Don’t remove it yet\. Talk to an advocate first\.<\/h3>/);
    assert.match(side, /can tip off the person who installed it/);
    const card = /<li class="held-item">[\s\S]*?<\/li>/.exec(side)[0];
    assert.match(card, /AnyDesk/);
    assert.ok(side.indexOf('Don’t remove it yet') < side.indexOf(card), 'the warning before the card');
    assert.doesNotMatch(side, /data-fix-|data-mark-|mx-decide/, 'nothing to remove from here');
  }
});

test('the mission screen, standard mode, the engine’s real stalkerware finding (no removal_alert): the line and the note behind it', async () => {
  const M = require('./fixtures/monitoring-findings.json');
  const d = { schema_version: 1, platform: 'darwin', modules: [JSON.parse(JSON.stringify(M.stalkerware_scan))] };
  assert.ok(!d.modules[0].findings[0].removal_alert);
  const { item, frame, click } = await missionScreen('standard', false, d, []);
  assert.match(item, /ITEM 1 OF 1/);
  assert.match(item, /<summary>Removing this can alert whoever installed it\. Read this first\.<\/summary>/);
  const note = /<details class="finding-card__note">[\s\S]*?<\/details>/.exec(item)[0];
  assert.match(note, PLACE_NOTE);
  assert.doesNotMatch(item, DV, 'no hotline wording on the screen');
  assertHelpOneStepAway(frame, click, 'stalkerware');
});

test('standard mode, the Guest Book card: the hotline is one step from the card, in the help district', async () => {
  const { item, frame, click } = await missionScreen('standard', false, null, []);
  assert.match(item, /AnyDesk/);
  assert.match(item, LINE_NOTE);
  assertHelpOneStepAway(frame, click, 'remote tool');
});

test('a fix with no engine action, standard mode: the Guest Book’s "Remove it" is FixFlow’s module fix, its confirm warns; never in the city (held)', async () => {
  const { html, seen } = await missionScreen('standard', 'module');
  assert.match(html, /data-fix-module="remote_access_tools"/, 'the fix is offered');
  assert.doesNotMatch(html, /data-fix-action=/, 'no engine action');
  assert.match(/<div class="fix-panel"[\s\S]*?data-fix-confirm/.exec(html)[0], /data-fix-safety><strong>Removing this can alert whoever installed it\.<\/strong>/);
  assert.ok(!html.includes(FixFlow.WATCHED_WARNING), 'never the advocate line in the game');
  assert.doesNotMatch(html, /data-fix-city>/, 'the city words are city mode’s');
  assert.deepStrictEqual(seen, [['fix', false]]);
});

test('no fix at all (the engine’s real finding): "Remove it" carries warning: true, so the warning and a confirm come before the steps', async () => {
  const G = (await import('../renderer/missions/games/guestbook.js')).default;
  const T = await import('../renderer/missions/types.js');
  const it = T.groupMissions(doc(), { mode: 'standard' }).find((m) => m.type === 'guestbook').items[0];
  const rm = G.decisions(it, { mode: 'standard', platform: 'win32', answers: ['installed', 'nouse'] }).find((x) => x.id === 'remove');
  assert.strictEqual(rm.effect.kind, 'closer');
  assert.strictEqual(rm.effect.warning, true);
  const { item, html, seen, frame, click } = await missionScreen('standard', false);
  assert.match(item, LINE_NOTE);
  // R6: the confirm, under the warning, and no removal steps yet.
  const confirm = /<div class="panel mx-confirm"[\s\S]*?<\/div><\/div>/.exec(html)[0];
  assert.match(confirm, /Read the warning above first\. Go on\?/);
  assert.match(html, LINE_NOTE);
  assert.ok(html.indexOf(noteOf(html)) < html.indexOf(confirm), 'the warning above the confirm');
  assert.doesNotMatch(html, /Uninstall/, 'the steps wait for the confirm');
  assert.doesNotMatch(html, DV);
  assert.match(noteOf(html), PLACE_NOTE);
  assert.deepStrictEqual(seen, [], 'no fix flow: there is no fix');
  // Read, then on: the removal steps, the warning still above them.
  click({ 'data-act': 'mx-confirm' });
  await new Promise((r) => setTimeout(r, 0));
  assert.match(frame.innerHTML, /Uninstall/, 'the steps after the confirm');
  assert.match(frame.innerHTML, LINE_NOTE);
});

test('FixFlow’s own warnings: the advocate line only when watched outside the game; game words with the help district’s name', () => {
  assert.ok(FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: true }).includes(FixFlow.WATCHED_WARNING));
  assert.ok(!FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: false }).includes(FixFlow.WATCHED_WARNING));
  // With the help district's name (the game in city mode): the game words, never the advocate line.
  const city = FixFlow.fixControlsHtml({ module: 'm', fixable: MODULE_FIX }, { watched: true, place: 'The <Old> Mill' });
  assert.ok(!city.includes(FixFlow.WATCHED_WARNING));
  assert.doesNotMatch(city, CITY_FORBIDDEN);
  assert.ok(city.includes(`${FixFlow.CITY_WARNING}</strong> Stop by The &lt;Old&gt; Mill before you change it.`));
});

test('standard mode, the Guest Book’s "Someone I know": its steps point at the help district; no hotline on the screen, no removal', async () => {
  const { html, frame, click } = await missionScreen('standard', false, null, ['helped', 'knows', 'talk']);
  assert.match(html, /The Roundhouse has a note about this, with who can help\. Read it before you remove anything\./);
  assert.match(html, LINE_NOTE, 'the warning line is still there');
  assert.doesNotMatch(html, DV);
  assert.doesNotMatch(html, /mx-decide:remove|data-fix-/);
  assertHelpOneStepAway(frame, click, 'known outcome');
});

// A remote-access tool that is running now may be showing this screen to someone, live. Its card keeps the
// removal warning and the help district's name, but nothing that leads there (no GO THERE) until the person taps
// "I'm offline now" on that card. "Couldn't tell" counts as running (QuietNotes.goThereWaits).
function runningDoc(running) {
  const d = doc();
  const f = d.modules[0].findings[0];
  f.data = { ...f.data, running_now: running };
  if (running === true) f.code = 'security.remote_access_tools.running_now';
  return d;
}
const noGo = (h, where) => {
  assert.match(h, LINE_NOTE, `${where}: the line`);
  assert.match(noteOf(h), PLACE_NOTE, `${where}: the help district's name and the warning sentence`);
  assert.doesNotMatch(h, /data-go="side"|GO THERE/, `${where}: nothing on the screen leads to the help district`);
  assert.doesNotMatch(h, DV, `${where}`);
};

test('a running remote tool: no GO THERE until "I’m offline now"; then it’s there, and BACK hides it again', async () => {
  const { item, frame, click } = await missionScreen('standard', true, runningDoc(true), []);
  assert.match(item, /gb-stage-offline/);
  assert.match(item, /I’m offline now/);
  noGo(item, 'the offline step');
  click({ 'data-act': 'mx-decide:offline' });
  noGo(frame.innerHTML, 'after Go offline first');
  click({ 'data-act': 'mx-decide:continue' });
  assert.match(frame.innerHTML, /How did this get here\?/);
  assert.match(noteOf(frame.innerHTML), /<p><button type="button" class="btn-t" data-go="side">GO THERE ▶<\/button><\/p>/);
  assertHelpOneStepAway(frame, click, 'after I’m offline now');
  click({ 'data-act': 'mx-unask' });
  assert.match(frame.innerHTML, /gb-stage-offline/);
  noGo(frame.innerHTML, 'back at the offline step');
});

test('a remote tool the check couldn’t tell is running: no GO THERE on any step (couldn’t tell never means no)', async () => {
  for (const running of [null, undefined]) {
    const { steps, item } = await missionScreen('standard', true, runningDoc(running), GUESTBOOK_REMOVE);
    assert.strictEqual(steps.length, 2);
    for (const [i, h] of [...steps, item].entries()) noGo(h, `${running}: step ${i}`);
  }
});

test('a remote tool that isn’t running: GO THERE straight away', async () => {
  const { item, frame, click } = await missionScreen('standard', true, runningDoc(false), []);
  assert.match(item, /How did this get here\?/);
  assert.match(noteOf(item), /data-go="side">GO THERE ▶/);
  assertHelpOneStepAway(frame, click, 'not running');
});

test('goThereWaits: only remote-access tools that may be running; other monitoring and warned findings are unaffected', async () => {
  const tool = (data, code = 'security.remote_access_tools.tool_found') => ({ module: 'remote_access_tools', code, removal_alert: true, data: { check: 'tool_found', ...data } });
  assert.strictEqual(Q.goThereWaits(tool({ running_now: true })), true);
  assert.strictEqual(Q.goThereWaits(tool({ running_now: null })), true);
  assert.strictEqual(Q.goThereWaits(tool({})), true);
  assert.strictEqual(Q.goThereWaits(tool({ running_now: false })), false);
  assert.strictEqual(Q.goThereWaits(tool({ running_now: true }), { answers: [Q.OFFLINE_ANSWER] }), false);
  assert.strictEqual(Q.goThereWaits(tool({ running_now: true }), { answers: ['installed'] }), true);
  assert.strictEqual(Q.goThereWaits({ module: 'remote_access_tools', code: 'security.remote_access_tools.several_tools', data: { check: 'several_tools', tools: ['A', 'B'] } }), true,
    'the several-tools card can’t say which of them is running');
  assert.strictEqual(Q.goThereWaits({ code: 'security.remote_access_tools.running_now', data: { running_now: true } }), true, 'by code, without a module');
  // The Guest Book's "I'm offline now" is the answer it waits for.
  const gb = await import('../renderer/missions/games/guestbook.js');
  const offline = gb.decisions({ finding: tool({ running_now: true }) }, {}).find((x) => x.label.standard === 'I’m offline now');
  assert.strictEqual(offline && offline.id, Q.OFFLINE_ANSWER);
  // Other findings: monitoring software, a sharing setting with the engine's own warning. GO THERE as before.
  const { briefingNote } = await import('../renderer/game/held.js');
  const others = [
    { module: 'stalkerware_scan', code: 'security.stalkerware_scan.monitoring_software_found', severity: 'critical', data: { stalkerware_name: 'ExampleWatch', running_now: true } },
    { module: 'sharing_services', code: 'security.sharing_services.screen_sharing', severity: 'warning', removal_alert: true, remediation: { safety_note: 'Turning it off can alert them.' }, data: { running_now: true } },
    { module: 'keylogger_indicators', code: 'security.keylogger_indicators.suspicious', severity: 'warning', data: {} },
  ];
  for (const f of others) {
    assert.strictEqual(Q.goThereWaits(f), false, f.module);
    const n = briefingNote(Q, 'standard', f, { place: PLACE });
    assert.strictEqual(n.go, true, f.module);
    assert.match(n.html, /data-go="side">GO THERE ▶/, f.module);
  }
  const running = briefingNote(Q, 'standard', tool({ running_now: true }), { place: PLACE });
  assert.strictEqual(running.go, false);
  assert.match(running.html, PLACE_NOTE);
  assert.doesNotMatch(running.html, /data-go="side"|GO THERE/);
  assert.match(briefingNote(Q, 'standard', tool({ running_now: true }), { place: PLACE, answers: ['continue'] }).html, /data-go="side"/);
  // City mode's one line (a mission or briefing there, if a remote tool ever reaches one): the same rule.
  const { cityWarnHtml } = await import('../renderer/game/views/briefing.js');
  assert.match(cityWarnHtml(PLACE), /data-go="side"/);
  const hidden = cityWarnHtml(PLACE, { go: false });
  assert.match(hidden, /Removing this can alert whoever installed it\.<\/b> Stop by The Roundhouse before you change it\./);
  assert.doesNotMatch(hidden, /data-go="side"|GO THERE/);
});
