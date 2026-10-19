'use strict';
// Missions UX fixes, group B: city progress, deck and flows (UX audit P1-1,
// P1-5, P2-1, P2-4, P2-5, P2-8) and the points ruling (only a monitoring
// check's item pays nothing). A stubbed window like missions-foundation-city.
const test = require('node:test');
const assert = require('node:assert');
const { savedProfile } = require('./profile-read.js');
const RealFix = require('../renderer/fix-flow.js');
const RealMark = require('../renderer/mark-flow.js');

const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; } }; };
const tick = () => new Promise((r) => setTimeout(r, 0));
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}: what it is.`, severity, data, ...extra });
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });

// Seven Odd Jobs items in the Gatehouse: a fixable warned critical (part 1 of
// 4 items) and a markable warning among the rest (part 2 of 3).
function doc({ part = 'part' } = {}) {
  return scan(
    mod('battery_health', Array.from({ length: 5 }, (_, i) => f(`Worn part ${i}`, 'warning', { name: `${part}${i}` }))),
    mod('sudo_config_audit', [f('Odd sudo rule', 'critical', { path: '/opt/x/a.bin' }, { removal_alert: true,
      fixable: { will_change: 'Turns it off.', how_to_undo: ['Turn it on.'], action: 'disable_launch_agent', target: '/Library/LaunchDaemons/x.plist' } })]),
    mod('ssh_key_audit', [f('An extra key', 'warning', { path: '/etc/ssh/k' }, { markable: { id: 'abcdef012345', kind: 'background_task', label: 'com.example.task', program: '/opt/x/task', plist: '/Library/LaunchAgents/com.example.task.plist', will_change: 'Remembers it as yours.', how_to_undo: ['Stop treating it as mine.'] } })]),
  );
}

function stub(recheckDocs = []) {
  const listeners = [];
  const calls = { recheck: [], fixHtml: [], markHtml: [], clicked: [], focused: [] };
  const el = (name) => ({ name, click() { calls.clicked.push(name); }, focus() { calls.focused.push(name); }, setAttribute() {} });
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: (sel) => {
      if (/data-fix-open/.test(sel) && /data-fix-open/.test(frame.innerHTML)) return el('fix-open');
      if (/data-mark-open/.test(sel) && /data-mark-open/.test(frame.innerHTML)) return el('mark-open');
      if (/mx-act/.test(sel) && /mx-act/.test(frame.innerHTML)) return el('mx-act');
      return null;
    }, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const hooks = {};
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: (_r, _a, h) => { hooks.fix = h; }, resultHtml: () => '',
      describeFixResult: RealFix.describeFixResult, undoListHtml: RealFix.undoListHtml, UNDO_HERE: RealFix.UNDO_HERE,
      fixControlsHtml: (finding, opts) => { calls.fixHtml.push(opts); return finding.fixable ? `<div class="fix-it" data-fix-module="${finding.module}"><button type="button" data-fix-open>Fix it for me</button><div class="fix-panel" data-fix-panel hidden><p class="fix-panel__line"><strong>To undo:</strong> Undo is on this item.</p><button data-fix-confirm>Yes, fix it</button><button data-fix-cancel>Cancel</button></div></div>` : ''; } },
    // The real MarkFlow's markup: its open/confirm/cancel controls, and the unmark control for a marked finding.
    MarkFlow: { attach: (_r, _a, h) => { hooks.mark = h; },
      markControlsHtml: (finding, opts) => { calls.markHtml.push(finding.title); return RealMark.markControlsHtml(finding, opts); } },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {}, mode: () => 'standard' },
    rescue: {
      recheckModule: async (name) => {
        calls.recheck.push(name);
        const d = recheckDocs.shift();
        return { ok: true, doc: d, module: d.modules.find((m) => m.name === name) || { name, complete: true } };
      },
      openSetting: async () => true,
    },
  };
  const click = (attrs) => {
    const e = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => e } }));
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
const keepGame = async () => {
  const I = await import('../renderer/missions/games/index.js');
  const S = (await import('../renderer/missions/games/simple.js')).default;
  const reg = await I.loadGames({ importer: async () => { throw new Error('none'); } });
  reg.games.simple = { ...S, decisions: () => [{ id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } },
    { id: 'ok', label: { standard: 'Keep it', city: 'Keep' }, effect: { kind: 'keep' } }] };
  return reg;
};

// --- points ruling ---

test('points ruling: only a monitoring check’s item is "monitoring"; removal_alert, a safety note or a remote-access tool are not', async () => {
  const { isMonitoringItem } = await import('../renderer/game/missions-city.js');
  assert.ok(isMonitoringItem({ finding: { module: 'stalkerware_scan' } }));
  assert.ok(isMonitoringItem({ finding: { module: 'app_permissions' }, findings: [{ module: 'app_permissions' }, { module: 'keylogger_indicators' }] }), 'any of its findings');
  assert.ok(!isMonitoringItem({ finding: { module: 'remote_access_audit', removal_alert: true }, removal_alert: true }));
  assert.ok(!isMonitoringItem({ finding: { module: 'launch_agents_audit', remediation: { safety_note: 'Careful.' } } }));
  assert.ok(!isMonitoringItem(null));
});

test('points ruling: a warned remote-access item pays and is remembered; a monitoring one pays nothing and is asked again', async () => {
  const remote = () => scan(mod('remote_access_audit', [f('TeamViewer is installed', 'warning', { app: 'TeamViewer' }, { removal_alert: true })]));
  const s1 = memStore();
  const a = await setup(remote(), { storage: s1, games: keepGame });
  a.click({ 'data-act': 'investigate-next' });
  if (/PRACTICE FIRST/.test(a.html())) a.click({ 'data-act': 'mx-know' });
  assert.match(a.html(), /Removing this can alert whoever installed it\./, 'it still warns');
  a.click({ 'data-act': 'mx-decide:ok' });
  a.click({ 'data-act': 'mx-confirm' });
  assert.ok(savedProfile(s1).rank.points >= 5, 'it pays');
  assert.ok(Object.keys(savedProfile(s1).kept).length === 1, 'and is remembered');
  const REAL = require('./fixtures/monitoring-findings.json');
  const s2 = memStore();
  const b = await setup(scan(JSON.parse(JSON.stringify(REAL.keylogger_indicators))), { storage: s2, games: async () => (await import('../renderer/missions/games/index.js')).loadGames() });
  b.click({ 'data-go': 'mx:keyring:gatehouse:1' });
  if (/PRACTICE FIRST/.test(b.html())) b.click({ 'data-act': 'mx-know' });
  b.click({ 'data-act': 'mx-decide:keep' });
  if (/data-act="mx-confirm"/.test(b.html())) b.click({ 'data-act': 'mx-confirm' });
  await tick();
  assert.strictEqual(savedProfile(s2).rank.points, 0);
  assert.strictEqual(Object.keys(savedProfile(s2).kept).length, 0);
});


// --- P2-4: one-step decisions ---

test('Not mine (a fix) opens FixFlow at its confirm in the decision bar: one Yes left, its Cancel cancels, no extra NOT NOW', async () => {
  const t = await setup(doc());
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:fix' });
  const h = t.html();
  const bar = h.split('class="mx-bar"')[1] || '';
  assert.match(bar, /class="mx-act"[\s\S]*data-fix-confirm/, 'the confirm sits in the decision bar');
  assert.match(h, /data-fix-open hidden>/, 'FixFlow’s own open button is hidden');
  assert.ok(t.calls.clicked.includes('fix-open'), 'and pressed for the person, so its confirm is open');
  assert.match(h, /data-fix-cancel data-act="mx-cancel">/, 'its Cancel also cancels the decision');
  assert.doesNotMatch(h, /NOT NOW/, 'no second way out');
  // P1-5: "To undo" points where Undo really is.
  assert.doesNotMatch(h, /Undo is on this item\./);
  assert.match(h, /Undo is right here in this mission, and on the district’s list under DONE THIS SESSION\./);
  t.click({ 'data-act': 'mx-cancel' });
  assert.match(t.html(), /data-act="mx-decide:fix"/, 'cancelled: the decisions are back');
});

test('Mine (a mark) opens MarkFlow at its confirm with focus on it', async () => {
  const t = await setup(doc());
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:later' });
  t.click({ 'data-act': 'mx-decide:later' });
  t.click({ 'data-act': 'mx-decide:mine' });
  const h = t.html();
  assert.match(h, /data-mark-open hidden>/);
  assert.match(h, /data-mark-cancel data-act="mx-cancel">/);
  assert.ok(t.calls.clicked.includes('mark-open'));
  assert.ok(t.calls.focused.includes('mx-act'), 'focus moves to the confirm');
  assert.doesNotMatch(h, /NOT NOW/);
});

// --- P1-5: Undo inside missions ---

const QID = '20261019T120000Z-com.example.task.plist';
const fixedResult = { action: 'disable_launch_agent', applied: true, verified: true, status: 'fixed', quarantine_id: QID, how_to_undo: ['Undo it.'] };

test('a fix done from a mission shows DONE · UNDO in the mission and in the district; Undo puts the item back open', async () => {
  const fixed = doc();
  fixed.modules[1].findings = [];
  const storage = memStore();
  const t = await setup(doc(), { storage, recheckDocs: [fixed, doc()] });
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:fix' });
  t.hooks.fix.onResult({ kind: 'fix', module: 'sudo_config_audit', result: fixedResult, described: { tone: 'success' } });
  await tick(); await tick();
  let h = t.html();
  assert.match(h, /Odd sudo rule: Checked again: it’s gone\. \+75 points/, 'the notice names the item (P2-5)');
  assert.match(h, /DONE THIS SESSION[\s\S]*badge safe">DONE[\s\S]*Odd sudo rule[\s\S]*Fixed, and checked again: it’s gone\.[\s\S]*data-act="mx-undo:u1"[\s\S]*data-fix-undo data-quarantine-id="20261019T120000Z-com\.example\.task\.plist">UNDO/);
  t.click({ 'data-go': 'district:gatehouse' });
  h = t.html();
  assert.match(h, /DONE THIS SESSION[\s\S]*data-fix-undo/, 'and on the district’s list');
  // Undo: FixFlow carries it out; the desk only notes which one (no redraw under it).
  const before = t.html();
  t.click({ 'data-act': 'mx-undo:u1' });
  assert.strictEqual(t.html(), before);
  t.hooks.fix.onResult({ kind: 'undo', module: 'sudo_config_audit', result: { action: 'undo_disable_launch_agent', applied: true, status: 'restored' }, described: { tone: 'info', restored: true } });
  await tick(); await tick(); await tick();
  h = t.html();
  assert.doesNotMatch(h, /DONE THIS SESSION/);
  assert.match(h, /Odd sudo rule: Put back\. It’s on the list again\./);
  assert.deepStrictEqual(t.calls.recheck, ['sudo_config_audit', 'sudo_config_audit']);
  t.click({ 'data-go': 'mx:simple:gatehouse:1' });
  assert.match(t.html(), /ITEM \d OF 4/, 'its mission has it again');
  for (let i = 0; i < 3; i += 1) if (!/Odd sudo rule/.test(t.html().split('mx-card')[1] || '')) t.click({ 'data-act': 'mx-skip' });
  assert.match(t.html().split('mx-card')[1] || '', /Odd sudo rule/, 'open again, to decide');
});

test('a fix the engine can’t undo lists its undo steps instead of an Undo button', async () => {
  const fixed = doc();
  fixed.modules[1].findings = [];
  const t = await setup(doc(), { recheckDocs: [fixed] });
  t.click({ 'data-act': 'investigate-next' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:fix' });
  t.hooks.fix.onResult({ kind: 'fix', result: { applied: true, verified: true, status: 'fixed', how_to_undo: ['Turn it on again in Settings.'] }, described: { tone: 'success' } });
  await tick(); await tick();
  const h = t.html();
  assert.match(h, /DONE THIS SESSION[\s\S]*To undo it[\s\S]*Turn it on again in Settings\./);
  assert.doesNotMatch(h, /data-fix-undo/);
});

test('a mark done from a mission shows DONE · UNDO (MarkFlow’s own unmark); Undo puts it back', async () => {
  const marked = doc();
  marked.modules[2].findings[0] = { ...marked.modules[2].findings[0], markable: undefined, severity: 'info', data: { path: '/etc/ssh/k', marked_by_user: true, known_item_id: 'abcdef012345', original_severity: 'warning' } };
  const t = await setup(doc(), { recheckDocs: [marked, doc()] });
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:later' });
  t.click({ 'data-act': 'mx-decide:later' });
  t.click({ 'data-act': 'mx-decide:mine' });
  t.hooks.mark.onResult({ kind: 'marked', result: { status: 'marked', ids: ['abcdef012345'] }, described: { done: true } });
  await tick(); await tick();
  let h = t.html();
  assert.match(h, /DONE THIS SESSION[\s\S]*Marked as yours\. Nothing on your computer changed\.[\s\S]*data-unmark-id="abcdef012345"[\s\S]*>UNDO</);
  t.click({ 'data-act': 'mx-undo:u1' });
  t.hooks.mark.onResult({ kind: 'removed', result: { status: 'removed' }, described: { done: true } });
  await tick(); await tick(); await tick();
  h = t.html();
  assert.doesNotMatch(h, /DONE THIS SESSION/);
  assert.match(h, /An extra key: Put back\./);
});

// --- P1-1: progress that moves ---

test('deciding moves the city: DECIDED beside TO DO, MISSIONS by rows, the district bar and badge; TO DO stays the scan’s', async () => {
  const t = await setup(doc(), { games: keepGame });
  const todo = (h) => Number((h.match(/(\d+) TO DO/) || [])[1]);
  const deck0 = t.html();
  const todo0 = todo(deck0);
  assert.ok(todo0 > 0);
  assert.doesNotMatch(deck0, /DECIDED/);
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  for (let i = 0; i < 3; i += 1) t.click({ 'data-act': 'mx-decide:ok' });
  let h = t.html();
  assert.match(h, /<b>1\/2<\/b> <small>MISSIONS/, 'MISSIONS counts the district list’s rows');
  assert.match(h, /<b>3<\/b> <small>DECIDED/);
  t.click({ 'data-go': 'district:gatehouse' });
  h = t.html();
  assert.match(h, /1 of 2 missions done · 3 of 7 decided/);
  assert.match(h, /aria-valuenow="3"/);
  assert.match(h, /Decided isn’t fixed: only a re-check confirms a fix\./);
  t.click({ 'data-go': 'map' });
  h = t.html();
  assert.strictEqual(todo(h), todo0, 'TO DO is still the scan’s count');
  assert.match(h, /· 3 DECIDED/);
  assert.match(h, /3\/7 DECIDED/, 'the district’s badge');
  assert.match(h, /<b>3<\/b> <small>SORTED/, 'the SORTED bar moves');
});

test('YOUR FILE reads the missions: done, decided, kept, set aside, practice rounds', async () => {
  const t = await setup(doc(), { games: keepGame });
  t.click({ 'data-go': 'mx:simple:gatehouse:2' });
  t.click({ 'data-act': 'mx-know' });
  t.click({ 'data-act': 'mx-decide:ok' });
  t.click({ 'data-act': 'mx-decide:later' });
  t.click({ 'data-act': 'mx-decide:ok' });
  t.click({ 'data-go': 'profile' });
  const h = t.html();
  assert.match(h, /MISSIONS<\/h3><p>0 of 2 missions done · 2 of 7 things decided<\/p>/);
  assert.match(h, /This session: 2 kept · 1 set aside for later/);
  assert.match(h, /Practice rounds: 0 played, 1 skipped \(you said you know it\)/);
  assert.match(h, /Decided isn’t fixed/);
  assert.doesNotMatch(h, /0 set aside for later · 0 marked as yours/, 'no stale zeros from the old flow');
});

// --- P2-1: the deck shows missions ---

test('the deck lists the next missions under INVESTIGATE NEXT; the signals fold behind SEE ALL SIGNALS', async () => {
  const t = await setup(doc());
  const h = t.html();
  assert.match(h, /data-act="investigate-next"[\s\S]*NEXT MISSIONS[\s\S]*data-go="mx:simple:gatehouse:1"[\s\S]*Other[\s\S]*The Gatehouse · 4 items left · Odd sudo rule[\s\S]*data-go="mx:simple:gatehouse:2"/);
  assert.match(h, /<details class="all-signals"><summary class="label">SEE ALL SIGNALS \(\d+\)<\/summary><ul class="queue">[\s\S]*data-go="signal:/);
});

// --- P2-8: one count source ---

test('standard mode: TO DO is the list’s count, held monitoring items included (they are missions there); city mode leaves them out', async () => {
  const REAL = require('./fixtures/monitoring-findings.json');
  const d = () => { const x = doc(); x.modules.push(JSON.parse(JSON.stringify(REAL.stalkerware_scan))); return x; };
  const NC = require('../renderer/not-checked.js');
  const std = NC.scanCounts(d(), { mode: 'standard' }).todo;
  const cty = NC.scanCounts(d(), { mode: 'city' }).todo;
  assert.ok(std > cty, 'the fixture has a held item');
  const a = await setup(d());
  assert.match(a.html(), new RegExp(`INCOMING SIGNALS · ${std} TO DO`));
  const b = await setup(d(), { mode: 'city' });
  assert.match(b.html(), new RegExp(`INCOMING SIGNALS · ${cty} TO DO`));
});

test('a district’s NOTES badge is the list’s count; its notes are one GOOD TO KNOW row, not listed twice', async () => {
  const notes = mod('login_items', Array.from({ length: 3 }, (_, i) => f(`Login item ${i}`, 'info', { name: `l${i}` })));
  const x = doc();
  x.modules.push(notes);
  const NC = require('../renderer/not-checked.js');
  const want = NC.scanCounts(x, { mode: 'city', districtOf: (await import('../renderer/game/findings-to-city.js')).districtIdFor }).byDistrict;
  const t = await setup(x);
  const id = Object.keys(want).find((k) => want[k].notes > 0);
  assert.ok(id);
  assert.match(t.html(), new RegExp(`${want[id].notes} NOTES`));
  t.click({ 'data-go': `district:${id}` });
  const h = t.html();
  assert.match(h, /GOOD TO KNOW \(OPTIONAL\)/);
  assert.doesNotMatch(h, /<summary class="label">NOTES \(/, 'the old NOTES list isn’t drawn as well');
});

// --- keyring per key (group D's perKey, wired through groupMissions) ---

test('keyring: one app holding two keys is one item per key in its mission', async () => {
  const perm = (check, title) => f(title, 'warning', { check, apps: ['com.example.app'] }, { code: `security.app_permissions.${check}` });
  const d = scan(mod('app_permissions', [perm('accessibility_access', '1 app can control your Mac'), perm('screen_recording', '1 app can record your screen')]));
  const real = async () => (await import('../renderer/missions/games/index.js')).loadGames();
  const t = await setup(d, { games: real });
  const T = await import('../renderer/missions/types.js');
  const I = await import('../renderer/missions/games/index.js');
  const reg = await I.loadGames();
  const plain = T.groupMissions(d, { table: T.buildTable(I.ownGames(reg)) }).filter((m) => m.type === 'keyring').flatMap((m) => m.items);
  const split = T.groupMissions(d, { table: T.buildTable(I.ownGames(reg)), perKey: reg.modules.keyring.perKey }).filter((m) => m.type === 'keyring').flatMap((m) => m.items);
  assert.ok(split.length > plain.length, `per key: ${split.length} items, was ${plain.length}`);
  const id = (t.html().match(/data-go="(mx:keyring:[^"]+)"/) || [])[1];
  assert.ok(id);
  t.click({ 'data-go': id });
  if (/PRACTICE FIRST/.test(t.html())) t.click({ 'data-act': 'mx-know' });
  assert.match(t.html(), new RegExp(`ITEM 1 OF ${split.length}`));
});
