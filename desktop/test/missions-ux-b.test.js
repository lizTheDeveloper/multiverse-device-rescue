'use strict';
// Missions UX fixes, group B: city progress, deck and flows (UX audit P1-1,
// P1-5, P2-1, P2-4, P2-5, P2-8) and the points ruling (only a monitoring
// check's item pays nothing). A stubbed window like missions-foundation-city.
const test = require('node:test');
const assert = require('node:assert');
const { savedProfile } = require('./profile-read.js');

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
    mod('ssh_key_audit', [f('An extra key', 'warning', { path: '/etc/ssh/k' }, { markable: { id: 'm1', kind: 'background_task' } })]),
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
    FixFlow: { attach: (_r, _a, h) => { hooks.fix = h; }, resultHtml: (r) => (r && r.quarantine_id ? `<button data-fix-undo data-quarantine-id="${r.quarantine_id}">Undo</button>` : ''),
      fixControlsHtml: (finding, opts) => { calls.fixHtml.push(opts); return finding.fixable ? `<div class="fix-it" data-fix-module="${finding.module}"><button type="button" data-fix-open>Fix it for me</button><div class="fix-panel" data-fix-panel hidden><p class="fix-panel__line"><strong>To undo:</strong> Undo is on this item.</p><button data-fix-confirm>Yes, fix it</button><button data-fix-cancel>Cancel</button></div></div>` : ''; } },
    MarkFlow: { attach: (_r, _a, h) => { hooks.mark = h; },
      markControlsHtml: (finding) => { calls.markHtml.push(finding.title); return finding.markable ? '<div class="mark-mine" data-mark-card><button type="button" data-mark-open>I set this up</button><div class="fix-panel" data-mark-panel hidden><button data-mark-confirm>Yes, it’s mine</button><button data-mark-cancel>Cancel</button></div></div>' : ''; } },
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

