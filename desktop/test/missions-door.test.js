'use strict';
// The Door mini-game (missions/games/door.js): things that start on their own.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const imp = (...p) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', ...p)).href);
const door = () => imp('games', 'door.js');
const contract = () => imp('contract.js');
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'missions', name), 'utf8')).findings;

async function fixtureItems() {
  const C = await contract();
  return [...fixture('door-mac.json'), ...fixture('door-windows.json')].map((f) => C.makeItem(f));
}
async function byModule(mod) {
  return (await fixtureItems()).find((i) => i.finding.module === mod);
}
const ids = (ds) => ds.map((d) => d.id);

// Every data field the Door reads, by the module that writes it (checked against the module source).
const FIELDS = {
  'security/launch_agent_audit': ['label', 'program'],
  'security/launchd_persistence_audit': ['label', 'program', 'location', 'program_exists'],
  'security/scheduled_tasks_audit': ['label', 'location', 'plist', 'command'],
  'bloatware/login_items': ['item_name'],
  'performance/login_items_cleanup': ['items'],
  'security/cron_jobs_audit': ['entries'],
  'bloatware/startup_auditor': ['label', 'name'],
  'performance/startup_optimizer': ['items', 'third_party_labels'],
  'security/security_baseline_diff': ['added', 'baseline_captured_at'],
  'security/ai_worm_persistence': ['plist', 'label', 'task_name', 'command', 'file', 'path', 'unit_name'],
  'security/crypto_miner_persistence': ['location', 'mechanism', 'indicator'],
  'security/kext_audit': ['path', 'name', 'bundle_id'],
  'security/kernel_extensions_audit': ['kexts'],
  'integrity/system_extensions_check': ['waiting_extensions', 'terminated_extensions'],
  'security/win_autoruns_audit': ['entry_name', 'location', 'command'],
  'security/win_scheduled_tasks': ['task_name', 'task_path'],
  'security/win_scheduled_tasks_security': ['task_name', 'task_path', 'command', 'created_date'],
  'security/win_services_audit': ['services', 'name', 'display_name', 'path'],
  'security/win_services_security_audit': ['service_name', 'display_name', 'path'],
  'performance/win_startup': ['names'],
  'performance/win_startup_programs_audit': ['items'],
};

test('every field the Door reads is one its module really writes', () => {
  for (const [mod, fields] of Object.entries(FIELDS)) {
    const src = fs.readFileSync(path.join(ROOT, 'modules', mod, '__init__.py'), 'utf8');
    for (const k of fields) assert.ok(src.includes(`"${k}"`), `${mod} writes "${k}"`);
  }
});

test('covers: every module in the spec row, the Windows equivalents, no duplicates', async () => {
  const { default: game } = await door();
  const mods = game.covers.map((c) => c.module);
  assert.strictEqual(new Set(mods).size, mods.length, 'a module is claimed twice');
  for (const m of ['launch_agent_audit', 'launchd_persistence_audit', 'login_items_cleanup', 'login_items', 'scheduled_tasks_audit',
    'cron_jobs_audit', 'startup_optimizer', 'startup_auditor', 'security_baseline_diff', 'ai_worm_persistence',
    'crypto_miner_persistence', 'kext_audit', 'kernel_extensions_audit', 'system_extensions_check',
    'win_autoruns_audit', 'win_startup', 'win_startup_programs_audit', 'win_scheduled_tasks', 'win_scheduled_tasks_security',
    'win_services_audit', 'win_services_security_audit']) assert.ok(mods.includes(m), `covers ${m}`);
  for (const c of game.covers) assert.ok(fs.existsSync(path.join(ROOT, 'modules')) && fs.readdirSync(path.join(ROOT, 'modules')).some((d) => fs.existsSync(path.join(ROOT, 'modules', d, c.module))), `${c.module} is a real module`);
  const base = game.covers.find((c) => c.module === 'security_baseline_diff');
  assert.deepStrictEqual(base.codes, ['security.security_baseline_diff.new_persistence'], 'only the persistence items of the baseline diff');
});

test('the contract checks pass for fixture and practice items', async () => {
  const C = await contract();
  const { default: game } = await door();
  assert.deepStrictEqual(C.runContractChecks(game, await fixtureItems()), []);
  assert.deepStrictEqual(C.validateGame(game), []);
});

test('names and paths come from the fields the modules write', async () => {
  const D = await door();
  assert.strictEqual(D.nameOf({ data: { label: 'com.x.a', program: '/p' } }), 'com.x.a');
  assert.strictEqual(D.nameOf({ data: { entry_name: 'Updater', command: 'C:\\x.exe' } }), 'Updater');
  assert.strictEqual(D.nameOf({ data: { task_name: 'T', task_path: '\\T' } }), 'T');
  assert.strictEqual(D.nameOf({ title: 'Only a title', data: {} }), 'Only a title');
  assert.strictEqual(D.runsOf({ data: { label: 'a', program: '~/.hidden/a', location: '~/Library/LaunchAgents' } }), '~/.hidden/a');
  assert.strictEqual(D.runsOf({ data: { label: 'a', location: '~/Library/LaunchAgents' } }), '', 'a folder is not what it runs');
  assert.strictEqual(D.setUpIn({ data: { entry_name: 'U', command: 'C:\\a.exe', location: 'HKCU\\Run' } }), 'HKCU\\Run');
  assert.strictEqual(D.homeRelative('/bin/sh /Users/someone/x.sh'), '/bin/sh ~/x.sh');
  assert.strictEqual(D.homeRelative('C:\\Users\\someone\\AppData\\Local\\Temp\\a.exe'), '~\\AppData\\Local\\Temp\\a.exe');
  assert.strictEqual(D.homeRelative('/private/tmp/a'), '/tmp/a');
});

test('decisions: Mine / Look closer / Not mine on a note; Look closer first on a warning or critical item', async () => {
  const { default: game } = await door();
  const ctx = (await contract()).testContext();
  const vpnWarning = await byModule('launchd_persistence_audit');
  assert.deepStrictEqual(ids(game.decisions(vpnWarning, ctx)), ['closer', 'mine', 'not-mine'], 'a warning never leads with Mine');
  const vpn = { ...vpnWarning, severity: 'info', finding: { ...vpnWarning.finding, severity: 'info' } };
  assert.deepStrictEqual(ids(game.decisions(vpn, ctx)), ['mine', 'closer', 'not-mine']);
  assert.deepStrictEqual(game.decisions(vpn, ctx).map((d) => d.label.standard), ['Mine', 'Look closer', 'Not mine']);
  assert.strictEqual(game.decisions(vpn, ctx)[0].effect.kind, 'mark', 'markable → mark');
  const hidden = await byModule('launch_agent_audit');
  const d = game.decisions(hidden, ctx);
  assert.deepStrictEqual(ids(d), ['closer', 'mine', 'not-mine'], 'removal warning → look closer first');
  assert.strictEqual(d[2].effect.kind, 'fix', 'the engine offered a fix');
  assert.strictEqual(d[2].effect.warning, true, 'switching off an alerting item carries the warning');
  assert.ok(!('warning' in game.decisions(vpn, ctx)[2].effect), 'no warning flag on a non-alerting item');
  const alertingTask = { ...(await byModule('win_scheduled_tasks_security')), removal_alert: true };
  assert.deepStrictEqual(game.decisions(alertingTask, ctx).map((x) => [x.id, !!x.effect.warning]), [['closer', false], ['mine', false], ['not-mine', true]]);
  const unverifiedCritical = { ...hidden, removal_alert: false, finding: { ...hidden.finding, removal_alert: false } };
  assert.strictEqual(game.decisions(unverifiedCritical, ctx)[0].id, 'closer', 'critical with an unverified maker → look closer first');
  const safety = { ...vpn, finding: { ...vpn.finding, remediation: { safety_note: 'x' } } };
  assert.strictEqual(game.decisions(safety, ctx)[0].id, 'closer');
});

test('decisions: Mine is keep when nothing can be marked; Not mine routes to the right switch', async () => {
  const { default: game } = await door();
  const ctx = (await contract()).testContext();
  const nm = async (mod) => game.decisions(await byModule(mod), ctx).find((x) => x.id === 'not-mine').effect;
  assert.strictEqual(game.decisions(await byModule('login_items'), ctx).find((x) => x.id === 'mine').effect.kind, 'keep');
  assert.deepStrictEqual(await nm('login_items'), { kind: 'settings', pane: 'login-items' });
  assert.deepStrictEqual(await nm('kext_audit'), { kind: 'settings', pane: 'login-items' });
  assert.deepStrictEqual(await nm('win_startup'), { kind: 'settings', pane: 'startup-apps' });
  const task = await nm('win_scheduled_tasks_security');
  assert.strictEqual(task.kind, 'closer');
  assert.match(task.checklist.join(' '), /Task Scheduler.*Disable/);
  const svc = await nm('win_services_audit');
  assert.match(svc.checklist.join(' '), /services\.msc.*Disabled/);
  const cron = await nm('cron_jobs_audit');
  assert.strictEqual(cron.kind, 'closer');
  assert.match(cron.checklist.join(' '), /keeping a copy/);
});

test('Look closer: a what-to-check list, with the search as text to use elsewhere in city mode', async () => {
  const { default: game } = await door();
  const C = await contract();
  const hidden = await byModule('launch_agent_audit');
  const std = game.decisions(hidden, C.testContext()).find((d) => d.id === 'closer').effect.checklist.join('\n');
  assert.match(std, /Login Items/);
  assert.match(std, /recognise the maker/);
  assert.match(std, /hidden or temporary folder/);
  assert.match(std, /around 30 Sep 2026/);
  assert.match(std, /Search the name: com\.example\.syncer/);
  const city = game.decisions(hidden, C.testContext({ mode: 'city' })).find((d) => d.id === 'closer').effect.checklist.join('\n');
  assert.match(city, /another device: com\.example\.syncer/);
  assert.deepStrictEqual(C.checkCityWords(city), []);
  const win = game.decisions(await byModule('win_autoruns_audit'), C.testContext()).find((d) => d.id === 'closer').effect.checklist.join('\n');
  assert.match(win, /Task Manager under Startup apps/);
});

test('R1: render draws only the knock card — no buttons, links or evidence rows', async () => {
  const { default: game } = await door();
  const C = await contract();
  for (const item of [...(await fixtureItems()), ...game.practice.items]) {
    const ctx = C.testContext({ evidenceRows: () => [{ label: 'EVROW', value: 'EVVAL' }] });
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx) }, ctx);
    assert.doesNotMatch(html, /<button|<a\b|href=|EVROW|data-decision/);
  }
});

test('the knock card: hidden and temporary folders highlighted, the file itself never', async () => {
  const { default: game, pathHtml } = await door();
  const C = await contract();
  const ctx = C.testContext();
  assert.strictEqual(pathHtml('/Users/someone/.hidden/upd8r/upd8r', ctx), '~/<mark class="door-hidden">.hidden</mark>/upd8r/upd8r');
  assert.strictEqual(pathHtml('~/Library/.profile', ctx), '~/Library/.profile', 'a dot-file is not a hidden folder');
  assert.match(pathHtml('~\\AppData\\Local\\Temp\\exupd.exe /silent', ctx), /<mark class="door-hidden">Temp<\/mark>/);
  assert.match(pathHtml('/tmp/x/run', ctx), /^\/<mark class="door-hidden">tmp<\/mark>\//);
  const html = game.render({ item: await byModule('launch_agent_audit'), index: 0, total: 3 }, ctx);
  assert.match(html, /<mark class="door-hidden">\.cache<\/mark>/);
  assert.match(html, /<mark class="door-hidden">\.sx<\/mark>/);
  assert.match(html, /1 of 3/);
  assert.match(html, /door-place/, 'a short note on what the place means');
  const win = game.render({ item: await byModule('win_services_audit') }, ctx);
  assert.match(win, /<mark class="door-hidden">Downloads<\/mark>/);
});

test('the knock card: signer and verified, appeared on, what the program is — honestly', async () => {
  const { default: game } = await door();
  const C = await contract();
  const ctx = C.testContext();
  const vpn = game.render({ item: await byModule('launchd_persistence_audit') }, ctx);
  assert.match(vpn, /Example VPN Ltd<\/span> <span class="door-chip door-verified">verified/);
  assert.match(vpn, /a VPN app’s helper|a VPN app&#39;s helper/);
  assert.match(vpn, /Appeared on<\/dt><dd><span class="door-none">Not recorded/);
  const hidden = game.render({ item: await byModule('launch_agent_audit') }, ctx);
  assert.match(hidden, /door-unverified">not verified/);
  assert.match(hidden, /30 Sep 2026/);
  assert.match(hidden, /Not known: nobody has vouched/);
  const noMaker = game.render({ item: await byModule('login_items') }, ctx);
  assert.match(noMaker, /Not checked: the checkup didn’t read a maker/);
  assert.match(noMaker, /What it is<\/dt><dd><span class="door-none">Not known\.</, 'no maker read: not "nobody vouched"');
  assert.match(game.render({ item: await byModule('win_scheduled_tasks_security') }, ctx), /2 Oct 2026/);
  assert.match(game.render({ item: await byModule('security_baseline_diff') }, ctx), /New since 10 Oct 2026/);
  // A claimed (unverified) maker's "what" is never shown.
  const claimed = C.makeItem({ module: 'launch_agent_audit', data: { label: 'x', program: '/p' }, made_by: [{ subject: '/p', name: 'Apple Inc.', verified: false, what: 'Totally safe' }] });
  assert.doesNotMatch(game.render({ item: claimed }, ctx), /Totally safe/);
});

test('the knock card: lists capped at four, an unfinished check says so, practice pointer', async () => {
  const { default: game } = await door();
  const C = await contract();
  const ctx = C.testContext();
  const kexts = game.render({ item: await byModule('kernel_extensions_audit') }, ctx);
  assert.strictEqual((kexts.match(/<li>/g) || []).length, 4);
  assert.match(kexts, /and 2 more/);
  assert.match(game.render({ item: await byModule('cron_jobs_audit') }, ctx), /<mark class="door-hidden">\.local<\/mark>/);
  const partial = C.makeItem({ module: 'launch_agent_audit', data: { label: 'x', program: '/p' } }, { unfinished: true });
  assert.match(game.render({ item: partial }, ctx), /This check didn’t finish/);
  assert.strictEqual(game.research(partial, ctx).unfinished, true);
  assert.doesNotMatch(game.render({ item: C.makeItem({ module: 'launch_agent_audit', data: { label: 'x', program: '/p' } }) }, ctx), /didn’t finish/);
  const p = game.practice;
  const step = p.script.find((s) => s.point === 'runs');
  const html = game.render({ item: p.items[step.item], practice: true, step }, ctx);
  assert.match(html, /door-runs door-point/);
  assert.match(html, /door-say/);
});

test('research: evidence rows from ctx, link intents for the switch, a look-up and the lesson', async () => {
  const { default: game } = await door();
  const C = await contract();
  let seen = null;
  const ctx = C.testContext({ mode: 'city', evidenceRows: (f, o) => { seen = o; return [{ label: 'Path', value: 'v' }]; } });
  const vpn = game.research(await byModule('launchd_persistence_audit'), ctx);
  assert.deepStrictEqual(seen, { mode: 'city' });
  assert.deepStrictEqual(vpn.rows, [{ label: 'Path', value: 'v' }]);
  assert.match(vpn.what, /VPN/);
  assert.deepStrictEqual(vpn.links, [
    { kind: 'settings', pane: 'login-items' },
    { kind: 'lookup', source: 'maker-site', query: 'Example VPN Ltd' },
    { kind: 'lesson', concept: 'where-it-lives', lesson: 'starts-on-its-own' },
  ]);
  const hidden = game.research(await byModule('launch_agent_audit'), C.testContext());
  assert.strictEqual(hidden.what, '');
  assert.deepStrictEqual(hidden.links[1], { kind: 'lookup', source: 'web', query: 'com.example.syncer' });
  const apple = game.research(game.practice.items[0], C.testContext());
  assert.strictEqual(apple.links[1].source, 'maker-site');
  const win = game.research(await byModule('win_scheduled_tasks_security'), C.testContext());
  assert.ok(!win.links.some((l) => l.kind === 'settings'), 'no settings pane switches off a scheduled task');
  assert.deepStrictEqual(game.research(await byModule('win_startup'), C.testContext()).links[0], { kind: 'settings', pane: 'startup-apps' });
});

test('practice: a verified Apple agent, an unsigned agent in ~/.hidden, a developer tool you installed', async () => {
  const { default: game } = await door();
  const C = await contract();
  const ctx = C.testContext();
  const [apple, hidden, dev] = game.practice.items;
  assert.strictEqual(game.practice.items.length, 3);
  assert.ok(apple.finding.made_by[0].verified && /^Apple/.test(apple.finding.made_by[0].name));
  assert.match(hidden.finding.data.program, /^~\/\.hidden\//);
  assert.strictEqual(hidden.finding.made_by[0].verified, false);
  assert.match(dev.finding.setup, /you installed/);
  for (const s of game.practice.script) {
    assert.ok(game.practice.items[s.item], 'step points at a practice item');
    if (s.expect) assert.ok(ids(game.decisions(game.practice.items[s.item], ctx)).includes(s.expect), `${s.expect} is a decision`);
    assert.deepStrictEqual(C.checkCityWords(s.say.city), []);
  }
  const expects = game.practice.script.filter((s) => s.expect).map((s) => [s.item, s.expect]);
  assert.deepStrictEqual(expects, [[0, 'mine'], [1, 'not-mine'], [2, 'mine']]);
  // The hidden practice agent carries the removal warning, so its default is Look closer.
  assert.strictEqual(game.decisions(hidden, ctx)[0].id, 'closer');
});

test('summary counts answers and never says all clear', async () => {
  const { default: game } = await door();
  const C = await contract();
  const r = [{ decision: 'mine' }, { decision: 'not-mine' }, { decision: 'closer' }, { decision: 'mine' }];
  const s = game.summary(r, C.testContext());
  assert.match(s, /4 things that start on their own: 2 yours, 1 not yours, 1 still to look at/);
  const c = game.summary(r, C.testContext({ mode: 'city' }));
  assert.match(c, /4 knocks at the door: 2 let in, 1 barred, 1 still being looked at/);
  for (const x of [s, c, game.summary([], C.testContext())]) assert.doesNotMatch(x, /all clear|nothing (?:wrong|bad)|safe now/i);
  assert.deepStrictEqual(C.checkCityWords(c), []);
});

test('copy has no time estimates or time words', async () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'missions', 'games', 'door.js'), 'utf8');
  assert.doesNotMatch(src.replace(/\/\/.*$/gm, ''), /\b\d+\s*(?:seconds?|minutes?|hours?)\b|\bquick(?:ly)?\b|\bin a moment\b/i);
});

test('fixtures are synthetic: no account names, MAC addresses or serials', () => {
  const dir = path.join(__dirname, 'fixtures', 'missions');
  for (const f of fs.readdirSync(dir).filter((x) => x.startsWith('door-'))) {
    const t = fs.readFileSync(path.join(dir, f), 'utf8');
    assert.doesNotMatch(t, /\/(?:Users|home)\/(?!Shared)[^/"]+\//, `${f}: a home folder path`);
    assert.doesNotMatch(t, /[A-Za-z]:\\\\Users\\\\/, `${f}: a Windows home folder path`);
    assert.doesNotMatch(t, /\b[0-9a-f]{2}(?::[0-9a-f]{2}){5}\b/i, `${f}: a MAC address`);
    assert.doesNotMatch(t, /\bC02[A-Z0-9]{8}\b|serial/i, `${f}: a serial`);
  }
});
