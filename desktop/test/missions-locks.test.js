'use strict';
// Lock Run (missions/games/locks.js): settings and locks, macOS and Windows.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
// A practice step's best move (`expect` is one id or a list, the best first).
const first = (e) => (Array.isArray(e) ? e[0] : e);

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const loadContract = () => import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
const loadGame = () => import(pathToFileURL(path.join(MISSIONS, 'games', 'locks.js')).href);
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'missions', name), 'utf8'));

async function setup() {
  const C = await loadContract();
  const mod = await loadGame();
  const items = (name) => fixture(name).findings.map((f) => C.makeItem(f));
  return { C, mod, game: mod.default, mac: items('locks-mac.json'), win: items('locks-win.json') };
}
const find = (items, module, re) => items.find((i) => i.finding.module === module && (!re || re.test(i.finding.code || i.finding.data.check || '')));
const textOf = (html) => String(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');

test('the game passes every contract check on the Mac and Windows fixtures', async () => {
  const { C, game, mac, win } = await setup();
  assert.deepStrictEqual(C.runContractChecks(game, [...mac, ...win]), []);
});

test('every fixture item maps to a lock, and every lock has the words both modes need', async () => {
  const { mod, mac, win } = await setup();
  for (const item of [...mac, ...win]) assert.ok(mod.lockOf(item.finding), `${item.key} has no lock`);
  assert.ok(mod.LOCK_IDS.length >= 15);
});

test('decisions: Turn it on (the exact pane) / Done (re-check that check) / Not now', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const d = game.decisions(find(mac, 'automatic_updates'), ctx);
  assert.deepStrictEqual(d.map((x) => x.id), ['on', 'done', 'later']);
  assert.deepStrictEqual(d.map((x) => x.label.standard), ['Turn it on', 'Done', 'Not now']);
  assert.deepStrictEqual(d[0].effect, { kind: 'settings', pane: 'software-update' });
  assert.strictEqual(d[1].effect.kind, 'recheck');
  assert.strictEqual(d[1].effect.module, 'automatic_updates');
  assert.strictEqual(d[2].effect.kind, 'later');
});

test('each Mac lock opens its own pane', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const pane = (m, re) => game.decisions(find(mac, m, re), ctx)[0].effect.pane;
  assert.strictEqual(pane('encryption_check'), 'filevault');
  assert.strictEqual(pane('filevault_recovery'), 'filevault');
  assert.strictEqual(pane('firewall_audit'), 'firewall');
  assert.strictEqual(pane('screen_lock_check'), 'lock-screen');
  assert.strictEqual(pane('login_password_policy'), 'users-groups');
  assert.strictEqual(pane('find_my_mac_check'), 'apple-id');
  assert.strictEqual(pane('guest_account_check'), 'sharing');
  assert.strictEqual(pane('backup_status'), 'time-machine');
  assert.strictEqual(pane('macos_eol_check'), 'software-update');
  assert.strictEqual(pane('update_checker', /^os_updates$/), 'software-update');
});

test('Windows locks open Windows panes, or show the steps when Windows has no page to open', async () => {
  const { C, game, win } = await setup();
  const ctx = C.testContext({ platform: 'win32' });
  const first = (m) => game.decisions(find(win, m), ctx)[0];
  assert.deepStrictEqual(first('win_windows_update_status').effect, { kind: 'settings', pane: 'windows-update' });
  assert.deepStrictEqual(first('win_defender').effect, { kind: 'settings', pane: 'windows-security' });
  assert.deepStrictEqual(first('win_firewall').effect, { kind: 'settings', pane: 'windows-firewall' });
  // Panes that exist since integration: device encryption, sign-in options, Find my device.
  assert.deepStrictEqual(first('win_bitlocker_check').effect, { kind: 'settings', pane: 'windows-bitlocker' });
  for (const m of ['win_uac_check', 'win_user_accounts', 'win_restore_points']) {
    const d = first(m);
    assert.strictEqual(d.effect.kind, 'closer', m);
    assert.strictEqual(d.label.standard, 'Show me how', m);
    assert.ok(d.effect.checklist.length >= 2, m);
  }
  // No Mac words on a Windows lock.
  for (const item of win) {
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.doesNotMatch(textOf(html), /System Settings|FileVault|Time Machine|macOS/, item.key);
  }
});

test('locks with no pane on the Mac show the steps (firmware, antivirus, Homebrew, saved keys)', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  for (const [m, re] of [['firmware_password'], ['antivirus_status'], ['update_checker', /brew_outdated/], ['session_revocation_scan']]) {
    const d = game.decisions(find(mac, m, re), ctx)[0];
    assert.strictEqual(d.effect.kind, 'closer', m);
    assert.ok(d.effect.checklist.length >= 2, m);
  }
});

test('"couldn\'t check" is never fine: Not checked, the didn\'t-finish line, Check it myself / Check again', async () => {
  const { C, game, mod, mac, win } = await setup();
  for (const [item, ctx] of [[find(mac, 'time_machine_check'), C.testContext()], [find(win, 'win_update_history'), C.testContext({ platform: 'win32' })]]) {
    assert.ok(mod.couldntCheck(item), item.key);
    const d = game.decisions(item, ctx);
    assert.strictEqual(d[0].label.standard, 'Check it myself');
    assert.strictEqual(d[1].label.standard, 'Check again');
    assert.strictEqual(d[1].effect.kind, 'recheck');
    const r = game.research(item, ctx);
    assert.match(r.notChecked, /didn’t finish/);
    const t = textOf(game.render({ item, research: r, decisions: d, index: 0, total: 1 }, ctx));
    assert.match(t, /Not checked/);
    assert.doesNotMatch(t, /\b(?:On|Fine|All clear|Locked)\b/);
  }
  // A check the runner says didn't finish counts too, whatever its title.
  const unfinished = { ...find(mac, 'automatic_updates'), incomplete: true };
  assert.ok(mod.couldntCheck(unfinished));
  // An ordinary off switch is not "couldn't check".
  assert.ok(!mod.couldntCheck(find(mac, 'firewall_audit')));
});

test('the macOS "couldn\'t check for updates" note (engine wording) reads as not checked', async () => {
  const { C, mod } = await setup();
  const item = C.makeItem({ module: 'update_checker', severity: 'info', title: 'Couldn\'t check for macOS updates', data: { check: 'os_updates_not_checked', timeout_s: 40 } });
  assert.ok(mod.couldntCheck(item));
});

test('recovery-key locks say never to paste the key anywhere, in both modes; nothing asks for it', async () => {
  const { C, game, mac, win } = await setup();
  for (const [item, platform] of [[find(mac, 'filevault_recovery'), 'darwin'], [find(win, 'win_bitlocker'), 'win32']]) {
    for (const mode of ['standard', 'city']) {
      const ctx = C.testContext({ mode, platform });
      const r = game.research(item, ctx);
      const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
      assert.match(textOf(html), /Never type or paste your recovery key/, `${item.key} ${mode}`);
      assert.doesNotMatch(html, /<input|<textarea|contenteditable/i);
    }
  }
  // Every lock, every mode: no field, and no request for a password, code or key.
  for (const item of [...mac, ...win, ...game.practice.items]) {
    for (const mode of ['standard', 'city']) {
      const ctx = C.testContext({ mode });
      const t = textOf(game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx));
      assert.doesNotMatch(t, /(?:enter|type|paste|share|send)\s+(?:us\s+|it\s+|in\s+)?your\s+(?:password|recovery key|code)\s+(?:here|below|in)\b/i, item.key);
    }
  }
});

test('the saved-keys lock (removal warning) never puts a removal first', async () => {
  const { C, game, mac } = await setup();
  const item = find(mac, 'session_revocation_scan');
  assert.ok(item.removal_alert);
  const d = game.decisions(item, C.testContext());
  assert.notStrictEqual(d[0].effect.kind, 'fix');
  assert.ok(!d.some((x) => x.effect.kind === 'fix'));
});

test('research: what it protects, where the switch is, allowlisted link intents only', async () => {
  const { C, game, mac } = await setup();
  const r = game.research(find(mac, 'firmware_password'), C.testContext());
  assert.match(r.what, /another disk/);
  assert.match(r.where, /Startup Security Utility/);
  assert.deepStrictEqual(C.checkResearch(r), []);
  assert.ok(r.links.some((l) => l.kind === 'lookup' && l.source === 'apple-support'));
  const fv = game.research(find(mac, 'encryption_check'), C.testContext());
  assert.ok(fv.links.some((l) => l.kind === 'settings' && l.pane === 'filevault'));
  assert.ok(fv.links.some((l) => l.kind === 'lesson' && l.concept === 'disk-encryption'));
  // Look-ups are fixed queries, never scan values.
  const hostile = C.makeItem({ module: 'firmware_password', code: 'security.firmware_password.firmware_password_not_set', title: '<b>x</b>', data: { check: 'firmware_password_not_set', name: 'evil' } });
  for (const l of game.research(hostile, C.testContext()).links) if (l.kind === 'lookup') assert.doesNotMatch(l.query, /evil|<b>/);
});

test('research rows come from ctx.evidenceRows; render leaves evidence, buttons and links to the runner', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext({ evidenceRows: () => [{ label: 'File', value: 'EVIDENCE-ROW-VALUE', mono: true }] });
  const item = find(mac, 'session_revocation_scan');
  const r = game.research(item, ctx);
  assert.strictEqual(r.rows[0].value, 'EVIDENCE-ROW-VALUE');
  const html = game.render({ item, research: r, decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
  assert.doesNotMatch(html, /EVIDENCE-ROW-VALUE|<button|<a\b|href=/);
});

test('the saved-keys lock asks the runner for the removal warning (warning: true)', async () => {
  const { C, game, mac } = await setup();
  const d = game.decisions(find(mac, 'session_revocation_scan'), C.testContext());
  assert.strictEqual(d[0].effect.warning, true);
  assert.ok(!game.decisions(find(mac, 'firewall_audit'), C.testContext())[0].effect.warning);
});

test('an item the foundation marks unfinished shows "This check didn\'t finish"', async () => {
  const { C, game, mac } = await setup();
  const item = { ...find(mac, 'firewall_audit'), unfinished: true };
  const ctx = C.testContext();
  const t = textOf(game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx));
  assert.match(t, /This check didn’t finish/);
  assert.match(t, /Not checked/);
});

test('render: a row of locks with the current one marked, the lock\'s name, state and what it protects', async () => {
  const { C, game, mac } = await setup();
  const item = find(mac, 'firewall_audit');
  for (const [mode, name, state] of [['standard', 'Firewall', 'Off'], ['city', 'Outer wall', 'Unlocked']]) {
    const ctx = C.testContext({ mode });
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 1, total: 4 }, ctx);
    assert.strictEqual((html.match(/class="lk-pip/g) || []).length, 4);
    assert.match(html, /lk-pip lk-pip--here/);
    assert.match(textOf(html), new RegExp(name));
    assert.match(textOf(html), new RegExp(state));
    assert.match(textOf(html), /didn’t get asked for/);
    // Past locks are visited, never drawn as shut.
    assert.doesNotMatch(html, /lk-pip--shut/);
  }
});

test('city mode: game words only, practice included', async () => {
  const { C, game, mac, win } = await setup();
  const ctx = C.testContext({ mode: 'city' });
  for (const item of [...mac, ...win, ...game.practice.items]) {
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1, practice: true }, ctx);
    assert.deepStrictEqual(C.checkCityWords(html), [], item.key);
  }
  for (const step of game.practice.script) assert.deepStrictEqual(C.checkCityWords(step.say.city), []);
  assert.strictEqual(game.title.city, 'Lock Run');
});

test('practice: updates off, FileVault off, screen lock never — synthetic, with a guided script', async () => {
  const { C, game } = await setup();
  const mods = game.practice.items.map((i) => i.finding.module);
  assert.deepStrictEqual(mods, ['automatic_updates', 'encryption_check', 'screen_lock_check']);
  for (const step of game.practice.script) {
    assert.ok(step.item >= 0 && step.item < game.practice.items.length);
    assert.ok(step.say.standard && step.say.city);
    if (step.expect) assert.ok(game.decisions(game.practice.items[step.item], C.testContext()).some((d) => d.id === first(step.expect)));
  }
  assert.ok(game.practice.script.some((s) => /Never paste/.test(s.say.standard + (s.why ? s.why.standard : ''))));
  // The coach line shows when the runner passes a step.
  const ctx = C.testContext();
  const html = game.render({ item: game.practice.items[0], research: game.research(game.practice.items[0], ctx), decisions: [], index: 0, total: 3, practice: true, step: game.practice.script[0] }, ctx);
  assert.match(html, /lr-coach/);
  assert.match(textOf(html), /Practice/);
  assert.doesNotMatch(JSON.stringify(game.practice.items), /\/Users\/|\\Users\\/);
});

test('summary: counts each decision, names what couldn\'t be checked, never says all clear', async () => {
  const { C, game, mac } = await setup();
  const results = [
    { item: find(mac, 'firewall_audit'), decision: 'on' },
    { item: find(mac, 'encryption_check'), decision: { id: 'done' } },
    { item: find(mac, 'time_machine_check'), decision: 'later' },
  ];
  for (const mode of ['standard', 'city']) {
    const t = textOf(game.summary(results, C.testContext({ mode })));
    assert.match(t, /3/);
    assert.match(t, mode === 'city' ? /fog/ : /couldn’t be checked/);
    assert.doesNotMatch(t, /all clear|you(?:’|')re safe|nothing wrong/i);
  }
  assert.match(textOf(game.summary([], C.testContext())), /don’t rule one out/);
});

test('no time words in the game\'s own copy', async () => {
  const { C, game, mac } = await setup();
  const TIME = /\b(?:seconds?|minutes?|hours?|quick(?:ly)?|soon|instantly|in no time)\b/i;
  const ctx = C.testContext();
  for (const item of game.practice.items) {
    const r = game.research(item, ctx);
    assert.doesNotMatch(`${r.what} ${r.where} ${r.steps.join(' ')} ${r.notChecked}`, TIME, item.key);
  }
  for (const step of game.practice.script) assert.doesNotMatch(`${step.say.standard} ${step.say.city}`, TIME);
  assert.doesNotMatch(textOf(game.summary([{ item: find(mac, 'firewall_audit'), decision: 'on' }], ctx)), TIME);
});

test('covers: the locks row of the spec, Windows equivalents, the firewall switch and stealth, protection switches by code', async () => {
  const { game } = await setup();
  const by = new Map(game.covers.map((c) => [c.module, c]));
  for (const m of ['automatic_updates', 'update_checker', 'encryption_check', 'filevault_recovery', 'firewall_audit', 'screen_lock_check', 'lock_screen_check',
    'find_my_mac_check', 'guest_account_check', 'firmware_password', 'login_password_policy', 'antivirus_status', 'macos_version_support', 'macos_eol_check',
    'backup_status', 'time_machine_check', 'session_revocation_scan', 'appleid_security_check',
    'win_updates', 'win_windows_update_status', 'win_bitlocker', 'win_bitlocker_check', 'win_defender', 'win_antivirus_status', 'win_firewall']) {
    assert.ok(by.has(m), `${m} not covered`);
  }
  assert.strictEqual(by.get('firewall_audit').codes, undefined, 'the whole firewall_audit (switch, stealth, couldn’t check)');
  assert.deepStrictEqual(by.get('firewall_rules_audit').codes, ['security.firewall_rules_audit.alf_', 'security.firewall_rules_audit.stealth_']);
  assert.ok(!by.has('win_firewall_rules_audit'), 'Windows rules belong to the switchboard');
  for (const m of ['clamav_scanner', 'browser_privacy_check', 'default_browser']) assert.ok(by.has(m) && !by.get(m).codes, m);
  assert.deepStrictEqual(by.get('rootkit_check').codes, ['security.rootkit_check.sip_disabled']);
  assert.deepStrictEqual(by.get('win_rootkit_check').codes, ['security.win_rootkit_check.secure_boot_disabled']);
  assert.deepStrictEqual(by.get('win_malware_indicators').codes, ['security.win_malware_indicators.safe_mode_disabled']);
  // No duplicate (module, code) claims inside this game.
  const seen = new Set();
  for (const c of game.covers) for (const code of c.codes || ['*']) {
    const k = `${c.module}|${code}`;
    assert.ok(!seen.has(k), k);
    seen.add(k);
  }
});

test('covers name real engine modules, and narrowed codes are real finding codes', async () => {
  const { game } = await setup();
  const root = path.join(__dirname, '..', '..', 'modules');
  const dirs = new Map();
  for (const cat of fs.readdirSync(root)) {
    const p = path.join(root, cat);
    if (fs.statSync(p).isDirectory()) for (const m of fs.readdirSync(p)) dirs.set(m, path.join(p, m, '__init__.py'));
  }
  for (const c of game.covers) {
    assert.ok(dirs.has(c.module) && fs.existsSync(dirs.get(c.module)), `${c.module} is not an engine module`);
    const src = fs.readFileSync(dirs.get(c.module), 'utf8');
    for (const code of c.codes || []) assert.ok(src.includes(`"${code}`), `${code} is not a code of ${c.module}`);
  }
});

test('the game is pure: no DOM, storage, network, clipboard or globals', async () => {
  const src = fs.readFileSync(path.join(MISSIONS, 'games', 'locks.js'), 'utf8').replace(/\/\/.*$/gm, '');
  assert.doesNotMatch(src, /\b(?:document|window|globalThis|navigator)\s*\.|\b(?:localStorage|sessionStorage|XMLHttpRequest|clipboard)\b|\bfetch\s*\(|\brequire\s*\(|\bimport\s*\(/);
  assert.doesNotMatch(src, /https?:\/\/|x-apple\.systempreferences|ms-settings:/, 'games return intents, never URLs');
});

test('the state badge fits the lock: a missing key is Missing, automatic sign-in is On, a plain switch is Off', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const badge = (item) => (game.render({ item, research: game.research(item, ctx), decisions: [], index: 0, total: 1 }, ctx).match(/class="lk-state[^"]*">([^<]*)</) || [])[1];
  assert.strictEqual(badge(find(mac, 'filevault_recovery')), 'Missing');
  assert.strictEqual(badge(find(mac, 'login_password_policy')), 'On');
  assert.strictEqual(badge(find(mac, 'firewall_audit')), 'Off');
  assert.strictEqual(badge(find(mac, 'time_machine_check')), 'Not checked');
  assert.strictEqual(game.decisions(find(mac, 'filevault_recovery'), ctx)[0].label.standard, 'Open FileVault');
  assert.strictEqual(game.decisions(find(mac, 'login_password_policy'), ctx)[0].label.standard, 'Turn it off');
});

test('summary: says how a lock pays when nothing has paid yet; no such line once points came', async () => {
  const C = await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'contract.js')).href);
  const game = (await import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'games', 'locks.js')).href)).default;
  const item = game.practice.items[0];
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const none = game.summary([{ item, decision: 'later', points: 0 }], ctx);
    assert.match(none, /No points yet/);
    assert.doesNotMatch(game.summary([{ item, decision: 'done', points: 75 }], ctx), /No points yet/);
    assert.doesNotMatch(game.summary([], ctx), /No points yet/);
    if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(none), []);
  }
});

test('Lock Run’s classes are its own: no class name shared with the Evidence Locker’s stylesheet', () => {
  const classes = (file) => new Set(fs.readFileSync(path.join(MISSIONS, 'games', file), 'utf8').replace(/\/\*[\s\S]*?\*\//g, '').match(/\.[a-z][a-z0-9_-]*/gi) || []);
  const locks = classes('locks.css');
  const shared = [...classes('locker.css')].filter((c) => locks.has(c));
  assert.deepStrictEqual(shared, []);
});

// --- sleep, screen-off, Power Nap and wake: Lock Run's sleep locks ---
const SLEEP_MODULES = ['energy_saver_check', 'energy_settings', 'power_settings', 'clamshell_mode'];

test('sleep locks: screen-off opens Lock Screen, sleep / Power Nap / wake open Battery (Energy), Windows opens Power', async () => {
  const { C, mod, game, mac, win } = await setup();
  const ctx = C.testContext();
  const screen = find(mac, 'energy_saver_check', /display_sleep/);
  assert.strictEqual(mod.lockOf(screen.finding), 'screen-off');
  assert.deepStrictEqual(game.decisions(screen, ctx)[0].effect, { kind: 'settings', pane: 'lock-screen' });
  assert.match(game.research(screen, ctx).where, /Lock Screen/);
  for (const [m, re, line] of [['power_settings', null, /Prevent automatic sleeping/], ['energy_settings', null, /Power Nap/], ['energy_saver_check', /wake_on_lan/, /Wake for network access/]]) {
    const it = find(mac, m, re);
    assert.strictEqual(mod.lockOf(it.finding), 'sleep', m);
    assert.deepStrictEqual(game.decisions(it, ctx)[0].effect, { kind: 'settings', pane: 'battery' }, m);
    const r = game.research(it, ctx);
    assert.match(r.where, /Battery/, m);
    assert.match(r.where, line, m);
    assert.ok(r.links.some((l) => l.kind === 'settings' && l.pane === 'battery'), m);
  }
  // Proximity Wake has no switch in System Settings: the steps, no page.
  const prox = find(mac, 'clamshell_mode');
  assert.strictEqual(mod.lockOf(prox.finding), 'sleep');
  const d = game.decisions(prox, ctx)[0];
  assert.strictEqual(d.effect.kind, 'closer');
  assert.ok(d.effect.checklist.length >= 1);
  // Windows: the sleep timeout opens Settings > System > Power.
  const w = find(win, 'win_power_plan_check');
  const wctx = C.testContext({ platform: 'win32' });
  assert.strictEqual(mod.lockOf(w.finding), 'sleep');
  assert.deepStrictEqual(game.decisions(w, wctx)[0].effect, { kind: 'settings', pane: 'windows-power' });
  assert.match(game.research(w, wctx).where, /Settings > System > Power/);
  // Lock Run's other power-plan items aren't locks.
  assert.strictEqual(mod.lockOf({ module: 'win_power_plan_check', data: { type: 'power_saver_active' } }), null);
});

test('sleep locks: names and states in both modes; labels are calm and short', async () => {
  const { C, game, mac } = await setup();
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    for (const it of mac.filter((i) => SLEEP_MODULES.includes(i.finding.module))) {
      const html = game.render({ item: it, research: game.research(it, ctx), decisions: game.decisions(it, ctx), index: 0, total: 1 }, ctx);
      assert.doesNotMatch(textOf(html), /Automatic updates|Patch lock/, `${it.key} isn't drawn as the updates lock`);
      if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(html), [], it.key);
      for (const dd of game.decisions(it, ctx)) assert.ok(dd.label[mode].split(/\s+/).length <= 4, dd.label[mode]);
    }
  }
});

test('covers: Lock Run claims the sleep checks (and Windows’ sleep timeout by its type); nothing else claims them', async () => {
  const { game } = await setup();
  const by = new Map(game.covers.map((c) => [c.module, c]));
  for (const m of SLEEP_MODULES) assert.ok(by.has(m) && !by.get(m).codes && !by.get(m).checks, m);
  assert.deepStrictEqual(by.get('win_power_plan_check').checks, ['sleep_timeout']);
  const J = (await import(pathToFileURL(path.join(MISSIONS, 'games', 'junkyard.js')).href)).default;
  for (const m of SLEEP_MODULES) assert.ok(!J.covers.some((c) => c.module === m), `the Junkyard gave up ${m}`);
  const T = await import(pathToFileURL(path.join(MISSIONS, 'types.js')).href);
  const I = await import(pathToFileURL(path.join(MISSIONS, 'games', 'index.js')).href);
  const table = T.buildTable(I.ownGames(await I.loadGames()));
  assert.deepStrictEqual(T.doubleClaims(table), []);
  for (const m of SLEEP_MODULES) {
    assert.strictEqual(T.typeOf({ module: m, severity: 'warning', data: { setting: 'sleep' } }, table), 'locks', m);
    assert.strictEqual(T.typeOf({ module: m, severity: 'warning', data: { setting: 'sleep' } }), 'locks', `${m} (base table)`);
    assert.ok(!T.ODD_JOBS.includes(m), `${m} left Odd Jobs`);
  }
  // A Windows sleep timeout the person calls odd is a lock; the power plan's other items stay in the Junkyard.
  assert.strictEqual(T.claimedType({ module: 'win_power_plan_check', data: { type: 'sleep_timeout' } }, table), 'locks');
  assert.strictEqual(T.typeOf({ module: 'win_power_plan_check', severity: 'warning', data: { type: 'power_saver_active' } }, table), 'junkyard');
  // The real data.type value in the engine.
  const src = fs.readFileSync(path.join(__dirname, '..', '..', 'modules', 'performance', 'win_power_plan_check', '__init__.py'), 'utf8');
  assert.ok(src.includes('"type": "sleep_timeout"'));
});

// --- Windows practice ---
test('Windows practice: Windows Update paused, BitLocker off, a computer that never sleeps — in Windows words', async () => {
  const { C, game } = await setup();
  const p = C.practiceOf(game, 'win32');
  assert.notStrictEqual(p, game.practice);
  assert.deepStrictEqual(p.items.map((i) => i.finding.module), ['win_windows_update_status', 'win_bitlocker', 'win_power_plan_check']);
  assert.strictEqual(p.script.length, game.practice.script.length, 'same steps, so the profile measures them alike');
  const ctx = C.testContext({ platform: 'win32' });
  const panes = p.items.map((i) => game.decisions(i, ctx)[0].effect.pane);
  assert.deepStrictEqual(panes, ['windows-update', 'windows-bitlocker', 'windows-power']);
  for (const step of p.script) {
    assert.ok(step.item >= 0 && step.item < p.items.length);
    if (step.expect) assert.ok(game.decisions(p.items[step.item], ctx).some((d) => d.id === first(step.expect)));
  }
  const words = (mode) => [...p.items.map((i) => i.finding.title), ...p.script.flatMap((s) => [s.say[mode], s.why ? s.why[mode] : '']),
    ...p.items.map((i) => { const r = game.research(i, C.testContext({ platform: 'win32', mode })); return `${r.where} ${r.what} ${r.steps.join(' ')}`; })].join(' ');
  const std = words('standard');
  assert.match(std, /Settings > Accounts > Sign-in options/);
  assert.match(std, /Windows Hello/);
  assert.match(std, /Settings > System > Power/);
  assert.match(std, /Never paste/);
  for (const mode of ['standard', 'city']) {
    assert.doesNotMatch(words(mode), /\bMac\b|macOS|FileVault|System Settings|Time Machine/, `${mode}: no Mac words`);
    assert.doesNotMatch(words(mode), /\b(?:seconds?|minutes?|hours?|quick(?:ly)?|soon|instantly|in no time)\b/i, `${mode}: no time words`);
    assert.deepStrictEqual(C.checkCityWords(words('city')), []);
  }
  assert.doesNotMatch(JSON.stringify(p.items), /\/Users\/|\\Users\\/);
  assert.deepStrictEqual(C.runContractChecks(game, []), []);
});
