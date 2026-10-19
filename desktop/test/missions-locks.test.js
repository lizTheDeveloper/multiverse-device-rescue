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
  assert.match(html, /lk-coach/);
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
