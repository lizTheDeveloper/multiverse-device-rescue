'use strict';
// The Loadout: browser add-ons mini-game (spec: little missions, "loadout").
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const fs = require('fs');
const { pathToFileURL } = require('url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const loadContract = () => import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
const loadGame = async () => (await import(pathToFileURL(path.join(MISSIONS, 'games', 'loadout.js')).href)).default;
const FIX = JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'missions', 'loadout-findings.json'), 'utf8'));

async function setup() {
  const C = await loadContract();
  const game = await loadGame();
  const items = (list) => list.map((f) => C.makeItem(f));
  return { C, game, mac: items(FIX.darwin), win: items(FIX.win32) };
}
const byTitle = (items, re) => items.find((i) => re.test(i.finding.title));
const ids = (ds) => ds.map((d) => d.id);
const allText = (x) => JSON.stringify(x);

// ---- Task 1: contract and covers ----

test('loadout passes every contract check on macOS and Windows fixtures and its practice', async () => {
  const { C, game, mac, win } = await setup();
  assert.deepStrictEqual(C.runContractChecks(game, mac), []);
  // Windows ctx: run the same checks with platform win32 by wrapping testContext.
  const p = [];
  for (const mode of ['standard', 'city']) {
    for (const item of win) {
      const ctx = C.testContext({ mode, platform: 'win32' });
      const d = game.decisions(item, ctx);
      p.push(...C.checkDecisions(d, item));
      const r = game.research(item, ctx);
      p.push(...C.checkResearch(r));
      const html = game.render({ item, research: r, decisions: d, index: 0, total: 1 }, ctx);
      p.push(...C.checkInert(html));
      if (mode === 'city') p.push(...C.checkCityWords(html + allText(d)));
    }
  }
  assert.deepStrictEqual(p, []);
});

test('covers claims the browser modules and only the baseline extension code', async () => {
  const { game } = await setup();
  const mods = game.covers.map((c) => c.module).sort();
  assert.deepStrictEqual(mods, ['browser_cryptojacking_check', 'browser_extension_audit', 'browser_hijack_check',
    'chrome_extensions', 'safari_extensions', 'security_baseline_diff']);
  const base = game.covers.find((c) => c.module === 'security_baseline_diff');
  assert.deepStrictEqual(base.codes, ['security.security_baseline_diff.new_browser_extension']);
  assert.strictEqual(game.type, 'loadout');
  assert.deepStrictEqual(game.title, { standard: 'Browser add-ons', city: 'The Loadout' });
  assert.ok(game.concepts.includes('browser-add-ons'));
});

// ---- Task 2: powers in plain words, the card ----

test('permissions read as plain words, the strongest first', async () => {
  const { game } = await setup();
  const p = game.powers(['activeTab', 'tabs', '<all_urls>', 'cookies'], 'standard');
  assert.strictEqual(p[0].text, 'Read and change all your data on all websites');
  assert.strictEqual(p[0].level, 'high');
  assert.ok(p.some((x) => x.text === 'Read the cookies that keep you signed in'));
  assert.ok(p.some((x) => x.text === 'Read your browsing history'));
  assert.strictEqual(p[p.length - 1].level, 'low');
  assert.deepStrictEqual(game.powers(['all_urls', '<all_urls>'], 'standard').length, 1, 'same power once');
  const host = game.powers(['https://*.example.com/*'], 'standard')[0];
  assert.match(host.text, /example\.com/);
  const odd = game.powers(['someNewPermission'], 'standard')[0];
  assert.strictEqual(odd.text, 'someNewPermission');
  assert.strictEqual(odd.raw, true);
});

test('the extension card: name, browser, powers; no access reads as such', async () => {
  const { C, game, mac } = await setup();
  const item = byTitle(mac, /Tab Tidy/);
  const ctx = C.testContext();
  const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
  assert.match(html, /Tab Tidy Example/);
  assert.match(html, /Chrome/);
  assert.match(html, /Read and change all your data on all websites/);
  const theme = game.practice.items[2];
  const t = game.render({ item: theme, research: game.research(theme, C.testContext({ practice: true })), decisions: game.decisions(theme, ctx), index: 2, total: 3, practice: true }, ctx);
  assert.match(t, /Asks for no special access/);
});

test('hostile names, ids and permissions are escaped and never reach typed steps', async () => {
  const { C, game } = await setup();
  for (const h of C.HOSTILE) {
    const item = C.makeItem({ module: 'browser_extension_audit', code: 'security.browser_extension_audit.excessive_permissions', title: h, removal_alert: true,
      data: { check: 'excessive_permissions', browser: h, extension: h, extension_id: h, permissions: [h, '<all_urls>'] } });
    for (const mode of ['standard', 'city']) {
      const ctx = C.testContext({ mode });
      const d = game.decisions(item, ctx);
      const r = game.research(item, ctx);
      assert.deepStrictEqual(C.checkInert(game.render({ item, research: r, decisions: d, index: 0, total: 1 }, ctx)), []);
      const steps = d.flatMap((x) => x.effect.steps || []).join('\n');
      assert.ok(!steps.includes(h), 'a scan value that is not a valid id never lands in typed steps');
      assert.ok(!r.links.some((l) => l.source === 'chrome-web-store'), 'no store look-up for an invalid id');
    }
  }
});

// ---- Task 3: decisions and browser steps ----

test('an extension: Trim / Keep / Remove on a warning (Keep / Trim / Remove on a note), Remove never first, mark only when markable', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const plain = byTitle(mac, /Tab Tidy/);
  const d = game.decisions(plain, ctx);
  assert.deepStrictEqual(ids(d), ['trim', 'keep', 'remove'], 'a warning never leads with Keep');
  assert.strictEqual(d[1].effect.kind, 'keep');
  assert.notStrictEqual(d[2].effect.kind, 'fix', 'no engine fix for extensions: instructions');
  const note = C.makeItem({ ...plain.finding, severity: 'info', removal_alert: false, remediation: null });
  assert.deepStrictEqual(ids(game.decisions(note, ctx)), ['keep', 'trim', 'remove']);
  const markable = byTitle(mac, /Price Pal/);
  assert.strictEqual(game.decisions(markable, ctx).find((x) => x.id === 'keep').effect.kind, 'mark');
  const fixable = C.makeItem({ ...plain.finding, fixable: { will_change: 'x', how_to_undo: ['y'] } });
  const df = game.decisions(fixable, ctx);
  assert.strictEqual(df[2].effect.kind, 'fix');
  assert.deepStrictEqual(C.checkDecisions(df, fixable), []);
});

test('Chrome steps say what to type, with the extension id, and Return on a Mac', async () => {
  const { C, game, mac } = await setup();
  const d = game.decisions(byTitle(mac, /Tab Tidy/), C.testContext());
  const trim = d.find((x) => x.id === 'trim').effect.steps.join('\n');
  assert.match(trim, /chrome:\/\/extensions\/\?id=abcdefghijklmnopabcdefghijklmnop/);
  assert.match(trim, /Return/);
  assert.match(trim, /Site access/);
  const remove = d.find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(remove, /Remove/);
});

test('Windows: the mining check\'s "User Data" browser is read from its path (Edge, Chrome), Enter not Return', async () => {
  const { C, game, win } = await setup();
  const ctx = C.testContext({ platform: 'win32' });
  const edge = byTitle(win, /Coin Helper/);
  assert.strictEqual(game.browserOf(edge.finding).id, 'edge');
  const steps = game.decisions(edge, ctx).find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(steps, /edge:\/\/extensions\/\?id=bbbbccccddddeeeeffffgggghhhhiiii/);
  assert.match(steps, /Enter/);
  assert.doesNotMatch(steps, /Return/);
  assert.strictEqual(game.browserOf(byTitle(win, /Weather Now/).finding).id, 'chrome');
  const page = byTitle(win, /mine\.example\.test\/edge/);
  assert.strictEqual(game.browserOf(page.finding).id, 'unknown', 'a Windows startup page names no browser folder');
  const hosts = win.find((i) => i.finding.data.check === 'mining_hosts_entry');
  const hs = game.decisions(hosts, ctx).find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(hs, /Notepad/);
  assert.match(hs, /drivers\\etc\\hosts/);
});

test('Firefox, Safari, Brave and an unknown browser each get their own page', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const ff = game.decisions(byTitle(mac, /babylon/), ctx).find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(ff, /about:addons/);
  const sf = game.decisions(byTitle(mac, /Adware extension found: coupon/), ctx).find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(sf, /Safari > Settings/);
  assert.match(sf, /Extensions/);
  const brave = game.decisions(byTitle(mac, /Speedy Tabs/), ctx).find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(brave, /brave:\/\/extensions\/\?id=hhhhggggffffeeeeddddccccbbbbaaaa/);
  assert.match(brave, /sync/i, 'a miner: sync can bring it back');
  const many = game.decisions(byTitle(mac, /a lot of browser extensions/), ctx);
  assert.deepStrictEqual(ids(many), ['trim', 'keep']);
  const m = many.find((x) => x.id === 'trim').effect.steps.join('\n');
  assert.match(m, /chrome:\/\/extensions/);
  assert.match(m, /about:addons/);
  assert.match(m, /Safari > Settings/);
});

test('each other kind gets its own moves', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const want = [
    [/known to be malicious/, ['closer', 'remove', 'keep']],
    [/Adware extension/, ['closer', 'remove', 'keep']],
    [/secretly mining/, ['closer', 'remove', 'keep']],
    [/opens a mining page/, ['closer', 'reset']],
    [/hosts file sends/, ['closer', 'remove']],
    [/Chrome is opening to a website/, ['closer', 'reset', 'keep']],
    [/Safari is using a search engine/, ['closer', 'reset', 'keep']],
    [/organization policy/, ['closer', 'keep']],
    [/Old-style Safari/, ['closer', 'keep', 'remove']],
    [/content blockers are off/, ['turn-on', 'keep']],
    [/new browser extension/, ['closer', 'keep', 'remove']],
  ];
  for (const [re, expected] of want) {
    const item = byTitle(mac, re);
    assert.ok(item, String(re));
    const d = game.decisions(item, ctx);
    assert.deepStrictEqual(ids(d), expected, String(re));
    assert.deepStrictEqual(C.checkDecisions(d, item), [], String(re));
  }
  const reset = game.decisions(byTitle(mac, /Chrome is opening/), ctx).find((x) => x.id === 'reset').effect.steps.join('\n');
  assert.match(reset, /chrome:\/\/settings\/onStartup/);
  const sreset = game.decisions(byTitle(mac, /Safari is using/), ctx).find((x) => x.id === 'reset').effect.steps.join('\n');
  assert.match(sreset, /Safari > Settings > Search/);
  const freset = game.decisions(byTitle(mac, /Firefox is using/), ctx).find((x) => x.id === 'reset').effect.steps.join('\n');
  assert.match(freset, /about:preferences#search/);
  const hosts = game.decisions(byTitle(mac, /hosts file sends/), ctx).find((x) => x.id === 'remove').effect.steps.join('\n');
  assert.match(hosts, /sudo nano \/etc\/hosts/);
  const closer = game.decisions(byTitle(mac, /organization policy/), ctx).find((x) => x.id === 'closer').effect;
  assert.ok(closer.checklist.some((s) => /chrome:\/\/management/.test(s)));
});

test('R6: remove and trim carry warning:true on an item with the removal warning, not otherwise', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext();
  const d = game.decisions(byTitle(mac, /Tab Tidy/), ctx);
  assert.strictEqual(d.find((x) => x.id === 'remove').effect.warning, true);
  assert.strictEqual(d.find((x) => x.id === 'trim').effect.warning, true);
  assert.ok(!d.find((x) => x.id === 'keep').effect.warning, 'keeping needs no warning');
  const miner = game.decisions(byTitle(mac, /secretly mining/), ctx);
  assert.ok(!miner.find((x) => x.id === 'remove').effect.warning, 'no removal_alert on the mining finding');
});

test('R1: render draws only the card: no buttons, links or evidence rows', async () => {
  const { C, game, mac } = await setup();
  const ctx = C.testContext({ evidenceRows: () => [{ label: 'ROWLABEL', value: 'ROWVALUE' }] });
  for (const item of mac) {
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.doesNotMatch(html, /<button|<a\b|ROWLABEL/);
  }
});

// ---- Task 4: research ----

test('research: rows from evidenceRows, what is known, store look-up by id, lesson', async () => {
  const { C, game, mac } = await setup();
  const rows = [{ label: 'Extension', value: 'Tab Tidy Example' }];
  const ctx = C.testContext({ evidenceRows: () => rows });
  const r = game.research(byTitle(mac, /Tab Tidy/), ctx);
  assert.strictEqual(r.rows, rows);
  assert.ok(r.links.some((l) => l.kind === 'lookup' && l.source === 'chrome-web-store' && l.query === 'abcdefghijklmnopabcdefghijklmnop'));
  assert.ok(r.links.some((l) => l.kind === 'lesson' && l.concept === 'browser-add-ons'));
  assert.match(r.what, /Unknown maker|don.t know/i);
  const pm = game.research(byTitle(mac, /Bitwarden/), ctx);
  assert.match(pm.what, /Bitwarden/);
  assert.match(pm.what, /password manager/i);
  const ff = game.research(byTitle(mac, /babylon/), ctx);
  assert.ok(ff.links.some((l) => l.source === 'web' && /"babylon"/.test(l.query) && /Firefox/.test(l.query)));
  assert.ok(!ff.links.some((l) => l.source === 'chrome-web-store'));
  const mined = game.research(byTitle(mac, /secretly mining/), ctx);
  assert.ok(mined.links.some((l) => l.kind === 'lesson' && l.concept === 'wifi-and-mining'));
  const managed = game.research(byTitle(mac, /organization policy/), ctx);
  assert.ok(managed.links.some((l) => l.kind === 'settings' && l.pane === 'profiles'));
  const added = game.research(byTitle(mac, /new browser extension/), ctx);
  assert.strictEqual(added.links.filter((l) => l.source === 'chrome-web-store').length, 2);
  const verified = C.makeItem({ ...byTitle(mac, /Tab Tidy/).finding, makers_verified: true, made_by: [{ subject: 'x', name: 'Example Co', verified: true, what: 'Tab Tidy: groups your tabs.' }] });
  assert.match(game.research(verified, ctx).what, /groups your tabs/);
  // Another program's verified entry on a finding that names several: not this add-on's.
  const other = C.makeItem({ ...byTitle(mac, /Tab Tidy/).finding, data: { ...byTitle(mac, /Tab Tidy/).finding.data, path: '/opt/ext/a', apps: ['/Applications/Other.app'] },
    made_by: [{ subject: '/Applications/Other.app', name: 'Other Co', verified: true, what: 'Other: a different app.' }, { subject: '/opt/ext/a', name: 'Nobody', verified: false }] });
  assert.doesNotMatch(game.research(other, ctx).what, /different app/);
});

test('the card is honest about an unfinished check (R2); practice gives no look-ups', async () => {
  const { C, game, mac } = await setup();
  const item = { ...byTitle(mac, /Tab Tidy/), unfinished: true };
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const html = game.render({ item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: 1 }, ctx);
    assert.match(html, /didn’t finish/);
  }
  const done = byTitle(mac, /Tab Tidy/);
  const ctx0 = C.testContext();
  assert.doesNotMatch(game.render({ item: done, research: game.research(done, ctx0), decisions: [], index: 0, total: 1 }, ctx0), /didn’t finish/);
  for (const p of game.practice.items) {
    const r = game.research(p, C.testContext({ practice: true }));
    assert.ok(!r.links.some((l) => l.kind === 'lookup'), 'practice ids are made up');
  }
});

// ---- Task 5: practice and summary ----

test('practice: a password manager (keep), a coupon add-on reading every site (remove), a theme (keep)', async () => {
  const { C, game } = await setup();
  const ctx = C.testContext({ practice: true });
  const [pm, coupon, theme] = game.practice.items;
  assert.match(game.research(pm, ctx).what, /password/i);
  assert.ok(coupon.finding.data.permissions.includes('<all_urls>'));
  assert.match(coupon.finding.data.extension, /coupon/i);
  assert.deepStrictEqual(theme.finding.data.permissions, []);
  const expects = game.practice.script.map((s) => [s.item, s.expect]);
  assert.deepStrictEqual(expects, [[0, 'keep'], [1, 'remove'], [2, 'keep']]);
  for (const s of game.practice.script) {
    assert.ok(ids(game.decisions(game.practice.items[s.item], ctx)).includes(s.expect));
    assert.deepStrictEqual(C.checkCityWords(s.say.city), []);
  }
  assert.ok(game.practice.items.every((i) => i.practice === true));
});

test('summary counts the moves and never says all clear; city words only', async () => {
  const { C, game, mac } = await setup();
  const results = [
    { item: mac[0], decision: { id: 'keep' } },
    { item: mac[1], decision: 'trim' },
    { item: mac[2], decision: { id: 'remove' } },
    { item: mac[3], decision: { id: 'remove' } },
  ];
  const s = game.summary(results, C.testContext());
  assert.match(s, /kept 1/i);
  assert.match(s, /trim 1/i);
  assert.match(s, /remove 2/i);
  assert.doesNotMatch(s, /all clear/i);
  const city = game.summary(results, C.testContext({ mode: 'city' }));
  assert.deepStrictEqual(C.checkCityWords(city), []);
  assert.doesNotMatch(game.summary([], C.testContext()), /all clear/i);
});

test('city mode: no forbidden words in any effect text or render, practice included', async () => {
  const { C, game, mac, win } = await setup();
  for (const platform of ['darwin', 'win32']) {
    const ctx = C.testContext({ mode: 'city', platform });
    for (const item of [...mac, ...win, ...game.practice.items]) {
      const d = game.decisions(item, ctx);
      const r = game.research(item, ctx);
      const html = game.render({ item, research: r, decisions: d, index: 0, total: 1, practice: !!item.practice, step: game.practice.script[0] }, ctx);
      assert.deepStrictEqual(C.checkCityWords(allText(d) + r.what + html), [], item.key);
    }
  }
});

test('no time words in any copy', async () => {
  const { C, game, mac } = await setup();
  const TIME = /\b(minutes?|seconds?|hours?|quick(ly)?|instantly|soon)\b/i;
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    for (const item of [...mac, ...game.practice.items]) {
      const d = game.decisions(item, ctx);
      const r = game.research(item, ctx);
      const text = allText(d) + r.what + game.render({ item, research: r, decisions: d, index: 0, total: 1 }, ctx);
      assert.doesNotMatch(text, TIME, item.key);
    }
    assert.doesNotMatch(allText(game.practice.script), TIME);
  }
});
