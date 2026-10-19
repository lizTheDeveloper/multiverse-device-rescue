'use strict';
// The Keyring: apps with powerful access (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const NotChecked = require('../renderer/not-checked.js');

const R = path.join(__dirname, '..', 'renderer', 'missions');
const load = async () => ({
  C: await import(pathToFileURL(path.join(R, 'contract.js')).href),
  G: (await import(pathToFileURL(path.join(R, 'games', 'keyring.js')).href)).default,
  K: await import(pathToFileURL(path.join(R, 'games', 'keyring.js')).href),
});
const fixture = (name) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', 'missions', name), 'utf8'));

// Every item the fixture gives, the way the foundation hands them over (standard mode keeps held items in the lists).
function itemsOf(doc, mode = 'standard') {
  const l = NotChecked.displayItems(doc, { mode });
  return [...l.critical, ...l.warning, ...l.info].map((it) => ({ ...it, removal_alert: !!it.finding.removal_alert }));
}
const byCode = (items, code) => items.find((i) => i.finding.code === code);
const text = (html) => String(html).replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const view = (item, G, ctx) => ({ item, research: G.research(item, ctx), decisions: G.decisions(item, ctx), index: 0, total: 1, practice: false });

test('passes every contract check for the macOS and Windows fixtures', async () => {
  const { C, G } = await load();
  const items = [...itemsOf(fixture('keyring-scan.json')), ...itemsOf(fixture('keyring-windows.json'))];
  assert.ok(items.length >= 7);
  assert.deepStrictEqual(C.runContractChecks(G, items), []);
});

test('covers the keyring modules, macOS and Windows, with the Windows location code only', async () => {
  const { G } = await load();
  const mods = G.covers.map((c) => c.module);
  for (const m of ['app_permissions', 'privacy_permissions_audit', 'accessibility_permissions', 'keylogger_indicators',
    'screen_time_audit', 'location_services', 'win_cortana_telemetry']) assert.ok(mods.includes(m), m);
  const win = G.covers.find((c) => c.module === 'win_cortana_telemetry');
  assert.deepStrictEqual(win.codes, ['security.win_cortana_telemetry.location_services']);
});

test('each finding maps to its keys and the exact privacy pane', async () => {
  const { K } = await load();
  const k = (f) => K.keysOf({ data: {}, ...f }).map((x) => x.id);
  assert.deepStrictEqual(k({ code: 'security.privacy_permissions_audit.screen_recording_access', data: { service: 'kTCCServiceScreenCapture' } }), ['screen']);
  assert.deepStrictEqual(k({ code: 'security.app_permissions.full_disk_access' }), ['full-disk']);
  assert.deepStrictEqual(k({ code: 'security.privacy_permissions_audit.camera_microphone_combo' }), ['camera', 'microphone']);
  assert.deepStrictEqual(k({ code: 'security.privacy_permissions_audit.screen_accessibility_combo' }), ['screen', 'accessibility']);
  assert.deepStrictEqual(k({ module: 'keylogger_indicators', code: 'security.keylogger_indicators.cgeventtap_usage' }), ['keyboard']);
  assert.deepStrictEqual(k({ code: 'security.location_services.location_desktop_find_my_only' }), ['location']);
  assert.deepStrictEqual(k({ code: 'security.win_cortana_telemetry.location_services' }), ['location']);
  assert.deepStrictEqual(k({ code: 'x.y', data: { service: 'kTCCServiceAppleEvents' } }), ['automation']);
  assert.deepStrictEqual(k({ code: 'security.screen_time_audit.screen_time_no_passcode' }), ['screen-time']);
  assert.strictEqual(K.KEYS.keyboard.pane, 'privacy-input-monitoring');
  assert.strictEqual(K.KEYS.automation.pane, 'privacy-automation');
});

test('Keep is first; Hand back opens that key’s pane; Windows uses its privacy page with the permission', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  const ctx = C.testContext();
  const combo = byCode(items, 'security.privacy_permissions_audit.camera_microphone_combo');
  const d = G.decisions(combo, ctx);
  assert.strictEqual(d[0].id, 'keep');
  const back = d.find((x) => x.id === 'hand_back');
  assert.deepStrictEqual([back.effect.kind, back.effect.pane], ['settings', 'privacy-camera']);
  assert.ok(!d.some((x) => x.id === 'closer'), 'a confirmed maker needs no Look closer');

  const win = itemsOf(fixture('keyring-windows.json'))[0];
  const wd = G.decisions(win, C.testContext({ platform: 'win32' }));
  const wb = wd.find((x) => x.id === 'hand_back');
  assert.deepStrictEqual([wb.effect.kind, wb.effect.pane, wb.effect.permission], ['settings', 'windows-privacy', 'location']);
});

test('a marked-as-yours-able list keeps through MarkFlow; others keep in mission state', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  const acc = byCode(items, 'security.accessibility_permissions.suspicious_accessibility');
  assert.strictEqual(G.decisions(acc, C.testContext())[0].effect.kind, 'mark');
  const loc = byCode(items, 'security.location_services.location_desktop_find_my_only');
  assert.strictEqual(G.decisions(loc, C.testContext())[0].effect.kind, 'keep');
});

test('apps known only by a bundle id never read as confirmed, even when made_by says verified', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  const held = byCode(items, 'security.keylogger_indicators.suspicious_input_monitoring');
  for (const mode of ['standard', 'city']) {
    // In city mode held items never reach a game; a keyboard key that does (a note turned odd) is not held.
    const keys = mode === 'city' ? { ...held, held: false } : held;
    const ctx = C.testContext({ mode });
    const r = G.research(keys, ctx);
    assert.ok(!/Example Keys Co/.test(r.what) && !/keyboard tool/.test(r.what), r.what);
    const html = G.render(view(keys, G, ctx), ctx);
    assert.match(text(html), mode === 'city' ? /Maker unconfirmed/ : /Maker not confirmed/);
    assert.doesNotMatch(html, /Example Keys Co/);
    assert.ok(G.decisions(keys, ctx).some((d) => d.id === 'closer'));
  }
});

test('a full-path app with a verified maker shows the maker and what it is', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  const combo = byCode(items, 'security.privacy_permissions_audit.screen_accessibility_combo');
  const ctx = C.testContext();
  assert.match(G.research(combo, ctx).what, /a screen recorder/);
  const t = text(G.render(view(combo, G, ctx), ctx));
  assert.match(t, /Example Studio Ltd/);
  assert.match(t, /Example Capture/);
  assert.match(t, /Screen Recording/);
  assert.match(t, /Accessibility/);
});

test('keyboard access by an unconfirmed maker always carries the removal warning, never Hand back first', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  for (const code of ['security.keylogger_indicators.suspicious_input_monitoring', 'security.keylogger_indicators.cgeventtap_usage']) {
    const found = byCode(items, code);
    for (const mode of ['standard', 'city']) {
      const it = mode === 'city' ? { ...found, held: false } : found;
      const ctx = C.testContext({ mode });
      const html = G.render(view(it, G, ctx), ctx);
      // A monitoring check's own finding: the runner's removal warning (contract.js isAlertingItem), not the card's.
      assert.ok(C.isAlertingItem(it), `${code} ${mode}: the runner warns`);
      assert.doesNotMatch(html, /kr-warn/, `${code} ${mode}: one warning, the runner's`);
      if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(html), []);
      assert.notStrictEqual(G.decisions(it, ctx)[0].id, 'hand_back');
    }
  }
  // A confirmed maker with a non-keyboard key and no alert: no warning line.
  const plain = C.makeItem({ module: 'privacy_permissions_audit', code: 'security.privacy_permissions_audit.excessive_camera',
    data: { apps: ['/Applications/Example Meet.app'] },
    made_by: [{ subject: '/Applications/Example Meet.app', name: 'Example Meetings Inc', verified: true, what: 'Example Meet: a video-call app.' }] });
  const ctx = C.testContext();
  assert.doesNotMatch(G.render(view(plain, G, ctx), ctx), /kr-warn/);
});

test('scan titles and descriptions are never rendered (engine words stay out of the city)', async () => {
  const { C, G } = await load();
  const it = C.makeItem({ module: 'keylogger_indicators', code: 'security.keylogger_indicators.known_keyloggers', severity: 'critical',
    title: 'Known keylogger app found: spyware', description: 'someone may be spying on you; talk to an advocate',
    data: { check: 'known_keyloggers', apps: ['com.example.recorder'] } });
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const html = G.render(view(it, G, ctx), ctx);
    assert.doesNotMatch(html, /advocate|spying|Known keylogger/);
  }
});

test('a held item in city mode (never expected) renders no app names', async () => {
  const { C, G } = await load();
  const it = C.makeItem({ module: 'keylogger_indicators', code: 'security.keylogger_indicators.suspicious_input_monitoring',
    data: { apps: ['com.example.secretname'] } }, { held: true });
  const ctx = C.testContext({ mode: 'city' });
  const html = G.render(view(it, G, ctx), ctx);
  assert.doesNotMatch(html, /secretname/);
  assert.deepStrictEqual(C.checkCityWords(html), []);
});

test('a check that didn’t finish says so', async () => {
  const { C, G } = await load();
  const it = C.makeItem({ module: 'location_services', code: 'security.location_services.location_desktop_find_my_only', data: {} }, { unfinished: true });
  const ctx = C.testContext();
  assert.match(text(G.render(view(it, G, ctx), ctx)), /This check didn’t finish/);
  const it2 = C.makeItem({ module: 'app_permissions', code: 'security.app_permissions.camera_access', data: { apps: [], incomplete: true } });
  assert.match(text(G.render(view(it2, G, ctx), ctx)), /This check didn’t finish/);
});

test('research: link intents for the pane, a look-up per app, and the lesson', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  const acc = byCode(items, 'security.accessibility_permissions.suspicious_accessibility');
  const r = G.research(acc, C.testContext());
  assert.deepStrictEqual(r.links[0], { kind: 'settings', pane: 'privacy-accessibility' });
  const looks = r.links.filter((l) => l.kind === 'lookup');
  assert.deepStrictEqual(looks.map((l) => l.query), ['com.example.puzzle', 'com.example.helper']);
  assert.ok(looks.every((l) => l.source === 'apple-support'));
  assert.ok(r.links.some((l) => l.kind === 'lesson'));
  const wr = G.research(itemsOf(fixture('keyring-windows.json'))[0], C.testContext({ platform: 'win32' }));
  assert.deepStrictEqual(wr.links[0], { kind: 'settings', pane: 'windows-privacy', permission: 'location' });
});

test('many holders: the card names a few and counts the rest', async () => {
  const { C, G } = await load();
  const apps = Array.from({ length: 15 }, (_, i) => `com.example.app${i}`);
  const it = C.makeItem({ module: 'app_permissions', code: 'security.app_permissions.accessibility_access', data: { apps } });
  const ctx = C.testContext();
  const t = text(G.render(view(it, G, ctx), ctx));
  assert.match(t, /com\.example\.app0/);
  assert.doesNotMatch(t, /com\.example\.app14/);
  assert.match(t, /and 7 more/);
});

test('practice: a screen recorder (keep), a game with Accessibility (hand back), a keyboard tool (look closer)', async () => {
  const { C, G } = await load();
  const { items, script } = G.practice;
  assert.strictEqual(items.length, 3);
  const ctx = C.testContext({ practice: true });
  const expects = script.filter((s) => s.expect).map((s) => [s.item, s.expect]);
  assert.deepStrictEqual(expects, [[0, 'keep'], [1, 'hand_back'], [2, 'closer']]);
  for (const s of script) {
    const ids = G.decisions(items[s.item], ctx).map((d) => d.id);
    if (s.expect) assert.ok(ids.includes(s.expect), `${s.expect} in ${ids}`);
    assert.deepStrictEqual(C.checkCityWords(s.say.city), []);
  }
  // Synthetic only: no home folders.
  assert.doesNotMatch(JSON.stringify(items), /\/Users\//);
});

test('summary counts the keys and never says all clear', async () => {
  const { C, G } = await load();
  const items = itemsOf(fixture('keyring-scan.json'));
  const results = [
    { item: items[0], decision: 'keep' },
    { item: items[1], decision: { id: 'hand_back' } },
    { item: items[2], decision: 'hand_back' },
    { item: items[3], decision: 'closer' },
  ];
  const s = G.summary(results, C.testContext());
  assert.match(text(s), /Kept 1/);
  assert.match(text(s), /Handed back 2/);
  assert.match(text(s), /look closer at 1/i);
  assert.doesNotMatch(s, /all clear/i);
  const c = G.summary(results, C.testContext({ mode: 'city' }));
  assert.deepStrictEqual(C.checkCityWords(c), []);
  assert.doesNotMatch(c, /all clear/i);
  assert.strictEqual(typeof G.summary([], C.testContext()), 'string');
});

// R4: groupMissions explodes permission lists into one item per app; the game decides and draws per app.
test('per app (R4): the exploded item names only its app, with every key it holds, and decides for that app', async () => {
  const { C, G } = await load();
  const T = await import(pathToFileURL(path.join(R, 'types.js')).href);
  const pf = (code, service, apps, extra = {}) => ({ title: `${service} list`, description: 'x', severity: 'warning', category: 'security',
    code: `security.app_permissions.${code}`, data: { service, apps }, ...extra });
  const doc = { schema_version: 1, platform: 'darwin', modules: [{ name: 'app_permissions', category: 'security', status: 'ok', error: null, supported: true,
    findings: [
      pf('camera_access', 'kTCCServiceCamera', ['com.example.alpha', 'com.example.beta'], { markable: { id: 'k-cam', kind: 'app_permissions' } }),
      pf('microphone_access', 'kTCCServiceMicrophone', ['com.example.alpha']),
      pf('contacts_access', 'kTCCServiceAddressBook', ['com.example.solo'], { markable: { id: 'k-con', kind: 'app_permissions' } }),
    ] }] };
  const items = T.groupMissions(doc, { mode: 'standard', table: T.buildTable([G]) }).filter((m) => m.type === 'keyring').flatMap((m) => m.items);
  const alpha = items.find((i) => i.key === `app|${i.district}|com.example.alpha`);
  const beta = items.find((i) => i.key === `app|${i.district}|com.example.beta`);
  const solo = items.find((i) => i.key === `app|${i.district}|com.example.solo`);
  assert.ok(alpha && beta && solo, items.map((i) => i.key).join(', '));
  assert.deepStrictEqual(alpha.keys.map((k) => k.permission), ['kTCCServiceCamera', 'kTCCServiceMicrophone']);
  for (const mode of ['standard', 'city']) {
    const ctx = C.testContext({ mode });
    const html = G.render(view(alpha, G, ctx), ctx);
    assert.match(html, /com\.example\.alpha/);
    assert.doesNotMatch(html, /com\.example\.beta/, 'the other holder of the camera key is its own item');
    assert.strictEqual((html.match(/class="kr-app"/g) || []).length, 1);
    assert.deepStrictEqual([...html.matchAll(/data-key="([^"]+)"/g)].map((x) => x[1]), ['camera', 'microphone']);
    assert.doesNotMatch(G.render(view(beta, G, ctx), ctx), /data-key="microphone"/);
    if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(html), []);
  }
  const ctx = C.testContext();
  const d = G.decisions(alpha, ctx);
  const back = d.find((x) => x.id === 'hand_back').effect;
  assert.strictEqual(back.pane, 'privacy-camera');
  assert.ok(back.steps.some((x) => /Microphone/.test(x) && /com\.example\.alpha/.test(x)), back.steps.join(' | '));
  assert.strictEqual(d[0].effect.kind, 'keep', 'marking the camera list would mark beta too');
  assert.strictEqual(G.decisions(solo, ctx)[0].effect.kind, 'mark', 'a list of one app is marked through MarkFlow');
  const looks = G.research(alpha, ctx).links.filter((l) => l.kind === 'lookup').map((l) => l.query);
  assert.deepStrictEqual(looks, ['com.example.alpha']);
  assert.deepStrictEqual(C.runContractChecks(G, [alpha, beta, solo]), []);
});
