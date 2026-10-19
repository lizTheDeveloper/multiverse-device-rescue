'use strict';
// Little missions: research (missions/research.js) — link intents to allowlisted URLs.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { isAllowedSettingUrl } = require('../setting-urls.js');

const url = (rel) => pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', rel)).href;
const load = () => Promise.all([import(url('research.js')), import(url('contract.js'))]);

test('every settings pane opens on macOS and Windows (or says why not), through the setting allowlist', async () => {
  const [R, C] = await load();
  for (const pane of C.SETTINGS_PANES) {
    for (const platform of ['darwin', 'win32']) {
      const u = R.paneUrl(pane, platform);
      if (u === null) { assert.ok(R.NO_PANE[pane] && R.NO_PANE[pane][platform], `${pane} on ${platform} has no URL and no reason`); continue; }
      assert.ok(isAllowedSettingUrl(u), `${pane} ${platform}: ${u}`);
      assert.ok(platform === 'darwin' ? u.startsWith('x-apple.systempreferences:') : u.startsWith('ms-settings:'), u);
    }
  }
  assert.strictEqual(R.paneUrl('login-items', 'darwin'), 'x-apple.systempreferences:com.apple.LoginItems-Settings.extension');
  assert.strictEqual(R.paneUrl('login-items', 'win32'), 'ms-settings:startupapps');
  assert.strictEqual(R.paneUrl('privacy-screen-recording', 'darwin'), 'x-apple.systempreferences:com.apple.preference.security?Privacy_ScreenCapture');
  assert.strictEqual(R.paneUrl('nope', 'darwin'), null);
  assert.strictEqual(R.paneUrl('login-items', 'linux'), null, 'Linux has no panes');
});

test('look-ups come from fixed templates; values are encoded and cleaned', async () => {
  const [R] = await load();
  const u = R.lookupUrl('web', 'com.example.helper & <b>');
  assert.ok(u.startsWith('https://duckduckgo.com/?q='));
  assert.ok(!/[<>& ]/.test(u.slice('https://duckduckgo.com/?q='.length)), u);
  assert.match(decodeURIComponent(u), /"com\.example\.helper & <b>"/);
  const hostile = R.lookupUrl('web', 'a\nb‮c\u0000d' + 'x'.repeat(500));
  assert.ok(!/%0A|%E2%80%AE|%00/i.test(hostile), 'control and bidi characters are dropped');
  assert.ok(decodeURIComponent(hostile).length < 200, 'capped');
  assert.ok(R.lookupUrl('apple-support', 'Login Items').includes(encodeURIComponent('site:support.apple.com')));
  assert.ok(R.lookupUrl('microsoft-support', 'Startup apps').includes(encodeURIComponent('site:support.microsoft.com')));
  assert.strictEqual(R.lookupUrl('chrome-web-store', 'abcdefghijklmnopabcdefghijklmnop'),
    'https://chromewebstore.google.com/detail/abcdefghijklmnopabcdefghijklmnop');
  assert.ok(R.lookupUrl('chrome-web-store', 'javascript:alert(1)').startsWith('https://duckduckgo.com/'), 'not an id: a web search');
  assert.strictEqual(R.lookupUrl('evil', 'x'), null);
  assert.strictEqual(R.lookupUrl('web', '   '), null, 'nothing to search for');
});

test('city mode: look-ups are text to search on another device, never links; panes still open', async () => {
  const [R] = await load();
  const links = R.resolveLinks([{ kind: 'lookup', source: 'web', query: 'Helper One' }, { kind: 'settings', pane: 'login-items' }],
    { mode: 'city', platform: 'darwin' });
  assert.strictEqual(links[0].url, null);
  assert.match(links[0].text, /Helper One/);
  assert.match(links[0].text, /another device/);
  assert.ok(links[1].url.startsWith('x-apple.systempreferences:'));
  const std = R.resolveLinks([{ kind: 'lookup', source: 'web', query: 'Helper One' }], { mode: 'standard', platform: 'darwin' });
  assert.ok(std[0].url.startsWith('https://'));
});

test('a game’s raw URL or unknown intent is dropped, never opened', async () => {
  const [R] = await load();
  const links = R.resolveLinks([
    { kind: 'lookup', source: 'web', query: 'x', href: 'https://evil.example/' },
    { kind: 'settings', pane: 'login-items', url: 'file:///etc/passwd' },
    { kind: 'nope' },
    { kind: 'settings', pane: 'made-up' },
    { kind: 'lesson', concept: 'where-it-lives' },
  ], { mode: 'standard', platform: 'darwin' });
  assert.ok(links.every((l) => !l.url || !/evil|file:/.test(l.url)));
  assert.deepStrictEqual(links.map((l) => l.kind), ['lesson'], 'an intent that carries a URL is dropped whole');
  assert.strictEqual(links[0].concept, 'where-it-lives');
});

test('what it is: the verified program’s own description, else Unknown maker', async () => {
  const [R] = await load();
  assert.strictEqual(R.whatOf({ makers_verified: true, made_by: [{ verified: true, name: 'Google LLC', what: 'Google Chrome: a web browser.' }] }), 'Google Chrome: a web browser.');
  // The program's own entry, matched by subject.
  const two = { data: { apps: ['/Applications/A.app', '/Applications/B.app'] }, made_by: [
    { subject: '/Applications/A.app', verified: true, name: 'A Co', what: 'A: an editor.' },
    { subject: '/Applications/B.app', verified: false, name: 'B Co', what: '' }] };
  assert.strictEqual(R.whatOf(two), 'Unknown maker', 'a finding naming two programs: not one program’s description');
  assert.strictEqual(R.whatOf(two, '/Applications/A.app'), 'A: an editor.');
  assert.strictEqual(R.whatOf(two, '/Applications/B.app'), 'Unknown maker');
  // One entry that isn't the program's own, and the engine didn't say every maker verified.
  assert.strictEqual(R.whatOf({ data: { path: '/opt/x' }, made_by: [{ subject: '/opt/y', verified: true, name: 'Y', what: 'Y: other.' }] }), 'Unknown maker');
  assert.strictEqual(R.whatOf({ made_by: [{ verified: false, name: 'Google LLC', what: 'Google Chrome: a web browser.' }] }), 'Unknown maker');
  assert.strictEqual(R.whatOf({}), 'Unknown maker');
});

test('assemble: rows, what, resolved links, and "This check didn’t finish" for an unfinished check', async () => {
  const [R, C] = await load();
  const game = { research: () => ({ rows: [{ label: 'Path', value: '/x' }], what: '', links: [{ kind: 'settings', pane: 'login-items' }] }) };
  const item = C.makeItem({ module: 'launch_agent_audit', title: 't' });
  const doc = { modules: [{ name: 'launch_agent_audit', status: 'ok', supported: true, complete: false, findings: [] }] };
  const r = R.assemble(game, item, C.testContext(), { unfinished: R.unfinishedModules(doc) });
  assert.strictEqual(r.rows.length, 1);
  assert.strictEqual(r.what, 'Unknown maker');
  assert.ok(r.links[0].url);
  assert.strictEqual(r.unfinished, R.UNFINISHED_LINE);
  const r2 = R.assemble(game, item, C.testContext(), { unfinished: new Set() });
  assert.strictEqual(r2.unfinished, '');
  const broken = R.assemble({ research: () => { throw new Error('x'); } }, item, C.testContext(), {});
  assert.deepStrictEqual(broken.links, [], 'a game that throws gives no links, not a crash');
});

test('R5: a settings intent’s permission picks the exact Windows privacy page; new panes resolve', async () => {
  const [R] = await load();
  const win = (permission) => R.resolveLink({ kind: 'settings', pane: 'windows-privacy', permission }, { platform: 'win32' }).url;
  assert.strictEqual(win('camera'), 'ms-settings:privacy-webcam');
  assert.strictEqual(win('kTCCServiceMicrophone'), 'ms-settings:privacy-microphone');
  assert.strictEqual(win('location'), 'ms-settings:privacy-location');
  assert.strictEqual(win('nonsense'), 'ms-settings:privacy');
  assert.strictEqual(R.resolveLink({ kind: 'settings', pane: 'privacy-camera', permission: 'camera' }, { platform: 'darwin' }).url,
    'x-apple.systempreferences:com.apple.preference.security?Privacy_Camera', 'macOS keeps its own pane');
  for (const p of ['privacy-contacts', 'screen-time', 'windows-bitlocker', 'windows-signin', 'windows-backup', 'windows-findmydevice']) {
    assert.ok(R.paneUrl(p, 'win32').startsWith('ms-settings:'), p);
  }
});

test('R6: a settings intent with warning: true keeps it through resolution', async () => {
  const [R] = await load();
  assert.strictEqual(R.resolveLink({ kind: 'settings', pane: 'privacy-camera', warning: true }, { platform: 'darwin' }).warning, true);
  assert.ok(!('warning' in R.resolveLink({ kind: 'settings', pane: 'privacy-camera' }, { platform: 'darwin' })));
});

test('P2-12: city settings buttons name their pane in game words, one name per pane', async () => {
  const [R, C] = await load();
  const labels = C.SETTINGS_PANES.map((pane) => R.resolveLink({ kind: 'settings', pane }, { mode: 'city', platform: 'darwin' }).label.city);
  assert.strictEqual(new Set(labels).size, labels.length, `two panes read alike: ${labels.join(' / ')}`);
  for (const l of labels) {
    assert.match(l, /^Open the [a-z -]+ settings$/, l);
    assert.notStrictEqual(l, 'Open the settings');
    assert.doesNotMatch(l, /monitor|recording|spy|stalk|watch|track/i, l);
    assert.doesNotMatch(l, C.CITY_FORBIDDEN, l);
  }
  // Keyring's two keys on one item: the buttons can be told apart.
  const two = R.resolveLinks([{ kind: 'settings', pane: 'privacy-accessibility' }, { kind: 'settings', pane: 'privacy-input-monitoring' }],
    { mode: 'city', platform: 'darwin' });
  assert.deepStrictEqual(two.map((l) => l.label.city), ['Open the control key settings', 'Open the keyboard key settings']);
  assert.strictEqual(two[0].label.standard, 'Open Accessibility settings', 'standard words unchanged');
});

test('P2-12: a city look-up quotes the words once', async () => {
  const [R] = await load();
  const text = (query) => R.resolveLink({ kind: 'lookup', source: 'web', query }, { mode: 'city' }).text;
  assert.strictEqual(text('Example Notes'), 'Search for “Example Notes” on another device.');
  assert.strictEqual(text('"Example Worm"'), 'Search for “Example Worm” on another device.');
  assert.strictEqual(text('"babylon" Firefox add-on'), 'Search for “babylon” Firefox add-on on another device.');
  assert.strictEqual(text('part"1'), 'Search for “part1” on another device.', 'a stray quote is dropped');
  for (const q of ['Example Notes', '"Example Worm"', '"babylon" Firefox add-on', 'a"b"c"d']) {
    assert.doesNotMatch(text(q), /“"|"”|""|“\s*“/, q);
    assert.ok(!text(q).includes('"'), `no straight quote left: ${text(q)}`);
  }
});

test('P3: an item never shows the same lesson button twice; each lesson button names its lesson', async () => {
  const [R] = await load();
  for (const mode of ['standard', 'city']) {
    const links = R.resolveLinks([{ kind: 'lesson', concept: 'who-made-it' }, { kind: 'lesson', concept: 'couldnt-check' },
      { kind: 'lesson', concept: 'who-made-it' }, { kind: 'settings', pane: 'login-items' }, { kind: 'settings', pane: 'login-items' }],
    { mode, platform: 'darwin' });
    assert.deepStrictEqual(links.map((l) => l.kind), ['lesson', 'lesson', 'settings'], mode);
    const said = links.map((l) => l.label[mode]);
    assert.strictEqual(new Set(said).size, said.length, said.join(' / '));
  }
  const std = R.resolveLinks([{ kind: 'lesson', concept: 'who-made-it' }, { kind: 'lesson', concept: 'couldnt-check' }], { mode: 'standard' });
  assert.deepStrictEqual(std.map((l) => l.label.standard), ['Learn: who made it', 'Learn: when a check can’t finish']);
  assert.deepStrictEqual(std.map((l) => l.label.city), ['Training: who made it', 'Training: when a check can’t finish']);
  // An unknown lesson keeps the plain words, and only one such button shows.
  const odd = R.resolveLinks([{ kind: 'lesson', concept: 'new-one' }, { kind: 'lesson', concept: 'other-new' }], { mode: 'standard' });
  assert.deepStrictEqual(odd.map((l) => l.label.standard), ['Learn how to read this']);
  // The same search twice is one line in the city.
  const city = R.resolveLinks([{ kind: 'lookup', source: 'web', query: 'X' }, { kind: 'lookup', source: 'maker-site', query: 'X' }], { mode: 'city' });
  assert.strictEqual(city.length, 1, 'the city shows only the words, and they are the same');
  const std2 = R.resolveLinks([{ kind: 'lookup', source: 'web', query: 'X' }, { kind: 'lookup', source: 'maker-site', query: 'X' }], { mode: 'standard' });
  assert.strictEqual(std2.length, 2, 'two different buttons stay');
  const same = R.resolveLinks([{ kind: 'lookup', source: 'web', query: 'X' }, { kind: 'lookup', source: 'web', query: 'X' }], { mode: 'city' });
  assert.strictEqual(same.length, 1);
});

test('P3: every lesson a game links to has its own button name', async () => {
  const fs = require('fs');
  const dir = path.join(__dirname, '..', 'renderer', 'missions', 'games');
  const concepts = new Set();
  for (const f of fs.readdirSync(dir)) for (const m of fs.readFileSync(path.join(dir, f), 'utf8').matchAll(/kind: 'lesson', concept: '([a-z-]+)'/g)) concepts.add(m[1]);
  assert.ok(concepts.size > 3, [...concepts].join());
  const [R] = await load();
  for (const concept of concepts) {
    assert.notStrictEqual(R.resolveLink({ kind: 'lesson', concept }).label.standard, 'Learn how to read this', concept);
  }
});
