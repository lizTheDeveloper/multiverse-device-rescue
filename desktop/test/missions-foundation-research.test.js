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
  assert.strictEqual(R.whatOf({ made_by: [{ verified: true, name: 'Google LLC', what: 'Google Chrome: a web browser.' }] }), 'Google Chrome: a web browser.');
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
