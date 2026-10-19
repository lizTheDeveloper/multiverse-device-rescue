'use strict';
// The 'open-lookup' IPC channel: main opens only the URLs research.js's
// look-up templates produce; standard mode opens look-ups in the browser, city
// mode never does (it shows them as words to search on another device).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { isAllowedLookupUrl } = require('../lookup-url.js');

const research = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'research.js')).href);
const contract = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'contract.js')).href);

test('every URL research.js builds is allowed, hostile names included', async () => {
  const R = await research();
  const C = await contract();
  const names = ['com.example.helper', 'Amical', 'ai.hermes.gateway-deflock', 'a b  c', 'Ünïcødé 名前', 'x'.repeat(300),
    'ab"cd"', '50% off & more?', "it's (here) ~*!", 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa', ...C.HOSTILE];
  let n = 0;
  for (const source of C.LOOKUP_SOURCES) {
    for (const q of names) {
      const url = R.lookupUrl(source, q);
      if (!url) continue;
      n += 1;
      assert.ok(isAllowedLookupUrl(url), `${source} ${JSON.stringify(q)} -> ${url}`);
    }
  }
  assert.ok(n > 40);
  assert.ok(isAllowedLookupUrl(R.lookupUrl('chrome-web-store', 'aaaabbbbccccddddeeeeffffgggghhhh')));
  assert.match(R.lookupUrl('chrome-web-store', 'aaaabbbbccccddddeeeeffffgggghhhh'), /^https:\/\/chromewebstore\.google\.com\/detail\//);
});

test('anything else is refused: other hosts, schemes, parameters, fragments, unquoted or unclean names', () => {
  const q = encodeURIComponent('"Amical"');
  const ok = `https://duckduckgo.com/?q=${q}`;
  assert.ok(isAllowedLookupUrl(ok));
  const hostile = [
    null, undefined, 42, {}, ['https://duckduckgo.com/?q=%22a%22'], '',
    `http://duckduckgo.com/?q=${q}`,
    `https://duckduckgo.com.evil.example/?q=${q}`,
    `https://evil.example/?q=${q}`,
    `https://duckduckgo.com@evil.example/?q=${q}`,
    `https://user:pw@duckduckgo.com/?q=${q}`,
    `https://duckduckgo.com:8443/?q=${q}`,
    `https://DUCKDUCKGO.com/?q=${q}`,
    `https://duckduckgo.com/html/?q=${q}`,
    `https://duckduckgo.com/?q=${q}&ia=web`,
    `https://duckduckgo.com/?q=${q}#x`,
    `https://duckduckgo.com/?ia=web&q=${q}`,
    `https://duckduckgo.com/?q=${q}%26kp%3D-2`,
    'https://duckduckgo.com/?q=Amical',
    `https://duckduckgo.com/?q=${encodeURIComponent('site:evil.example "Amical"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent('"a" "b"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent('"a\nb"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent('"‮gnp.exe"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent('"a​b"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent('" a"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent('"a  b"')}`,
    `https://duckduckgo.com/?q=${encodeURIComponent(`"${'x'.repeat(121)}"`)}`,
    'https://duckduckgo.com/?q="Amical"',
    'https://duckduckgo.com/?q=%22Amical%22%',
    'https://duckduckgo.com/?q=%E0%A4%A',
    'https://duckduckgo.com/?q=%22Ami%63al%22',
    'javascript:alert(1)',
    'file:///etc/passwd',
    'x-apple.systempreferences:com.apple.preference.security',
    'https://chromewebstore.google.com/detail/aaaabbbbccccddddeeeeffffgggghhh',
    'https://chromewebstore.google.com/detail/aaaabbbbccccddddeeeeffffgggghhhhz',
    'https://chromewebstore.google.com/detail/zzzzbbbbccccddddeeeeffffgggghhhh',
    'https://chromewebstore.google.com/detail/aaaabbbbccccddddeeeeffffgggghhhh/reviews',
    'https://chromewebstore.google.com/detail/aaaabbbbccccddddeeeeffffgggghhhh?x=1',
    'https://chromewebstore.google.com/detail/../../evil',
    'https://chromewebstore.google.com.evil.example/detail/aaaabbbbccccddddeeeeffffgggghhhh',
    ` ${ok}`, `${ok} `, `${ok}\n`,
  ];
  for (const u of hostile) assert.strictEqual(isAllowedLookupUrl(u), false, JSON.stringify(u));
});

test('main and preload wire open-lookup through the allowlist, and the file is packaged', () => {
  const read = (f) => fs.readFileSync(path.join(__dirname, '..', f), 'utf8');
  assert.match(read('main.js'), /ipcMain\.handle\('open-lookup', \(_e, url\) => \{\s*if \(!isAllowedLookupUrl\(url\)\) return false;\s*shell\.openExternal\(url\);/);
  assert.match(read('preload.js'), /openLookup: \(url\) => ipcRenderer\.invoke\('open-lookup', url\)/);
  assert.ok(JSON.parse(read('package.json')).build.files.includes('lookup-url.js'));
});

// The desk: a look-up button in standard mode calls rescue.openLookup with research.js's URL; city mode has no button and never calls it.
const tick = () => new Promise((r) => setTimeout(r, 0));
async function desk(mode) {
  const { createController } = await import('../renderer/game/controller.js');
  const listeners = [];
  const opened = [];
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); }, querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = { document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach() {}, resultHtml: () => '', fixControlsHtml: () => '' }, MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {}, mode: () => mode, citySeed: () => 1 },
    rescue: { openLookup: async (u) => { opened.push(u); return isAllowedLookupUrl(u); }, openSetting: async () => true } };
  const s = {}; const storage = { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; } };
  const ctl = createController({ win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}), loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick(); await tick();
  const click = (attrs) => { const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) }; listeners.forEach((fn) => fn({ target: { closest: () => el } })); };
  ctl.show({ schema_version: 1, platform: 'darwin', modules: [{ name: 'battery_health', category: 'integrity', status: 'ok', error: null, supported: true,
    findings: [{ title: 'Worn part <b>', description: 'x', severity: 'warning', category: 'integrity', data: { name: 'part"1' } }] }] }, { id: 'unsure' });
  await tick(); await tick();
  click({ 'data-act': 'investigate-next' });
  click({ 'data-act': 'mx-know' });
  return { html: () => frame.innerHTML, click, opened };
}

test('standard mode opens a look-up in the browser through rescue.openLookup; city mode only shows the words', async () => {
  const std = await desk('standard');
  const btn = /data-act="(mx-link:\d+)">Search the web/.exec(std.html());
  assert.ok(btn, 'a look-up button');
  std.click({ 'data-act': btn[1] });
  await tick();
  assert.strictEqual(std.opened.length, 1);
  assert.ok(isAllowedLookupUrl(std.opened[0]), std.opened[0]);
  assert.match(std.html(), /Opened in your browser\./);

  const city = await desk('city');
  assert.doesNotMatch(city.html(), /data-act="mx-link:\d+">Search/);
  assert.match(city.html(), /class="mx-link-text">Search for “[^”]+” on another device\./);
  for (let i = 0; i < 4; i += 1) city.click({ 'data-act': `mx-link:${i}` });
  await tick();
  assert.deepStrictEqual(city.opened, [], 'city mode never opens a look-up');
});

test('DuckDuckGo’s search tricks never get through: no "!" bang, no "\\" first-result jump', async () => {
  const R = await research();
  for (const q of ['!g evil.example', 'Helper !ducky', '\\evil site', 'a\\b', '!!', '! leading']) {
    const url = R.lookupUrl('web', q);
    if (!url) continue;
    const decoded = decodeURIComponent(url.split('?q=')[1]);
    assert.doesNotMatch(decoded, /[!\\]/, `${JSON.stringify(q)} -> ${decoded}`);
    assert.ok(isAllowedLookupUrl(url));
  }
  assert.strictEqual(R.lookupUrl('web', '!!'), null, 'nothing left to search');
  assert.strictEqual(R.cleanQuery('! Helper\\App'), 'Helper App');
  // Main rejects them even when a renderer builds the URL itself.
  for (const q of ['"!g evil"', '"\\evil"', 'site:support.apple.com "!bang"', '"a!b"']) {
    assert.strictEqual(isAllowedLookupUrl(`https://duckduckgo.com/?q=${encodeURIComponent(q)}`), false, q);
  }
});
