const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { resolveAppPath, serveApp, APP_ORIGIN } = require('../app-protocol');

const BASE = path.join('/tmp', 'desk');
const R = (p) => path.join(BASE, 'renderer', p);
const V = (p) => path.join(BASE, 'vendor', 'reclaim-city', 'src', p);

test('the page and its own files come from renderer/', () => {
  assert.deepStrictEqual(resolveAppPath(`${APP_ORIGIN}index.html`, BASE), { file: R('index.html'), mime: 'text/html; charset=utf-8' });
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}`, BASE).file, R('index.html'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}app.js`, BASE).mime, 'text/javascript; charset=utf-8');
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}game/views/map.js`, BASE).file, R('game/views/map.js'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}game/fonts/inter-latin-400-normal.woff2`, BASE).mime, 'font/woff2');
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}permissions-content.json`, BASE).mime, 'application/json');
});

test('assets/ is the game art, png only', () => {
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}assets/characters/scout/happy.png`, BASE).file, V('assets/characters/scout/happy.png'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}assets/x.js`, BASE), null);
});

test('rc/ serves only the allowlisted game sources', () => {
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/components/scout.js`, BASE).file, V('components/scout.js'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/style.css`, BASE).mime, 'text/css; charset=utf-8');
  for (const p of ['rc/app.js', 'rc/index.html', 'rc/sw.js', 'rc/utils/analytics.js', 'rc/utils/errors.js']) {
    assert.strictEqual(resolveAppPath(`${APP_ORIGIN}${p}`, BASE), null, p);
  }
});

test('odd hosts, schemes, encodings and file types are refused', () => {
  for (const url of [
    `${APP_ORIGIN}assets/..%2f..%2fapp.js`, `${APP_ORIGIN}rc/..%2f..%2fmain.js`, `${APP_ORIGIN}game\\..\\..\\main.js`,
    `${APP_ORIGIN}a%00.js`, 'app://evil/index.html', 'file:///etc/passwd', 'https://rescue/index.html',
    `${APP_ORIGIN}engine/rescue`, `${APP_ORIGIN}index.html.exe`, 'not a url',
  ]) {
    assert.strictEqual(resolveAppPath(url, BASE), null, url);
  }
});

test('dot segments never climb out of renderer/ (the URL parser collapses them first)', () => {
  // new URL('app://rescue/%2e%2e/main.js').pathname is '/main.js': it can only
  // ever name renderer/main.js, which does not exist, never desktop/main.js.
  for (const url of [`${APP_ORIGIN}../main.js`, `${APP_ORIGIN}%2e%2e/main.js`, `${APP_ORIGIN}game/%2e%2e/%2e%2e/main.js`,
    `${APP_ORIGIN}assets/../../../main.js`, `${APP_ORIGIN}rc/../../main.js`]) {
    const hit = resolveAppPath(url, BASE);
    assert.ok(hit === null || hit.file.startsWith(path.join(BASE, 'renderer') + path.sep), `${url} -> ${hit && hit.file}`);
  }
});

test('serveApp answers 404 for refused paths and sets the type for served ones', async () => {
  const miss = await serveApp('app://evil/x', BASE, async () => Buffer.from(''));
  assert.strictEqual(miss.status, 404);
  const hit = await serveApp(`${APP_ORIGIN}app.js`, BASE, async (f) => { assert.strictEqual(f, R('app.js')); return Buffer.from('ok'); });
  assert.strictEqual(hit.status, 200);
  assert.strictEqual(hit.headers.get('content-type'), 'text/javascript; charset=utf-8');
  assert.strictEqual(await hit.text(), 'ok');
});

test('serveApp answers 404 when the file is missing', async () => {
  const res = await serveApp(`${APP_ORIGIN}nope.js`, BASE, async () => { const e = new Error('x'); e.code = 'ENOENT'; throw e; });
  assert.strictEqual(res.status, 404);
});
