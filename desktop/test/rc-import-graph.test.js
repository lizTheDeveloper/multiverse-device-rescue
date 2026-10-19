const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const RC = require('../rc-files.json');
const { resolveAppPath, APP_ORIGIN } = require('../app-protocol');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const BASE = path.join(__dirname, '..');
let ENTRIES;
const IMPORT_RE = /(?:^|\n)\s*(?:import|export)\b[^;'"`]*?\bfrom\s*['"]([^'"]+)['"]/g;
const BARE_RE = /(?:^|\n)\s*import\s*['"]([^'"]+)['"]/g;

function walk(entries) {
  const seen = new Set();
  const queue = [...entries];
  while (queue.length) {
    const rel = queue.shift();
    if (seen.has(rel)) continue;
    seen.add(rel);
    const text = fs.readFileSync(path.join(SRC, rel), 'utf8');
    for (const re of [IMPORT_RE, BARE_RE]) {
      for (const m of text.matchAll(re)) queue.push(path.posix.normalize(path.posix.join(path.posix.dirname(rel), m[1])));
    }
  }
  return [...seen].sort();
}

const reachableP = import('../renderer/game/rc-load.js').then((m) => { ENTRIES = m.RC_ENTRY_FILES; return walk(ENTRIES); });
const read = (rel) => fs.readFileSync(path.join(SRC, rel), 'utf8');

test('rc-files.json is exactly the reachable graph plus the stylesheet', async () => {
  const reachable = await reachableP;
  assert.deepStrictEqual([...RC.files].sort(), [...reachable, 'style.css'].sort());
});

test('nothing reachable talks to the network or loads code at runtime', async () => {
  const reachable = await reachableP;
  for (const rel of reachable) {
    const text = read(rel);
    assert.doesNotMatch(text, /\bfetch\s*\(|sendBeacon|XMLHttpRequest|WebSocket|new Image\(/, rel);
    assert.doesNotMatch(text, /\bimport\(/, `${rel} uses dynamic import`);
  }
});

test('Sentry is only touched by utils/errors.js, behind a typeof guard', async () => {
  const reachable = await reachableP;
  for (const rel of reachable) {
    if (rel === 'utils/errors.js') continue;
    assert.doesNotMatch(read(rel), /Sentry/, rel);
  }
  assert.match(read('utils/errors.js'), /typeof Sentry === 'undefined'/);
});

// data/dialogue.js holds the districts' "ALLIED ORGANIZATIONS" links, one of
// them https://signal.org/donate/. controller.js render() strips that section
// from every screen (covered in game-controller.test.js, "a district at 100%").
const PAYMENT_OK = { 'components/hud.js': 'always replaced', 'data/dialogue.js': 'allies stripped at render' };
test('payment links live only in the HUD and the allies list, and neither is shown', async () => {
  const reachable = await reachableP;
  for (const rel of reachable) {
    if (PAYMENT_OK[rel]) continue;
    assert.doesNotMatch(read(rel), /buy\.stripe\.com|patreon\.com|\/donate\b/i, rel);
  }
  assert.match(read('data/dialogue.js'), /\/donate\b/, 'still the known source; if this fails, drop it from PAYMENT_OK');
  assert.strictEqual(RC.overrides['components/hud.js'], 'game/rc-overrides/hud.js');
  const served = resolveAppPath(`${APP_ORIGIN}rc/components/hud.js`, BASE);
  assert.strictEqual(served.file, path.join(BASE, 'renderer', 'game', 'rc-overrides', 'hud.js'));
});

test('the HUD stand-in exports everything the real HUD does', async () => {
  const real = await import(pathToFileURL(path.join(SRC, 'components', 'hud.js')).href);
  const stand = await import(pathToFileURL(path.join(BASE, 'renderer', 'game', 'rc-overrides', 'hud.js')).href);
  assert.deepStrictEqual(Object.keys(stand).sort(), Object.keys(real).sort());
  assert.strictEqual(stand.renderHud({}), '');
});

test('the never-load list stays unserved', () => {
  for (const rel of ['utils/analytics.js', 'utils/collective.js', 'utils/restore-send.js', 'utils/notifications.js', 'app.js', 'sw.js', 'index.html']) {
    assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/${rel}`, BASE), null, rel);
    assert.ok(!RC.files.includes(rel), rel);
  }
});
