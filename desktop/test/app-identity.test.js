const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const pkg = require('../package.json');
const { userDataDir, DATA_DIR_NAME } = require('../user-data.js');

const DESKTOP = path.join(__dirname, '..');
const REPO = path.join(DESKTOP, '..');
const read = (rel) => fs.readFileSync(path.join(REPO, rel), 'utf8');

test('the app is called Reclaim City everywhere the installer and the OS show it', () => {
  assert.strictEqual(pkg.productName, 'Reclaim City');
  assert.strictEqual(pkg.build.productName, 'Reclaim City');
  assert.strictEqual(pkg.build.dmg.title, 'Reclaim City');
  assert.strictEqual(pkg.build.nsis.shortcutName, 'Reclaim City');
  assert.strictEqual(pkg.build.mac.artifactName, 'ReclaimCity-mac-${arch}.${ext}');
  assert.strictEqual(pkg.build.win.artifactName, 'ReclaimCity-windows-${arch}.${ext}');
  // Any case (DEVICE RESCUE counts); the appId is the one slug kept on purpose.
  assert.doesNotMatch(JSON.stringify(pkg).replace('"school.themultiverse.devicerescue"', ''), /Device ?Rescue/i);
});

test('the installer id does not change, so updates and OS permissions carry over', () => {
  assert.strictEqual(pkg.build.appId, 'school.themultiverse.devicerescue');
});

test('saved data stays where every earlier version kept it', () => {
  assert.strictEqual(DATA_DIR_NAME, 'Device Rescue');
  assert.strictEqual(userDataDir('/Users/a/Library/Application Support'),
    path.join('/Users/a/Library/Application Support', 'Device Rescue'));
  const main = read('desktop/main.js');
  const pin = main.indexOf("app.setPath('userData', userDataDir(app.getPath('appData')));");
  assert.ok(pin > 0, 'main.js pins userData');
  assert.ok(pin < main.indexOf('app.whenReady('), 'before the app is ready');
  assert.ok(pin < main.indexOf('new BrowserWindow('), 'before any window');
  assert.ok(pkg.build.files.includes('user-data.js'), 'packaged');
});

test('the window, About and page titles are the new name, with no shield', () => {
  const main = read('desktop/main.js');
  assert.match(main, /title: 'Reclaim City'/);
  assert.match(main, /applicationName: 'Reclaim City'/);
  const html = read('desktop/renderer/index.html');
  assert.match(html, /<title>Reclaim City<\/title>/);
  assert.match(html, /<span class="brand-name">Reclaim City<\/span>/);
  assert.match(html, /<span class="route__eyebrow">Plain view<\/span>/);
  assert.doesNotMatch(html, /Device ?Rescue/i);
  assert.doesNotMatch(html, /&#128737;/, 'no shield in the header');
});

test('the release workflow uploads, checksums and names the new artifacts', () => {
  const wf = read('.github/workflows/release.yml');
  assert.doesNotMatch(wf.replace('used to be called Device Rescue', ''), /Device ?Rescue/i);
  assert.ok(wf.includes('desktop/dist/ReclaimCity-*.dmg'));
  assert.ok(wf.includes('desktop/dist/ReclaimCity-*.exe'));
  assert.ok(wf.includes('sha256sum ReclaimCity-* > SHA256SUMS.txt'));
  assert.ok(wf.includes('--title "Reclaim City $TAG"'));
  for (const a of ['ReclaimCity-mac-arm64.dmg', 'ReclaimCity-mac-x64.dmg', 'ReclaimCity-windows-x64.exe']) assert.ok(wf.includes(a), a);
});

test('an icon, once the owner adds one, is a 1024×1024 PNG where electron-builder looks', () => {
  const icon = path.join(DESKTOP, 'build', 'icon.png');
  if (!fs.existsSync(icon)) return; // until then electron-builder ships its default icon, not a shield
  const buf = fs.readFileSync(icon);
  assert.strictEqual(buf.toString('ascii', 1, 4), 'PNG');
  assert.strictEqual(buf.readUInt32BE(16), 1024);
  assert.strictEqual(buf.readUInt32BE(20), 1024);
});
