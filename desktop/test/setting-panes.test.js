const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const SettingPanes = require('../renderer/setting-panes');
const { isAllowedSettingUrl } = require('../setting-urls');

const ROOT = path.join(__dirname, '..', '..');
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
const importModule = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME, spec)).href);
const loadLessons = async () => (await import(pathToFileURL(path.join(GAME, 'training.js')).href)).loadLessons(importModule);

function moduleSource(name) {
  const mods = path.join(ROOT, 'modules');
  const cat = fs.readdirSync(mods).find((c) => fs.existsSync(path.join(mods, c, name, '__init__.py')));
  return cat ? fs.readFileSync(path.join(mods, cat, name, '__init__.py'), 'utf8') : null;
}

const warn = (code, module) => ({ title: 't', severity: 'warning', code, module, data: {} });

test('every Mac pane URL passes the open-setting allowlist', () => {
  for (const [key, p] of Object.entries(SettingPanes.MAC_PANES)) {
    assert.ok(p.url.startsWith('x-apple.systempreferences:'), key);
    assert.strictEqual(isAllowedSettingUrl(p.url), true, `${key}: ${p.url}`);
  }
});

test('every lesson `setting` names a pane in the module', async () => {
  const lessons = await loadLessons();
  let seen = 0;
  for (const l of lessons) {
    for (const q of l.questions) {
      if (q.setting == null) continue;
      seen += 1;
      assert.ok(SettingPanes.pane(q.setting), `${l.id}: unknown setting "${q.setting}"`);
    }
  }
  assert.ok(seen > 0, 'at least one lesson question links a setting');
});

test('every mapped finding code is one its module really emits, for a pane that exists', () => {
  for (const [code, key] of Object.entries(SettingPanes.CODE_PANES)) {
    const [, module] = code.split('.');
    const src = moduleSource(module);
    assert.ok(src, `no module ${module}`);
    assert.ok(src.includes(`"${code}"`), `${module} never emits ${code}`);
    assert.ok(SettingPanes.pane(key), `${code}: unknown pane ${key}`);
  }
  for (const module of Object.keys(SettingPanes.MODULE_PANES)) assert.ok(moduleSource(module), `no module ${module}`);
});

test('findings map to the pane their own guidance names', () => {
  const k = SettingPanes.paneKeyForFinding;
  assert.strictEqual(k(warn('security.automatic_updates.critical_update', 'automatic_updates')), 'softwareUpdate');
  assert.strictEqual(k(warn('security.encryption_check.filevault_disabled', 'encryption_check')), 'fileVault');
  assert.strictEqual(k(warn('security.screen_lock_check.screen_lock_delay', 'screen_lock_check')), 'lockScreen');
  assert.strictEqual(k(warn('security.firewall_audit.global_state', 'firewall_audit')), 'firewall');
  assert.strictEqual(k(warn('security.sharing_services.remote_login', 'sharing_services')), 'sharing');
  assert.strictEqual(k(warn(null, 'login_items')), 'loginItems');
  assert.strictEqual(k({ ...warn(null, 'update_checker'), data: { check: 'os_updates' } }), 'softwareUpdate');
  assert.strictEqual(k({ ...warn(null, 'update_checker'), data: { check: 'brew_outdated' } }), null, 'Homebrew is not a System Settings page');
  assert.strictEqual(k(warn('security.sharing_preferences_audit.airdrop_everyone', 'sharing_preferences_audit')), null);
  assert.strictEqual(k(warn('security.unrelated.thing', 'unrelated')), null);
});

test('an info card gets no button, even with a mapped code ("all fine" findings share codes)', () => {
  const f = { ...warn('security.screen_lock_check.screen_lock_required', 'screen_lock_check'), severity: 'info' };
  assert.strictEqual(SettingPanes.paneKeyForFinding(f), null);
  assert.strictEqual(SettingPanes.findingButtonHtml(f, 'darwin'), '');
});

test('the finding-card button shows only on darwin', () => {
  const f = warn('security.firewall_audit.global_state', 'firewall_audit');
  const html = SettingPanes.findingButtonHtml(f, 'darwin');
  assert.match(html, /data-setting-url="x-apple\.systempreferences:com\.apple\.Network-Settings\.extension\?Firewall"/);
  assert.match(html, /Open in System Settings/);
  for (const p of ['win32', 'linux', null, undefined]) assert.strictEqual(SettingPanes.findingButtonHtml(f, p), '', String(p));
});

test('button wording says it opens a page, not that it fixes anything', () => {
  for (const key of Object.keys(SettingPanes.MAC_PANES)) {
    const hint = SettingPanes.hintFor(key);
    assert.match(hint, /^Opens the .+\. You make the change there\.$/, key);
    assert.doesNotMatch(hint, /\bfix/i, key);
  }
  assert.strictEqual(SettingPanes.hintFor('nope'), '');
  assert.strictEqual(SettingPanes.urlFor('toString'), null, 'only own keys');
});

test('the lesson WHAT TO KNOW button appears only on darwin', async () => {
  const { renderLesson } = await import(pathToFileURL(path.join(GAME, 'views', 'lesson.js')).href);
  const lessons = await loadLessons();
  const l = lessons.find((x) => x.id === 'locked-door');
  const draw = (platform, qIndex = 0) => renderLesson({ lesson: l, qIndex, picked: null, scan: { running: false }, scout: () => '',
    pendingCity: false, settingFor: (key) => SettingPanes.lessonSetting(key, platform) });
  const mac = draw('darwin');
  assert.match(mac, /data-act="open-setting:softwareUpdate"/);
  assert.match(mac, /OPEN IN SYSTEM SETTINGS/);
  assert.match(mac, /Opens the Software Update page\. You make the change there\./);
  assert.match(draw('darwin', 2), /data-act="open-setting:fileVault"/);
  for (const p of ['win32', 'linux', null]) assert.doesNotMatch(draw(p), /open-setting/, String(p));
  // A question without a `setting` draws no button, even on a Mac.
  const plain = lessons.find((x) => x.questions.every((q) => !q.setting) && x.type !== 'phishing');
  const html = renderLesson({ lesson: plain, qIndex: 0, picked: null, scan: { running: false }, scout: () => '', pendingCity: false,
    settingFor: (key) => SettingPanes.lessonSetting(key, 'darwin') });
  assert.doesNotMatch(html, /open-setting/);
});

test('preload exposes a read-only platform for the pre-scan lessons', () => {
  const src = fs.readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  assert.match(src, /platform: process\.platform,/);
});

test('index.html loads setting-panes.js before app.js', () => {
  const html = fs.readFileSync(path.join(__dirname, '..', 'renderer', 'index.html'), 'utf8');
  const a = html.indexOf('src="setting-panes.js"');
  assert.ok(a > 0 && a < html.indexOf('src="app.js"'));
});
