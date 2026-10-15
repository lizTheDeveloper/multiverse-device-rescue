const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');
const { duringScanTips } = require('../renderer/app.js');

const content = JSON.parse(
  fs.readFileSync(path.join(__dirname, '..', 'renderer', 'permissions-content.json'), 'utf8')
);

test('install-time tips are left out once the app is open', () => {
  const titles = duringScanTips(content, 'macos').map((s) => s.title).join('\n');
  assert.ok(!/Open Anyway|can't be opened/.test(titles));
  assert.match(titles, /Full Disk Access/);
  const win = duringScanTips(content, 'windows').map((s) => s.title).join('\n');
  assert.ok(!/SmartScreen/.test(win));
  assert.match(win, /User Account Control/);
});

test('nothing to show for Linux or a missing file', () => {
  assert.deepStrictEqual(duringScanTips(content, 'linux'), []);
  assert.deepStrictEqual(duringScanTips(null, 'macos'), []);
});

test('the desktop copy of the tips matches the shared one', () => {
  const shared = fs.readFileSync(
    path.join(__dirname, '..', '..', 'shared', 'permissions-content.json'), 'utf8');
  const local = fs.readFileSync(
    path.join(__dirname, '..', 'renderer', 'permissions-content.json'), 'utf8');
  assert.strictEqual(local, shared);
});
