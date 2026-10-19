const test = require('node:test');
const assert = require('node:assert');
const { browserDisplayName } = require('../router-url');

test('browser names read as plain names', () => {
  assert.strictEqual(browserDisplayName('Google Chrome'), 'Google Chrome');
  assert.strictEqual(browserDisplayName('firefox.desktop'), 'firefox');
  assert.strictEqual(browserDisplayName('  Safari '), 'Safari');
  for (const v of ['', null, undefined, 42, '.desktop', 'x'.repeat(81)]) assert.strictEqual(browserDisplayName(v), null, JSON.stringify(v));
});
