const test = require('node:test');
const assert = require('node:assert');
const { isAllowedSettingUrl } = require('../setting-urls');

test('allows the macOS settings-pane URLs the walkthrough ships', () => {
  assert.strictEqual(
    isAllowedSettingUrl('x-apple.systempreferences:com.apple.preference.security'),
    true
  );
  assert.strictEqual(
    isAllowedSettingUrl(
      'x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles'
    ),
    true
  );
});

test('allows the Windows settings scheme', () => {
  assert.strictEqual(isAllowedSettingUrl('ms-settings:privacy-webcam'), true);
});

test('rejects schemes that could launch local code', () => {
  for (const url of [
    'file:///etc/passwd',
    'file:///C:/Windows/System32/cmd.exe',
    'vscode://file/etc/passwd',
    'smb://attacker.example/share',
    'javascript:alert(1)',
    'data:text/html,<script>alert(1)</script>',
    'http://attacker.example',
    'https://attacker.example',
  ]) {
    assert.strictEqual(isAllowedSettingUrl(url), false, `should reject ${url}`);
  }
});

test('rejects near-miss strings that only embed an allowed scheme', () => {
  // startsWith, not includes — an allowed scheme appearing later in the string
  // must not qualify the URL.
  assert.strictEqual(
    isAllowedSettingUrl('file:///tmp/x#x-apple.systempreferences:'),
    false
  );
  assert.strictEqual(
    isAllowedSettingUrl('  x-apple.systempreferences:com.apple.preference.security'),
    false
  );
});

test('rejects non-string input', () => {
  for (const value of [null, undefined, 42, {}, [], true]) {
    assert.strictEqual(isAllowedSettingUrl(value), false);
  }
});
