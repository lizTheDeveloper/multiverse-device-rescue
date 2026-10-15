const test = require('node:test');
const assert = require('node:assert');
const { groupFindingsBySeverity } = require('../renderer/app.js');

test('a check that could not run is listed, not counted as clean', () => {
  const { groups, erroredModules } = groupFindingsBySeverity({
    modules: [
      { name: 'arp_spoof_check', status: 'ok', supported: false,
        unsupported_reason: 'The neighbour table could not be read.', findings: [] },
      { name: 'disk_space', status: 'ok', supported: true, findings: [] },
    ],
  });
  assert.deepStrictEqual(erroredModules,
    [{ name: 'arp_spoof_check', error: 'The neighbour table could not be read.' }]);
  assert.strictEqual(groups.critical.length + groups.warning.length + groups.info.length, 0);
});

test('output from an older engine without the field still works', () => {
  const { erroredModules } = groupFindingsBySeverity({
    modules: [{ name: 'disk_space', status: 'ok', findings: [] }],
  });
  assert.deepStrictEqual(erroredModules, []);
});

test('descriptions keep paragraphs and pick out "What to do:"', () => {
  const { descriptionHtml } = require('../renderer/app.js');
  const esc = (v) => String(v).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const html = descriptionHtml('First <b>part</b>.\n\nWhat to do: open Passwords.\n\nLast.', esc);
  assert.strictEqual(html.match(/<p/g).length, 3);
  assert.ok(html.includes('<strong>What to do:</strong> open Passwords.'));
  assert.ok(html.includes('&lt;b&gt;'));
});
