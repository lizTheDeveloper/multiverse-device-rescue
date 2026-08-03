const test = require('node:test');
const assert = require('node:assert');
const { parseEngineOutput } = require('../engine-runner');

test('parseEngineOutput returns parsed JSON from stdout', () => {
  const out = JSON.stringify({ schema_version: 1, platform: 'darwin', modules: [] });
  assert.deepStrictEqual(parseEngineOutput(out).schema_version, 1);
});
test('parseEngineOutput throws on non-JSON', () => {
  assert.throws(() => parseEngineOutput('not json'));
});
