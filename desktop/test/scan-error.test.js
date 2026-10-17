const test = require('node:test');
const assert = require('node:assert');
const { scanErrorText } = require('../renderer/app.js');

test('Electron’s "Error invoking remote method" wrapper never reaches the person', () => {
  assert.strictEqual(scanErrorText("Error invoking remote method 'rescue:scan': Error: The engine stopped."), 'The engine stopped.');
  assert.strictEqual(scanErrorText("Error invoking remote method 'rescue:run-scan': TypeError: bad thing"), 'bad thing');
  assert.strictEqual(scanErrorText('The engine stopped.'), 'The engine stopped.');
  // Nothing left to say: empty, so each screen shows its own plain fallback.
  assert.strictEqual(scanErrorText("Error invoking remote method 'x': Error: "), '');
  assert.strictEqual(scanErrorText(''), '');
  assert.strictEqual(scanErrorText(null), '');
});
