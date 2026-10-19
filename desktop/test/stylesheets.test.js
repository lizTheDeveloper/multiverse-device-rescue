const test = require('node:test');
const assert = require('node:assert');
const fs = require('node:fs');
const path = require('node:path');

// An unclosed block makes the browser swallow every rule after it, silently.
// One left open in a dark-mode @media hid most of the results-screen styling.
const SHEETS = ['renderer/styles.css', 'renderer/game/game.css', 'renderer/game-fonts.css', 'renderer/checklist.css', 'renderer/game/profile.css', 'renderer/profile.css'];

for (const rel of SHEETS) {
  test(`${rel} closes every block it opens`, () => {
    const css = fs.readFileSync(path.join(__dirname, '..', rel), 'utf8')
      .replace(/\/\*[\s\S]*?\*\//g, '')
      .replace(/"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'/g, '""');
    let depth = 0;
    css.split('\n').forEach((line, i) => {
      for (const ch of line) {
        if (ch === '{') depth += 1;
        else if (ch === '}') depth -= 1;
        assert.ok(depth >= 0, `extra "}" on line ${i + 1}`);
      }
    });
    assert.strictEqual(depth, 0, `${depth} block(s) left open`);
  });
}
