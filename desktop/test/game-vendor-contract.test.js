const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const need = (rel) => path.join(SRC, rel);

test('the Reclaim City submodule is checked out (run: git submodule update --init)', () => {
  assert.ok(fs.existsSync(need('components/scout.js')),
    'desktop/vendor/reclaim-city is empty. Run: git submodule update --init');
});

test('every file game mode loads from the game exists', () => {
  for (const rel of ['components/scout.js', 'style.css', 'assets/characters/scout_0.png',
    'assets/iso_occupied.png', 'assets/iso_progress.png', 'assets/iso_liberated.png',
    'assets/iso_tower_occ.png', 'assets/iso_tower_lib.png']) {
    assert.ok(fs.existsSync(need(rel)), `missing ${rel}`);
  }
});

test('scoutSprite renders a sheet that exists on disk, for every feeling game mode uses', async () => {
  const { scoutSprite, FEELINGS } = await import(path.join(SRC, 'components', 'scout.js'));
  for (const feeling of ['happy', 'proud', 'wave', 'thinkingA', 'worried']) {
    assert.ok(FEELINGS[feeling], `feeling ${feeling} gone upstream`);
    const html = scoutSprite(feeling, { size: 64 });
    const m = html.match(/url\((assets\/characters\/scout\/[a-z-]+\.png)\)/);
    assert.ok(m, `no sheet url in: ${html}`);
    assert.ok(fs.existsSync(need(m[1])), `sheet missing on disk: ${m[1]}`);
  }
});

test('scout.js imports nothing (game mode relies on it being self-contained)', () => {
  const text = fs.readFileSync(need('components/scout.js'), 'utf8');
  assert.doesNotMatch(text, /^\s*import\s/m);
});
