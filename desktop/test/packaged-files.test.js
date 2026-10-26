const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const pkg = require('../package.json');

const DESKTOP = path.join(__dirname, '..');

// electron-builder's `build.files` is an allow-list: anything main.js needs that
// is not on it is missing from app.asar, and the installed app dies on launch
// with "Cannot find module" while `npm start` works fine. 0.3.7 shipped without
// router-url.js this way (added 2026-10-18 for the router button, never listed).
function packaged(rel) {
  return pkg.build.files.some((pattern) => {
    if (pattern.endsWith('/**')) return rel.startsWith(pattern.slice(0, -2));
    return rel === pattern;
  });
}

// Every local file reachable from the entry points by require('./...').
function localRequires(entry) {
  const seen = new Set();
  const walk = (rel) => {
    if (seen.has(rel)) return;
    seen.add(rel);
    const src = fs.readFileSync(path.join(DESKTOP, rel), 'utf8');
    const dir = path.posix.dirname(rel);
    for (const m of src.matchAll(/require\(\s*['"](\.{1,2}\/[^'"]+)['"]\s*\)/g)) {
      let target = path.posix.normalize(path.posix.join(dir, m[1]));
      if (!fs.existsSync(path.join(DESKTOP, target))) {
        if (fs.existsSync(path.join(DESKTOP, `${target}.js`))) target = `${target}.js`;
        else if (fs.existsSync(path.join(DESKTOP, target, 'index.js'))) target = `${target}/index.js`;
      }
      if (target.endsWith('.js')) walk(target);
      else seen.add(target);
    }
  };
  walk(entry);
  return [...seen];
}

test('every file main.js and preload.js load is packaged into the app', () => {
  const missing = [...new Set([...localRequires(pkg.main), ...localRequires('preload.js')])]
    .filter((rel) => !rel.startsWith('node_modules/') && !packaged(rel));
  assert.deepStrictEqual(missing, [], `not in build.files (missing from app.asar): ${missing.join(', ')}`);
});
