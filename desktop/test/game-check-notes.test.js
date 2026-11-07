// The sweep says what each check looks at, why, and where. The notes are
// generated (scripts/generate_check_notes.py) from scripts/check_notes.json;
// a module that ships without one fails here, before it reaches the sweep.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const load = (f) => import(pathToFileURL(path.join(GAME, f)).href);

// Every shipped check: a folder under modules/<category>/ whose __init__.py defines `class Module(`.
function shippedModules() {
  const out = [];
  const mods = path.join(ROOT, 'modules');
  for (const cat of fs.readdirSync(mods)) {
    const dir = path.join(mods, cat);
    if (!fs.statSync(dir).isDirectory()) continue;
    for (const name of fs.readdirSync(dir)) {
      const init = path.join(dir, name, '__init__.py');
      if (fs.existsSync(init) && /^class Module\(/m.test(fs.readFileSync(init, 'utf8'))) out.push({ name, category: cat });
    }
  }
  return out;
}

test('every shipped check has a what / why / where note, in its own category, and no note is left over', async () => {
  const { CHECK_NOTES } = await load('check-notes.js');
  const shipped = shippedModules();
  assert.ok(shipped.length > 200, 'found the modules');
  const missing = shipped.filter((m) => !CHECK_NOTES[m.name]).map((m) => m.name);
  assert.deepStrictEqual(missing, [], 'run scripts/generate_check_notes.py after adding a note to scripts/check_notes.json');
  for (const m of shipped) assert.strictEqual(CHECK_NOTES[m.name].category, m.category, m.name);
  const names = new Set(shipped.map((m) => m.name));
  assert.deepStrictEqual(Object.keys(CHECK_NOTES).filter((n) => !names.has(n)), []);
});

test('each note is short, and never a verdict or a time promise', async () => {
  const { CHECK_NOTES } = await load('check-notes.js');
  const { DIAGNOSTIC_PHRASES, TIME_WORDS } = await load('training.js');
  const LIMITS = { what: 60, why: 110, where: 90 };
  for (const [name, n] of Object.entries(CHECK_NOTES)) {
    for (const [k, max] of Object.entries(LIMITS)) {
      assert.ok(typeof n[k] === 'string' && n[k].trim(), `${name}: no ${k}`);
      assert.ok(n[k].length <= max, `${name}: ${k} is longer than ${max}`);
      assert.doesNotMatch(n[k], TIME_WORDS, `${name}: time word in ${k}`);
      for (const p of DIAGNOSTIC_PHRASES) assert.ok(!n[k].toLowerCase().includes(p), `${name}: "${p}"`);
    }
  }
});

test('the generated file matches its source', () => {
  const src = JSON.parse(fs.readFileSync(path.join(ROOT, 'scripts', 'check_notes.json'), 'utf8'));
  const js = fs.readFileSync(path.join(GAME, 'check-notes.js'), 'utf8');
  for (const [name, n] of Object.entries(src)) {
    for (const k of ['what', 'why', 'where']) assert.ok(js.includes(JSON.stringify(n[k])), `${name}.${k} is stale: run scripts/generate_check_notes.py`);
  }
});

test('noteFor: the note for a known check, a plain fallback for an unknown one, nothing for none', async () => {
  const { noteFor } = await load('sweep.js');
  const n = noteFor('launch_agent_audit', 'security');
  assert.strictEqual(n.module, 'launch_agent_audit');
  assert.ok(n.what && n.why && n.where);
  const u = noteFor('brand_new_check', 'network');
  assert.deepStrictEqual(u, { module: 'brand_new_check', what: 'Brand new check', why: '', where: '' });
  assert.strictEqual(noteFor(null, 'network'), null);
});
