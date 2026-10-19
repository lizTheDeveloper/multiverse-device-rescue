'use strict';
// Look-ups search for the item's own name (label, bundle id, extension id,
// program), never the finding's title sentence ("A scheduled job runs every
// minute" is not something to search for).
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const FIXTURES = path.join(__dirname, 'fixtures', 'missions');
const TYPES = ['door', 'keyring', 'loadout', 'seal', 'switchboard', 'locker', 'locks', 'junkyard', 'notes', 'simple'];

function fixtureFindings() {
  const out = [];
  const walk = (v, module) => {
    if (Array.isArray(v)) { v.forEach((x) => walk(x, module)); return; }
    if (!v || typeof v !== 'object') return;
    if (typeof v.title === 'string' && (typeof v.module === 'string' || module) && (v.severity || v.data)) {
      const { expect, platform, id, area, ...f } = v;
      out.push({ module, ...f });
      return;
    }
    if (typeof v.name === 'string' && Array.isArray(v.findings)) { walk(v.findings, v.name); return; }
    for (const k of Object.keys(v)) walk(v[k], module);
  };
  for (const file of fs.readdirSync(FIXTURES).filter((x) => x.endsWith('.json'))) walk(JSON.parse(fs.readFileSync(path.join(FIXTURES, file), 'utf8')), null);
  return out;
}

test('no game searches for a finding’s title sentence', async () => {
  const C = await import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
  const all = fixtureFindings();
  for (const type of TYPES) {
    const game = (await import(pathToFileURL(path.join(MISSIONS, 'games', `${type}.js`)).href)).default;
    const mods = [...new Set((game.covers || []).map((c) => c.module).filter((m) => m && m !== '*'))];
    const own = type === 'simple' ? all : type === 'notes' ? all.filter((f) => f.severity === 'info') : all.filter((f) => mods.includes(f.module));
    // Plus, for every module the game claims, a finding that names nothing but its title.
    const bare = (type === 'simple' || type === 'notes' ? ['some_module'] : mods).map((module) => ({
      module, severity: type === 'notes' ? 'info' : 'warning', title: 'Several things here need a careful look today', description: 'x', data: {} }));
    for (const f of [...own, ...bare]) {
      const item = C.makeItem(f);
      for (const platform of ['darwin', 'win32']) {
        const r = game.research(item, C.testContext({ platform }));
        const intents = [...(r.links || []), ...game.decisions(item, C.testContext({ platform })).map((d) => d.effect && d.effect.link).filter(Boolean)];
        for (const l of intents.filter((x) => x.kind === 'lookup')) {
          if (f.title.split(/\s+/).length >= 4) assert.ok(!String(l.query).includes(f.title), `${type} ${f.module}: searches "${l.query}"`);
        }
      }
    }
  }
});
