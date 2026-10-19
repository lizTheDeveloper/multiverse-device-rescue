'use strict';
// Every game's practice round asks before it tells (audit P2-6): a step that
// judges a move (`expect`) asks a question and keeps the verdict for `why`,
// which the mission screen shows after the move. A step with no `expect` only
// explains (the screen shows one GOT IT). `expect` may list several moves that
// all fit, the best first (Look closer, when you're not sure).
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const MISSIONS = path.join(__dirname, '..', 'renderer', 'missions');
const TYPES = ['door', 'keyring', 'loadout', 'seal', 'switchboard', 'locker', 'locks', 'junkyard', 'notes', 'simple'];
const TIME = /\b(?:minutes?|seconds?|hours?|quick(?:ly)?|instantly)\b/i;

async function load() {
  const C = await import(pathToFileURL(path.join(MISSIONS, 'contract.js')).href);
  const games = {};
  for (const t of TYPES) games[t] = (await import(pathToFileURL(path.join(MISSIONS, 'games', `${t}.js`)).href)).default;
  return { C, games };
}

const strip = (html) => String(html).replace(/<[^>]+>/g, ' ').replace(/&#39;|&rsquo;/g, '’').replace(/&quot;/g, '"').replace(/&amp;/g, '&').replace(/\s+/g, ' ');
const wants = (step) => (Array.isArray(step.expect) ? step.expect : step.expect ? [step.expect] : []);

test('practice steps: a judged step asks first and keeps its verdict for after the move', async () => {
  const { C, games } = await load();
  for (const [type, game] of Object.entries(games)) {
    const { items, script } = game.practice;
    assert.ok(script.some((s) => s.expect), `${type}: at least one step judges a move`);
    for (const [n, step] of script.entries()) {
      const where = `${type} step ${n + 1}`;
      assert.ok(items[step.item], `${where}: points at a practice item`);
      for (const mode of ['standard', 'city']) {
        assert.ok(step.say && typeof step.say[mode] === 'string' && step.say[mode].trim(), `${where}: say.${mode}`);
        assert.doesNotMatch(step.say[mode], TIME, `${where}: no time words`);
        if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(step.say.city), [], where);
      }
      if (!wants(step).length) {
        assert.ok(!step.why, `${where}: an explanation step has no verdict`);
        continue;
      }
      assert.strictEqual(new Set(wants(step)).size, wants(step).length, `${where}: no repeats in expect`);
      for (const mode of ['standard', 'city']) {
        const ctx = C.testContext({ mode, practice: true });
        const d = game.decisions(items[step.item], ctx);
        const ids = d.map((x) => x.id);
        for (const w of wants(step)) assert.ok(ids.includes(w), `${where} (${mode}): ${w} is one of ${ids}`);
        // Ask first: a question, and not the best answer's own button label.
        assert.match(step.say[mode], /\?\s*$/, `${where} (${mode}): asks a question`);
        const label = d.find((x) => x.id === wants(step)[0]).label[mode];
        assert.ok(!step.say[mode].toLowerCase().includes(label.toLowerCase()), `${where} (${mode}): say gives away "${label}"`);
        assert.ok(step.why && typeof step.why[mode] === 'string' && step.why[mode].trim(), `${where}: why.${mode}`);
        assert.doesNotMatch(step.why[mode], TIME, `${where}: no time words in why`);
        if (mode === 'city') assert.deepStrictEqual(C.checkCityWords(step.why.city), [], where);
      }
    }
  }
});

test('the card never prints the verdict: the screen shows why after the move', async () => {
  const { C, games } = await load();
  for (const [type, game] of Object.entries(games)) {
    for (const step of game.practice.script.filter((s) => s.why)) {
      for (const mode of ['standard', 'city']) {
        const ctx = C.testContext({ mode, practice: true });
        const item = game.practice.items[step.item];
        const view = { item, research: game.research(item, ctx), decisions: game.decisions(item, ctx), index: 0, total: game.practice.script.length, practice: true, step };
        for (const answer of [null, { id: wants(step)[0], right: true }]) {
          const html = strip(game.render({ ...view, answer }, ctx));
          assert.ok(!html.includes(strip(ctx.esc(step.why[mode]))), `${type} (${mode}): the card repeats why`);
        }
      }
    }
  }
});

test('door, seal, switchboard and keyring accept Look closer where the maker is unknown or the step allows it', async () => {
  const { games } = await load();
  const ok = wants;
  const door = games.door.practice.script.filter((s) => wants(s).length);
  // The hidden, unsigned agent: Look closer is the move (the real game's default for it), Not mine is fine too.
  assert.deepStrictEqual(ok(door[1]), ['closer', 'not-mine']);
  // The unverified developer tool you installed: Mine, or Look closer when you're not sure.
  assert.ok(ok(door[2]).includes('closer'));
  for (const type of ['seal', 'switchboard', 'keyring']) {
    assert.ok(games[type].practice.script.some((s) => ok(s).includes('closer')), `${type}: some step takes Look closer`);
  }
});
