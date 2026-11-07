const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const counts = (checked, secured) => ({ checks: 5, critical: 0, warning: 0, info: 0, fog: 0, checked, secured });

test('marking pays nothing, ever: no clean-sweep bonus for the sweep after a mark', async () => {
  const { recordSweep, noteMarked } = await game('ledger.js');
  const { emptyDeck } = await game('progress.js');
  let deck = recordSweep(emptyDeck(), counts(2, 1), 't1').deck; // not clean
  deck = noteMarked(deck);
  assert.strictEqual(deck.points, 0, 'the mark itself pays nothing');
  const r = recordSweep(deck, counts(2, 2), 't2'); // clean, but only because of the mark
  assert.strictEqual(r.points, 0);
  assert.strictEqual(r.clean, false);
  assert.strictEqual(r.deck.sweep.marked, undefined, 'the next sweep starts without the flag');
  // Unmark, re-sweep (not clean), mark, re-sweep (clean): still nothing to farm.
  let d = recordSweep(r.deck, counts(2, 1), 't3').deck;
  d = noteMarked(d);
  assert.strictEqual(recordSweep(d, counts(2, 2), 't4').points, 0);
});

test('the flag survives a restart as a bare boolean, and nothing else', async () => {
  const { noteMarked } = await game('ledger.js');
  const { emptyDeck, cleanDeck, validDeck } = await game('progress.js');
  const d = noteMarked(emptyDeck());
  assert.ok(validDeck(d));
  assert.deepStrictEqual(cleanDeck(JSON.parse(JSON.stringify(d))).sweep, { at: null, keys: {}, marked: true });
  assert.strictEqual(validDeck({ ...d, sweep: { ...d.sweep, marked: 'a.b' } }), false);
});
