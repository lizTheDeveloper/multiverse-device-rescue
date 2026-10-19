'use strict';
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');

const load = () => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'missions', 'contract.js')).href);

// A tiny well-behaved game: the contract's own reference for what passes.
function goodGame(C) {
  return {
    type: 'simple', title: { standard: 'Other', city: 'Odd Jobs' }, concepts: [],
    decisions: (item) => [
      { id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } },
      { id: 'fix', label: { standard: 'Fix it', city: 'Patch it' }, effect: { kind: 'fix' } },
    ],
    research: () => ({ rows: [], what: '', links: [{ kind: 'settings', pane: 'login-items' }, { kind: 'lookup', source: 'web', query: 'x' }] }),
    practice: { items: [C.makeItem({ title: 'a' }), C.makeItem({ title: 'b' })], script: [{ item: 0, say: { standard: 'Look', city: 'Look' } }] },
    render: (view, ctx) => `<h3>${ctx.esc(view.item.finding.title)}</h3><p>${ctx.esc(view.item.finding.data.path || '')}</p>`,
    summary: () => '<p>Done</p>',
  };
}

test('a well-behaved game passes every contract check', async () => {
  const C = await load();
  assert.deepStrictEqual(C.runContractChecks(goodGame(C), [C.makeItem({ title: 'Thing', data: { path: '/Applications/X.app' } })]), []);
});

test('unescaped rendering of a hostile value is caught', async () => {
  const C = await load();
  const bad = { ...goodGame(C), render: (view) => `<h3>${view.item.finding.title}</h3>` };
  assert.ok(C.runContractChecks(bad, []).some((p) => /script|onerror|control/.test(p)));
});

test('a removing default decision on an item with a removal warning is caught', async () => {
  const C = await load();
  const item = C.makeItem({ title: 't', removal_alert: true });
  const d = [
    { id: 'fix', label: { standard: 'Remove', city: 'Remove' }, effect: { kind: 'fix' } },
    { id: 'later', label: { standard: 'Later', city: 'Later' }, effect: { kind: 'later' } },
  ];
  assert.ok(C.checkDecisions(d, item).some((p) => /removal warning/.test(p)));
});

test('games return link intents, never URLs, from the allowlists', async () => {
  const C = await load();
  assert.ok(C.checkResearch({ rows: [], links: [{ kind: 'lookup', source: 'web', href: 'https://x' }] }).some((p) => /never URLs/.test(p)));
  assert.ok(C.checkResearch({ rows: [], links: [{ kind: 'settings', pane: 'nope' }] }).some((p) => /unknown settings pane/.test(p)));
});

test('city words: non-game words in city output are caught', async () => {
  const C = await load();
  const leaky = { ...goodGame(C), summary: (r, ctx) => (ctx.mode === 'city' ? '<p>We found stalkerware</p>' : '<p>ok</p>') };
  assert.ok(C.runContractChecks(leaky, []).some((p) => /stalk/.test(p)));
});

test('labels over four words and wrong counts are caught', async () => {
  const C = await load();
  const d = [{ id: 'a', label: { standard: 'one two three four five', city: 'x' }, effect: { kind: 'later' } }];
  const p = C.checkDecisions(d, C.makeItem({}));
  assert.ok(p.some((x) => /over 4 words/.test(x)));
  assert.ok(p.some((x) => /expected 2–3/.test(x)));
});
