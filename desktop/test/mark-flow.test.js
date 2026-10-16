const test = require('node:test');
const assert = require('node:assert');
const MarkFlow = require('../renderer/mark-flow.js');

const MARKABLE = {
  kind: 'background_task',
  id: 'abcdef012345',
  code: 'security.launch_agent_audit.suspicious_path',
  label: 'ai.example.gateway',
  program: '/Users/me/.example/venv/bin/python',
  plist: '/Users/me/Library/LaunchAgents/ai.example.gateway.plist',
  will_change: 'Device Rescue will stop warning you. It will still be listed as "marked as yours".',
  how_to_undo: ['Choose "Stop treating this as mine"', 'Or run: rescue known remove abc'],
};

test('no button without a well-formed markable block', () => {
  assert.strictEqual(MarkFlow.markControlsHtml({}), '');
  assert.strictEqual(MarkFlow.markControlsHtml({ markable: { ...MARKABLE, how_to_undo: [] } }), '');
  assert.strictEqual(MarkFlow.markControlsHtml({ markable: { ...MARKABLE, label: '--x' } }), '');
  assert.strictEqual(MarkFlow.markControlsHtml({ markable: { ...MARKABLE, id: '"><x' } }), '');
});

test('the button opens a hidden confirmation that says it stays listed and how to undo', () => {
  const html = MarkFlow.markControlsHtml({ markable: MARKABLE });
  assert.match(html, /I set this up — it’s mine/);
  assert.match(html, /data-mark-id="abcdef012345"/);
  assert.ok(!html.includes('data-mark-program'), 'only the id is carried back');
  assert.match(html, /data-mark-panel hidden/);
  assert.match(html, /marked as yours/);
  assert.match(html, /To undo later:/);
  assert.match(html, /Stop treating this as mine/);
  assert.match(html, /Yes, it’s mine/);
  assert.ok(html.includes('Only do this if you set this up yourself.'));
});

test('a marked finding offers unmark instead', () => {
  const html = MarkFlow.markControlsHtml({ data: { marked_by_user: true, known_item_id: 'abcdef012345' } });
  assert.match(html, /data-unmark-id="abcdef012345"/);
  assert.match(html, /Stop treating this as mine/);
  assert.strictEqual(MarkFlow.markControlsHtml({ data: { marked_by_user: true, known_item_id: '"><x' } }), '');
});

test('everything from the engine is escaped', () => {
  const html = MarkFlow.markControlsHtml({ markable: { ...MARKABLE, label: 'a"><img src=x onerror=1>', will_change: '<b>x</b>' } });
  assert.ok(!html.includes('<img'));
  assert.ok(!html.includes('<b>x</b>'));
});

test('results: only the engine saying so counts as saved', () => {
  assert.strictEqual(MarkFlow.describeMarkResult({ status: 'marked', how_to_undo: ['u'] }).tone, 'success');
  assert.strictEqual(MarkFlow.describeMarkResult({ status: 'removed' }).tone, 'info');
  assert.strictEqual(MarkFlow.describeMarkResult({ status: 'refused', message: 'No.' }).tone, 'error');
  assert.strictEqual(MarkFlow.describeMarkResult(null).tone, 'error');
  assert.ok(!MarkFlow.describeMarkResult({ status: 'failed' }).done);
});

// --- one task, two checks, two cards --------------------------------------------

const ID_A = 'aaaaaaaaaaaa';
const ID_B = 'bbbbbbbbbbbb';
const ID_OTHER = 'cccccccccccc';

test('the confirmation says it covers every warning about the task', () => {
  const html = MarkFlow.markControlsHtml({ markable: { ...MARKABLE, id: ID_A, ids: [ID_A, ID_B] } });
  assert.match(html, new RegExp(`data-mark-group="${ID_A} ${ID_B}"`));
  assert.match(html, /2 warnings about this task/);
  const single = MarkFlow.markControlsHtml({ markable: { ...MARKABLE, id: ID_A } });
  assert.match(single, new RegExp(`data-mark-group="${ID_A}"`));
  assert.ok(!/warnings about this task/.test(single));
  // Junk in the engine's list never reaches the page.
  const junk = MarkFlow.markControlsHtml({ markable: { ...MARKABLE, id: ID_A, ids: ['"><x', ID_B] } });
  assert.match(junk, new RegExp(`data-mark-group="${ID_A} ${ID_B}"`));
  const marked = MarkFlow.markControlsHtml({ data: { marked_by_user: true, known_item_id: ID_A }, marked_ids: [ID_A, ID_B] });
  assert.match(marked, new RegExp(`data-unmark-group="${ID_A} ${ID_B}"`));
});

function cardsRoot(cards) {
  const mkCard = (attrs) => {
    const card = { attrs: { 'data-mark-card': '', ...attrs } };
    const part = (a = {}) => ({
      attrs: a, hidden: false, innerHTML: '',
      closest(sel) { return sel === '[data-mark-card]' ? card : null; },
      hasAttribute(x) { return x in this.attrs; },
      getAttribute(x) { return this.attrs[x] === undefined ? null : this.attrs[x]; },
    });
    Object.assign(card, {
      hasAttribute(x) { return x in this.attrs; },
      getAttribute(x) { return this.attrs[x] === undefined ? null : this.attrs[x]; },
      setAttribute(x, v) { this.attrs[x] = v; },
      closest(sel) { return sel === '[data-mark-card]' ? card : null; },
    });
    card.panel = part(); card.panel.hidden = true;
    card.status = part(); card.status.hidden = true;
    card.open = part({ 'data-mark-open': '' });
    card.confirm = part({ 'data-mark-confirm': '' });
    card.unmark = part({ 'data-unmark': '' });
    const buttons = 'data-unmark-id' in attrs ? [card.unmark] : [card.open];
    card.querySelector = (sel) => ({ '[data-mark-panel]': card.panel, '[data-mark-status]': card.status }[sel] || null);
    card.querySelectorAll = (sel) => (sel === '[data-mark-open],[data-unmark]' ? buttons : []);
    return card;
  };
  const made = cards.map(mkCard);
  let click;
  const root = {
    addEventListener(type, fn) { if (type === 'click') click = fn; },
    click(target) { return click({ target: { closest: () => target } }); },
    querySelectorAll(sel) {
      const attr = sel.replace(/^\[|\]$/g, '');
      return made.filter((c) => attr in c.attrs);
    },
  };
  return { root, cards: made };
}

test('marking on one card updates every card for the same task, and only those', async () => {
  const { root, cards: [a, b, other] } = cardsRoot([
    { 'data-mark-id': ID_A, 'data-mark-group': `${ID_A} ${ID_B}` },
    { 'data-mark-id': ID_B, 'data-mark-group': `${ID_B} ${ID_A}` },
    { 'data-mark-id': ID_OTHER, 'data-mark-group': ID_OTHER },
  ]);
  const sent = [];
  MarkFlow.attach(root, { markMine: async (id) => { sent.push(id); return { status: 'marked', ids: [ID_A, ID_B], how_to_undo: ['u'] }; } });
  root.click(a.open);
  await root.click(a.confirm);
  assert.deepStrictEqual(sent, [ID_A], 'only the clicked card’s id crosses to the main process');
  assert.match(a.status.innerHTML, /Marked as yours/);
  assert.strictEqual(b.open.hidden, true, 'the twin card no longer offers the button');
  assert.strictEqual(b.status.hidden, false);
  assert.match(b.status.innerHTML, /Marked as yours/);
  assert.strictEqual(other.open.hidden, false, 'a different task is untouched');
  assert.strictEqual(other.status.innerHTML, '');
});

test('a refused mark leaves the twin card alone', async () => {
  const { root, cards: [a, b] } = cardsRoot([
    { 'data-mark-id': ID_A, 'data-mark-group': `${ID_A} ${ID_B}` },
    { 'data-mark-id': ID_B, 'data-mark-group': `${ID_B} ${ID_A}` },
  ]);
  MarkFlow.attach(root, { markMine: async () => ({ status: 'refused', message: 'It changed.' }) });
  root.click(a.open);
  await root.click(a.confirm);
  assert.strictEqual(b.open.hidden, false);
  assert.strictEqual(b.status.innerHTML, '');
});

test('the twin is updated only if the engine says it saved that id too', async () => {
  const { root, cards: [a, b] } = cardsRoot([
    { 'data-mark-id': ID_A, 'data-mark-group': `${ID_A} ${ID_B}` },
    { 'data-mark-id': ID_B, 'data-mark-group': `${ID_B} ${ID_A}` },
  ]);
  MarkFlow.attach(root, { markMine: async () => ({ status: 'marked', ids: [ID_A] }) });
  root.click(a.open);
  await root.click(a.confirm);
  assert.strictEqual(b.open.hidden, false);
});

test('stop treating this as mine updates every card for the same task', async () => {
  const { root, cards: [a, b, other] } = cardsRoot([
    { 'data-unmark-id': ID_A, 'data-unmark-group': `${ID_A} ${ID_B}` },
    { 'data-unmark-id': ID_B, 'data-unmark-group': `${ID_B} ${ID_A}` },
    { 'data-unmark-id': ID_OTHER, 'data-unmark-group': ID_OTHER },
  ]);
  const sent = [];
  MarkFlow.attach(root, { unmarkMine: async (id) => { sent.push(id); return { status: 'removed', ids: [ID_A, ID_B] }; } });
  await root.click(a.unmark);
  assert.deepStrictEqual(sent, [ID_A]);
  assert.match(a.status.innerHTML, /No longer marked as yours/);
  assert.strictEqual(b.unmark.hidden, true);
  assert.match(b.status.innerHTML, /No longer marked as yours/);
  assert.strictEqual(other.unmark.hidden, false);
});
