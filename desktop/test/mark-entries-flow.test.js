// "It's mine" for some entries of a list: a checklist of the apps (or keys),
// unticked, inside one finding. The confirmation lists exactly the ticked
// rows, always with the watching warning, and nothing is sent before "Yes".
const test = require('node:test');
const assert = require('node:assert');
const MarkFlow = require('../renderer/mark-flow.js');
const { createDocument } = require('./mini-dom.js');

const CARD = 'aaaaaaaaaaaa';
const ID_1 = '111111111111';
const ID_2 = '222222222222';
const DONE = '444444444444';
const ACC = 'security.app_permissions.accessibility_access';

const apps = (rows) => rows.map((r) => ({ id: r.key, name: r.label }));
const entries = (rows) => ({
  kind: 'app_permissions', id: CARD, code: ACC, group: '0123456789ab', label: `${rows.length} apps`, monitoring: true,
  shows: [['Apps', rows.map((r) => r.label).join(', ')], ['How many', String(rows.length)]],
  apps: apps(rows),
  items: rows,
  will_change: 'The checkup will stop warning you about this list of apps.',
  items_will_change: 'The checkup will stop warning you about the apps you choose.',
  how_to_undo: ['Choose "Stop treating this as mine" on the item in this app'],
});
const ROWS = [
  { key: 'com.example.one', label: 'One', detail: 'com.example.one', id: ID_1, monitoring: true },
  { key: 'com.example.two', label: 'Two', detail: 'com.example.two', id: ID_2, monitoring: true },
];
const finding = (markable, extra = {}) => ({ module: 'app_permissions', markable, ...extra });

test('a list finding shows a checklist of its apps, unticked, and no whole-list answer', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS), {
    made_by: [{ subject: 'com.example.one', name: 'Example Ltd', verified: true }],
  }));
  assert.match(html, /data-mark-entries/);
  assert.match(html, new RegExp(`data-cl-list="mark-${CARD}"`));
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
  assert.ok(!/\bchecked\b/.test(html));
  assert.match(html, /<code class="checklist__detail">com\.example\.one<\/code>/);
  assert.match(html, /Made by Example Ltd \(verified\)/);
  assert.match(html, /Some of these apps are mine/);
  assert.match(html, /Select at least one/);
  assert.ok(!html.includes(MarkFlow.NOT_SURE_LIST), 'no "leave the whole list" line');
  assert.ok(!html.includes('Yes, it’s mine'));
});

test('the confirmation always carries the watching warning, even without "watched"', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS)));
  const confirm = html.slice(html.indexOf('data-mark-items-confirm'));
  assert.ok(confirm.includes(MarkFlow.ONLY_IF_YOURS));
  assert.ok(confirm.includes(MarkFlow.COULD_WATCH));
  assert.ok(confirm.includes(MarkFlow.ENTRY_REASON));
  assert.ok(confirm.includes('The checkup will stop warning you about the apps you choose.'));
});

test('a row with no id is shown, disabled, with a note', () => {
  const rows = [...ROWS, { key: 'com.example.gone', label: 'Gone', detail: 'com.example.gone', id: null, monitoring: true }];
  const html = MarkFlow.markControlsHtml(finding(entries(rows)));
  assert.match(html, /data-cl-key="none-2" disabled>/);
  assert.ok(html.includes(MarkFlow.CANT_ALONE));
  assert.match(html, /data-mark-selectable="2"/);
});

test('rows already marked are listed with their own undo, never as checkboxes', () => {
  const rows = [...ROWS, { key: 'com.example.done', label: 'Done', detail: 'com.example.done', id: DONE, marked: true, monitoring: true }];
  const html = MarkFlow.markControlsHtml(finding(entries(rows)));
  assert.match(html, /Already marked as yours \(1\)/);
  assert.match(html, new RegExp(`data-unmark-item="${DONE}"`));
  assert.ok(!html.includes(`data-cl-key="${DONE}"`));
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
});

test('two apps with the same name are two checklist rows', () => {
  const rows = [
    { key: 'us.zoom.xos', label: 'Zoom', detail: 'us.zoom.xos', id: ID_1, monitoring: true },
    { key: 'com.fake.zoom', label: 'Zoom', detail: 'com.fake.zoom', id: ID_2, monitoring: true },
  ];
  const html = MarkFlow.markControlsHtml(finding(entries(rows)));
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
  assert.ok(html.includes('us.zoom.xos') && html.includes('com.fake.zoom'));
});

test('if the items and the rows disagree, the whole raw list is shown as before', () => {
  const m = entries(ROWS);
  const html = MarkFlow.markControlsHtml(finding({ ...m, items: [ROWS[0]] }));
  assert.ok(!html.includes('data-mark-entries'));
  assert.match(html, /Yes, these are mine/);
  assert.ok(html.includes(MarkFlow.NOT_SURE_LIST));
  const forged = MarkFlow.markControlsHtml(finding({ ...m, items: [ROWS[0], { ...ROWS[1], id: '"><x' }] }));
  assert.ok(!forged.includes('data-mark-entries') && !forged.includes('"><x'));
});

test('saved remote-login keys get the same checklist', () => {
  const sha = (c) => c.repeat(64);
  const keys = {
    kind: 'ssh_authorized_keys', id: CARD, code: 'security.session_revocation_scan.ssh_authorized_keys', group: '0123456789ab',
    monitoring: true, shows: [['Saved keys', '2'], ['Fingerprint of the list', 'abcd…']],
    items: [
      { key: sha('a'), label: 'ssh-ed25519 key', detail: 'me@laptop', id: ID_1, monitoring: true },
      { key: sha('b'), label: 'ssh-rsa key', detail: '', id: ID_2, monitoring: true },
    ],
    will_change: 'w', items_will_change: 'The checkup will stop warning you about the remote-login keys you choose.', how_to_undo: ['u'],
  };
  const html = MarkFlow.markControlsHtml({ module: 'session_revocation_scan', markable: keys });
  assert.match(html, /Some of these keys are mine/);
  assert.match(html, /<code class="checklist__detail">me@laptop<\/code>/);
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
});

test('a list marked entry by entry offers undo per row and for all of them', () => {
  const html = MarkFlow.markControlsHtml({ module: 'app_permissions', data: { marked_by_user: true, marked_items: [
    { id: ID_1, entry: 'com.example.one', shown: 'One · com.example.one' },
    { id: ID_2, entry: 'com.example.two', shown: 'Two · com.example.two' },
  ] } });
  assert.match(html, /data-mark-entries-done/);
  assert.match(html, /Marked as yours \(2\)/);
  assert.match(html, new RegExp(`data-unmark-item="${ID_1}"`));
  assert.match(html, new RegExp(`data-unmark-items="${ID_1} ${ID_2}"`));
  assert.strictEqual(MarkFlow.markControlsHtml({ module: 'stalkerware_scan', data: { marked_by_user: true, marked_items: [{ id: ID_1, shown: 'x' }] } }), '');
});

test('the test card below uses the same hooks the panel renders', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS)));
  for (const attr of ['data-mark-entries', 'data-mark-selectable', 'data-mark-items-pick', 'data-mark-items-confirm',
    'data-mark-items-head', 'data-mark-items-row', 'data-mark-items-yes', 'data-mark-items-back',
    'data-mark-items-done', 'data-mark-items-done-row', 'data-unmark-item', 'data-unmark-item-status',
    'data-cl-action="mark"', 'data-cl-item', 'data-mark-open', 'data-mark-cancel', 'data-mark-panel', 'data-mark-status']) {
    assert.ok(html.includes(attr), attr);
  }
});

// --- the flow, on a small DOM laid out like the panel ------------------------

function entryCard({ selectable = [ID_1, ID_2] } = {}) {
  const doc = createDocument();
  const root = doc.body.add('div');
  const card = root.add('div', { 'data-mark-card': '', 'data-mark-entries': '', 'data-mark-id': CARD,
    'data-mark-group': CARD, 'data-mark-selectable': String(selectable.length), 'data-mark-kind': 'app_permissions' });
  const open = card.add('button', { 'data-mark-open': '' });
  const panel = card.add('div', { 'data-mark-panel': '', hidden: '' });
  const pick = panel.add('div', { 'data-mark-items-pick': '' });
  const list = pick.add('fieldset', { 'data-cl-list': `mark-${CARD}` });
  const boxes = selectable.map((k) => { const b = list.add('input', { 'data-cl-item': '', 'data-cl-key': k }); b.checked = false; b.disabled = false; return b; });
  list.add('p', { 'data-cl-count': '' });
  const action = list.add('button', { 'data-cl-action': 'mark', 'data-cl-verb': 'Mark', 'data-cl-one': 'app',
    'data-cl-many': 'apps', 'data-cl-suffix': 'as mine', 'data-cl-min': '1' });
  const cancel = pick.add('button', { 'data-mark-cancel': '' });
  const confirm = panel.add('div', { 'data-mark-items-confirm': '', hidden: '' });
  const head = confirm.add('strong', { 'data-mark-items-head': '' });
  const confirmRows = selectable.map((k) => confirm.add('li', { 'data-mark-items-row': k, hidden: '' }));
  const yes = confirm.add('button', { 'data-mark-items-yes': '' });
  const back = confirm.add('button', { 'data-mark-items-back': '' });
  const status = card.add('div', { 'data-mark-status': '', hidden: '' });
  const done = card.add('ul', { 'data-mark-items-done': '', hidden: '' });
  const doneRows = selectable.map((k) => {
    const li = done.add('li', { 'data-mark-entry': k, 'data-mark-items-done-row': k, hidden: '' });
    li.add('button', { 'data-unmark-item': k });
    li.add('span', { 'data-unmark-item-status': '', hidden: '' });
    return li;
  });
  return { doc, root, card, open, panel, pick, boxes, action, cancel, confirm, head, confirmRows, yes, back, status, done, doneRows };
}

const tick = (c, i) => {
  c.boxes[i].checked = true;
  (c.root.listeners.change || []).forEach((fn) => fn({ target: c.boxes[i] }));
};

test('tick, then the button: the confirmation shows exactly the ticked rows; nothing is sent until Yes', async () => {
  const c = entryCard();
  const sent = [];
  const marked = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => { sent.push([id, ids]); return { status: 'marked', ids, how_to_undo: ['u'] }; } },
    { onMarked: (cards) => marked.push(cards) });
  await c.open.click();
  assert.strictEqual(c.panel.hidden, false);
  tick(c, 1);
  await c.action.click();
  assert.strictEqual(c.pick.hidden, true);
  assert.strictEqual(c.confirm.hidden, false);
  assert.deepStrictEqual(c.confirmRows.map((r) => r.hidden), [true, false]);
  assert.strictEqual(c.head.textContent, 'You’re saying this one is yours:');
  assert.deepStrictEqual(sent, [], 'nothing before Yes');
  await c.yes.click();
  assert.deepStrictEqual(sent, [[CARD, [ID_2]]]);
  assert.match(c.status.innerHTML, /Marked 1 as yours\./);
  assert.match(c.status.innerHTML, /The other 1 keep their warning\./);
  assert.strictEqual(c.done.hidden, false);
  assert.deepStrictEqual(c.doneRows.map((r) => r.hidden), [true, false]);
  assert.deepStrictEqual(marked, [], 'one of two: the card stays on the list');
});

test('ticking every row and saying yes clears the card', async () => {
  const c = entryCard();
  const marked = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => ({ status: 'marked', ids }) }, { onMarked: (cards) => marked.push(cards) });
  await c.open.click();
  tick(c, 0);
  tick(c, 1);
  await c.action.click();
  assert.strictEqual(c.head.textContent, 'You’re saying these 2 are yours:');
  await c.yes.click();
  assert.deepStrictEqual(marked, [[c.card]]);
});

test('Back returns to the list, and Escape closes the panel', async () => {
  const c = entryCard();
  MarkFlow.attach(c.root, { markMine: async () => { throw new Error('must not send'); } });
  await c.open.click();
  tick(c, 0);
  await c.action.click();
  await c.back.click();
  assert.strictEqual(c.pick.hidden, false);
  assert.strictEqual(c.confirm.hidden, true);
  await c.action.click();
  (c.root.listeners.keydown || []).forEach((fn) => fn({ key: 'Escape', target: c.yes }));
  assert.strictEqual(c.panel.hidden, true);
  await c.yes.click();
  assert.strictEqual(c.status.hidden, true, 'a closed confirmation sends nothing');
});

test('a refused answer says so and offers the button again', async () => {
  const c = entryCard();
  MarkFlow.attach(c.root, { markMine: async () => ({ status: 'refused', message: 'It changed since the checkup.' }) });
  await c.open.click();
  tick(c, 0);
  await c.action.click();
  await c.yes.click();
  assert.match(c.status.innerHTML, /We couldn’t mark this one\./);
  assert.strictEqual(c.open.hidden, false);
  assert.strictEqual(c.done.hidden, true);
});

test('keys the panel never showed are ignored', async () => {
  const c = entryCard({ selectable: [ID_1] });
  const sent = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => { sent.push(ids); return { status: 'marked', ids }; } });
  await c.open.click();
  c.boxes[0].setAttribute('data-cl-key', ID_2); // something rewrote the row
  tick(c, 0);
  await c.action.click();
  assert.strictEqual(c.confirm.hidden, true);
  await c.yes.click();
  assert.deepStrictEqual(sent, []);
});

test('undo on one row removes only that mark', async () => {
  const c = entryCard();
  const sent = [];
  MarkFlow.attach(c.root, { unmarkMine: async (ids) => { sent.push(ids); return { status: 'removed', ids }; } });
  const btn = c.doneRows[0].querySelector('[data-unmark-item]');
  await btn.click();
  assert.deepStrictEqual(sent, [[ID_1]]);
  assert.strictEqual(btn.hidden, true);
  assert.match(c.doneRows[0].querySelector('[data-unmark-item-status]').textContent, /No longer marked as yours/);
});

// --- beyond the brief: rows only the whole list can mark ---------------------

const NULL_ROW = { key: 'com.example.gone', label: 'Gone', detail: 'com.example.gone', id: null, monitoring: true };

test('a row with no id leaves a way to mark the whole list, with the full list and the warnings', () => {
  const html = MarkFlow.markControlsHtml(finding(entries([...ROWS, NULL_ROW])));
  assert.match(html, /data-mark-alone="1"/);
  assert.ok(html.includes(MarkFlow.WHOLE_BUTTON));
  const whole = html.slice(html.indexOf('data-mark-whole-confirm'));
  assert.match(whole, /Yes, the whole list is mine/);
  assert.ok(whole.includes(MarkFlow.ONLY_IF_YOURS) && whole.includes(MarkFlow.COULD_WATCH));
  assert.ok(whole.includes('The checkup will stop warning you about this list of apps.'));
  assert.ok(whole.includes('com.example.gone'), 'the whole list names every row');
  // Without such a row there is no whole-list answer at all.
  const plain = MarkFlow.markControlsHtml(finding(entries(ROWS)));
  assert.ok(!plain.includes('data-mark-whole-confirm') && !plain.includes('data-mark-confirm'));
});

test('only unverified rows: the panel still opens, every box disabled, the whole list offered', () => {
  const html = MarkFlow.markControlsHtml(finding(entries([{ ...ROWS[0], id: null }, { ...ROWS[1], id: null }])));
  assert.match(html, /data-mark-open>I know these apps — they’re mine</);
  assert.strictEqual((html.match(/data-cl-key="none-\d" disabled>/g) || []).length, 2);
  assert.ok(html.includes(MarkFlow.WHOLE_BUTTON));
});

test('the game theme and a per-finding scope reach the checklist', () => {
  const html = MarkFlow.markControlsHtml(finding(entries(ROWS)), { theme: 'game' });
  assert.match(html, /checklist--game/);
  const ids = (h) => (h.match(/id="([^"]+)"/g) || []);
  const other = MarkFlow.markControlsHtml(finding({ ...entries(ROWS), code: 'security.app_permissions.screen_recording_access' }));
  assert.notDeepStrictEqual(ids(html), ids(other));
});

test('a stale row says it changed', () => {
  const html = MarkFlow.markControlsHtml(finding(entries([{ ...ROWS[0], stale: true }, ROWS[1]])));
  assert.ok(html.includes(MarkFlow.STALE_ROW));
});

function wholeCard() {
  const c = entryCard();
  c.card.setAttribute('data-mark-alone', '1');
  const wholeOpen = c.pick.add('button', { 'data-mark-whole-open': '' });
  const whole = c.panel.add('div', { 'data-mark-whole-confirm': '', hidden: '' });
  const wholeYes = whole.add('button', { 'data-mark-confirm': '' });
  const wholeBack = whole.add('button', { 'data-mark-items-back': '' });
  return { ...c, wholeOpen, whole, wholeYes, wholeBack };
}

test('the whole-list answer asks first, and Back returns to the checklist', async () => {
  const c = wholeCard();
  const sent = [];
  const marked = [];
  MarkFlow.attach(c.root, { markMine: async (...a) => { sent.push(a); return { status: 'marked', ids: [CARD] }; } },
    { onMarked: (cards) => marked.push(cards) });
  await c.wholeYes.click();
  assert.deepStrictEqual(sent, [], 'a closed panel sends nothing');
  await c.open.click();
  await c.wholeYes.click();
  assert.deepStrictEqual(sent, [], 'not from the checklist view');
  await c.wholeOpen.click();
  assert.strictEqual(c.pick.hidden, true);
  assert.strictEqual(c.whole.hidden, false);
  await c.wholeBack.click();
  assert.strictEqual(c.pick.hidden, false);
  assert.strictEqual(c.whole.hidden, true);
  await c.wholeOpen.click();
  await c.wholeYes.click();
  assert.deepStrictEqual(sent, [[CARD]]);
  assert.deepStrictEqual(marked, [[c.card]]);
});

test('marking every box while a row is only markable with the whole list keeps the card listed', async () => {
  const c = wholeCard();
  const marked = [];
  MarkFlow.attach(c.root, { markMine: async (id, ids) => ({ status: 'marked', ids }) }, { onMarked: (cards) => marked.push(cards) });
  await c.open.click();
  tick(c, 0);
  tick(c, 1);
  await c.action.click();
  await c.yes.click();
  assert.match(c.status.innerHTML, /The other 1 keep their warning\./);
  assert.deepStrictEqual(marked, []);
});

test('undo on one row tells the page, so a cleared card comes back', async () => {
  const c = entryCard();
  const unmarked = [];
  const results = [];
  MarkFlow.attach(c.root, { unmarkMine: async (ids) => ({ status: 'removed', ids }) },
    { onUnmarked: (cards) => unmarked.push(cards), onResult: (r) => results.push(r.kind) });
  await c.doneRows[1].querySelector('[data-unmark-item]').click();
  assert.deepStrictEqual(unmarked, [[c.card]]);
  assert.deepStrictEqual(results, ['removed']);
});

test('a refused undo on one row offers the button again and tells nobody', async () => {
  const c = entryCard();
  const unmarked = [];
  MarkFlow.attach(c.root, { unmarkMine: async () => ({ status: 'refused', error: 'not_allowed' }) },
    { onUnmarked: (cards) => unmarked.push(cards) });
  const btn = c.doneRows[0].querySelector('[data-unmark-item]');
  await btn.click();
  assert.strictEqual(btn.hidden, false);
  assert.deepStrictEqual(unmarked, []);
});

test('Cancel forgets the ticks: the panel opens again with nothing ticked', async () => {
  const c = entryCard();
  MarkFlow.attach(c.root, { markMine: async () => { throw new Error('must not send'); } });
  await c.open.click();
  tick(c, 0);
  await c.cancel.click();
  assert.deepStrictEqual(c.boxes.map((b) => b.checked), [false, false]);
  await c.open.click();
  await c.action.click();
  assert.strictEqual(c.confirm.hidden, true, 'nothing ticked, nothing to confirm');
});
