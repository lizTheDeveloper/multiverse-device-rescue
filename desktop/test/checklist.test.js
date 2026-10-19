// The one checklist: real checkboxes, unticked, select all / none, a live
// count, and a primary button that says what it will do and to how many.
const test = require('node:test');
const assert = require('node:assert');
const Checklist = require('../renderer/checklist.js');
const { createDocument } = require('./mini-dom.js');

const MARK = { id: 'mark', verb: 'Mark', noun: ['app', 'apps'], suffix: 'as mine', min: 1 };
const items = (n) => Array.from({ length: n }, (_, i) => ({ key: `k${i}`, label: `App ${i}`, detail: `com.example.app${i}` }));

test('real checkboxes with real labels, inside a fieldset with a legend', () => {
  const html = Checklist.html({ id: 'apps-1', legend: 'Apps with Accessibility access', items: items(2), actions: [MARK], selectAll: true });
  assert.match(html, /<fieldset class="checklist checklist--plain" data-cl-list="apps-1"/);
  assert.match(html, /<legend class="checklist__legend">Apps with Accessibility access<\/legend>/);
  assert.strictEqual((html.match(/<input type="checkbox"/g) || []).length, 2);
  assert.match(html, /<input type="checkbox" id="apps-1-item-0" class="checklist__box" data-cl-item data-cl-key="k0">/);
  assert.match(html, /<label for="apps-1-item-0" class="checklist__label">/);
  assert.match(html, /<code class="checklist__detail">com\.example\.app0<\/code>/);
  assert.match(html, /data-cl-all>Select all<\/button>/);
  assert.match(html, /data-cl-none>Select none<\/button>/);
});

test('everything starts unticked, even if a caller asks otherwise', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: [{ key: 'a', label: 'A', checked: true }], actions: [MARK] });
  assert.ok(!/\bchecked\b/.test(html));
});

test('the count and the button start at zero, and the button says so', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: items(3), actions: [MARK] });
  assert.match(html, /<p class="checklist__count" data-cl-count aria-live="polite">0 of 3 selected<\/p>/);
  assert.match(html, /data-cl-action="mark"[^>]*disabled>Select at least one<\/button>/);
});

test('the primary button names the action and the number', () => {
  assert.strictEqual(Checklist.actionLabel(MARK, 3), 'Mark 3 apps as mine');
  assert.strictEqual(Checklist.actionLabel(MARK, 1), 'Mark 1 app as mine');
  assert.strictEqual(Checklist.actionLabel({ id: 'off', verb: 'Turn off', noun: ['startup item', 'startup items'] }, 2), 'Turn off 2 startup items');
  assert.strictEqual(Checklist.actionLabel(MARK, 0), 'Select at least one');
  assert.strictEqual(Checklist.countText(2, 7), '2 of 7 selected');
});

test('text is escaped and control characters are shown, not obeyed', () => {
  const html = Checklist.html({ id: 'x"><b', legend: '<i>L</i>', items: [{ key: 'a"b', label: 'Zoom‮exe.', note: '<b>n</b>' }], actions: [MARK] });
  assert.ok(!html.includes('<i>L</i>') && !html.includes('<b>n</b>'));
  assert.ok(!html.includes('‮'));
  assert.match(html, /Zoom\[U\+202E\]exe\./);
  assert.match(html, /data-cl-key="a&quot;b"/);
  assert.match(html, /data-cl-list="x___b"/);
});

test('a disabled row is shown, with its note, and not counted', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: [{ key: 'a', label: 'A' }, { key: 'b', label: 'B', disabled: true, note: 'Can’t be checked on its own' }], actions: [MARK], selectAll: true });
  assert.match(html, /data-cl-key="b" disabled>/);
  assert.match(html, /<span class="checklist__note">Can’t be checked on its own<\/span>/);
  assert.match(html, /0 of 1 selected/);
  assert.ok(!html.includes('data-cl-all'), 'no "Select all" for a single choosable row');
});

test('long lists show 50, then "Show all", and the count counts all of them', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: items(60), actions: [MARK], selectAll: true });
  assert.strictEqual((html.match(/data-cl-more hidden/g) || []).length, 10);
  assert.match(html, /data-cl-more-show>Show all 60<\/button>/);
  assert.match(html, /0 of 60 selected/);
});

test('the game theme is a class, nothing else', () => {
  const html = Checklist.html({ id: 'x', legend: 'L', items: items(1), actions: [MARK], theme: 'game' });
  assert.match(html, /class="checklist checklist--game"/);
});

// --- behaviour, on a small DOM built the way html() lays it out --------------

function build(keys, { disabled = [] } = {}) {
  const doc = createDocument();
  const root = doc.body.add('div');
  const list = root.add('fieldset', { 'data-cl-list': 'apps-1' });
  const boxes = keys.map((k) => {
    const row = list.add('li');
    const box = row.add('input', { 'data-cl-item': '', 'data-cl-key': k });
    box.checked = false;
    box.disabled = disabled.includes(k);
    box.focus = () => { doc.activeElement = box; };
    return box;
  });
  const all = list.add('button', { 'data-cl-all': '' });
  const none = list.add('button', { 'data-cl-none': '' });
  const count = list.add('p', { 'data-cl-count': '' });
  const action = list.add('button', { 'data-cl-action': 'mark', 'data-cl-verb': 'Mark', 'data-cl-one': 'app',
    'data-cl-many': 'apps', 'data-cl-suffix': 'as mine', 'data-cl-min': '1' });
  return { doc, root, list, boxes, all, none, count, action };
}

const fire = (root, type, event) => (root.listeners[type] || []).map((fn) => fn(event));

test('ticking updates the count and the button; select all and none skip disabled rows', async () => {
  const d = build(['a', 'b', 'c'], { disabled: ['c'] });
  const seen = [];
  Checklist.attach(d.root, { onAction: (listId, actionId, keys) => seen.push([listId, actionId, keys]) });
  d.boxes[0].checked = true;
  fire(d.root, 'change', { target: d.boxes[0] });
  assert.strictEqual(d.count.textContent, '1 of 2 selected');
  assert.strictEqual(d.action.textContent, 'Mark 1 app as mine');
  assert.strictEqual(d.action.disabled, false);
  await d.all.click();
  assert.deepStrictEqual(d.boxes.map((b) => b.checked), [true, true, false]);
  assert.strictEqual(d.action.textContent, 'Mark 2 apps as mine');
  await d.action.click();
  assert.deepStrictEqual(seen, [['apps-1', 'mark', ['a', 'b']]]);
  await d.none.click();
  assert.deepStrictEqual(d.boxes.map((b) => b.checked), [false, false, false]);
  assert.strictEqual(d.action.disabled, true);
  assert.strictEqual(d.action.textContent, 'Select at least one');
  await d.action.click();
  assert.strictEqual(seen.length, 1, 'nothing is sent with nothing ticked');
});

test('arrow keys, Home and End move between rows', () => {
  const d = build(['a', 'b', 'c']);
  Checklist.attach(d.root, {});
  let prevented = 0;
  const key = (box, k) => fire(d.root, 'keydown', { key: k, target: box, preventDefault: () => { prevented += 1; } });
  key(d.boxes[0], 'ArrowDown');
  assert.strictEqual(d.doc.activeElement, d.boxes[1]);
  key(d.boxes[1], 'End');
  assert.strictEqual(d.doc.activeElement, d.boxes[2]);
  key(d.boxes[2], 'ArrowDown');
  assert.strictEqual(d.doc.activeElement, d.boxes[2], 'stays on the last row');
  key(d.boxes[2], 'Home');
  assert.strictEqual(d.doc.activeElement, d.boxes[0]);
  key(d.boxes[0], 'x');
  assert.strictEqual(prevented, 4, 'other keys are left alone');
  assert.strictEqual(Checklist.moveIndex(0, 3, 'ArrowUp'), 0);
  assert.strictEqual(Checklist.moveIndex(-1, 3, 'ArrowDown'), null);
});

test('preserveFocus puts focus back on the same row after a redraw', () => {
  const d = build(['a', 'b']);
  d.doc.activeElement = d.boxes[1];
  let again;
  Checklist.preserveFocus(d.root, () => {
    d.root.removeChild(d.list);
    again = build(['a', 'b']);
    // The redraw replaces the elements; the new ones live in the same root.
    d.root.appendChild(again.list);
    again.boxes.forEach((b) => { b.focus = () => { d.doc.activeElement = b; }; });
  });
  assert.strictEqual(d.doc.activeElement, again.boxes[1]);
  assert.strictEqual(again.boxes[1].checked, false, 'the selection itself starts again');
});

test('preserveFocus does nothing when focus was elsewhere', () => {
  const d = build(['a']);
  d.doc.activeElement = null;
  let ran = false;
  Checklist.preserveFocus(d.root, () => { ran = true; });
  assert.ok(ran);
});
