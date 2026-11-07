const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const DisplayPrefs = require('../renderer/display-prefs.js');
const { recordingStore } = require('./disk-words.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);

test('the sweep is said once per quarter, never on a redraw, and never before it knows the total', async () => {
  const { sweepLine } = await game('a11y.js');
  assert.deepStrictEqual(sweepLine({ index: 3, total: 0 }, 0), { text: '', said: 0 });
  assert.deepStrictEqual(sweepLine(null, 0), { text: '', said: 0 });
  const said = [];
  let q = 0;
  for (let i = 0; i <= 200; i += 1) {
    const r = sweepLine({ index: i, total: 200 }, q);
    q = r.said;
    if (r.text) said.push(r.text);
  }
  assert.deepStrictEqual(said, ['Checkup 25% done.', 'Checkup 50% done.', 'Checkup 75% done.']);
  // a jump straight past two quarters says only the latest
  assert.deepStrictEqual(sweepLine({ index: 160, total: 200 }, 0), { text: 'Checkup 75% done.', said: 3 });
});

test('the end of a sweep: counts of real signals only, and how many are new', async () => {
  const { sweepDoneLine } = await game('a11y.js');
  const sig = (id, severity, kind = 'real') => ({ id, severity, kind, title: `secret title ${id}` });
  const now = [sig('a', 'critical'), sig('b', 'warning'), sig('c', 'warning'), sig('d', 'info'), sig('x', 'critical', 'drill')];
  const first = sweepDoneLine(now, []);
  assert.strictEqual(first, 'Checkup finished. 1 critical signal and 2 warnings to sort.');
  assert.doesNotMatch(first, /secret title/);
  assert.strictEqual(sweepDoneLine(now, [sig('a', 'critical'), sig('d', 'info')]),
    'Checkup finished. 1 critical signal and 2 warnings to sort. 2 new ones since the last checkup.');
  assert.strictEqual(sweepDoneLine(now, now), 'Checkup finished. 1 critical signal and 2 warnings to sort.');
  assert.strictEqual(sweepDoneLine([sig('d', 'info')], []), 'Checkup finished. Nothing critical or warning to sort.');
  assert.strictEqual(sweepDoneLine(undefined, undefined), 'Checkup finished. Nothing critical or warning to sort.');
});

// Just enough of an element for fixRcControls and focusScreenHeading.
function el(tagName, attrs = {}, text = '', parent = null) {
  const e = { tagName, attrs: { ...attrs }, textContent: text, parentElement: parent, focused: 0,
    hasAttribute: (k) => k in e.attrs, getAttribute: (k) => (k in e.attrs ? e.attrs[k] : null),
    setAttribute: (k, v) => { e.attrs[k] = String(v); }, focus: () => { e.focused += 1; } };
  return e;
}
const rootOf = (all) => ({
  querySelectorAll: (sel) => (sel === 'img' ? all.filter((e) => e.tagName === 'IMG') : all.filter((e) => 'data-action' in e.attrs)),
  querySelector: (sel) => all.find((e) => (sel === '[data-landing]' ? 'data-landing' in e.attrs : e.tagName === sel.toUpperCase())) || null,
});

test('Reclaim City’s span buttons get a role and a Tab stop; an account switch says which and whether it is on', async () => {
  const { fixRcControls } = await game('a11y.js');
  const row = el('DIV', {}, 'Do you have a Gmail account?   ON');
  const toggle = el('SPAN', { 'data-action': 'toggle-account' }, 'ON', row);
  const off = el('SPAN', { 'data-action': 'toggle-account' }, 'OFF', el('DIV', {}, ' Do you have a Yahoo account? OFF '));
  const dismiss = el('SPAN', { 'data-action': 'dismiss-intro' }, 'DISMISS');
  const already = el('DIV', { 'data-action': 'x', role: 'button', tabindex: '-1' }, 'kept');
  const link = el('A', { 'data-action': 'mission-step', href: '#/x' }, 'START');
  const img = el('IMG', { src: 'a.png' });
  const named = el('IMG', { src: 'b.png', alt: 'Scout' });
  assert.strictEqual(fixRcControls(rootOf([toggle, off, dismiss, already, link, img, named])), 4);
  assert.deepStrictEqual([toggle.attrs.role, toggle.attrs.tabindex, toggle.attrs['aria-pressed']], ['button', '0', 'true']);
  assert.strictEqual(toggle.attrs['aria-label'], 'Do you have a Gmail account?');
  assert.deepStrictEqual([off.attrs['aria-pressed'], off.attrs['aria-label']], ['false', 'Do you have a Yahoo account?']);
  assert.deepStrictEqual([dismiss.attrs.role, dismiss.attrs.tabindex], ['button', '0']);
  assert.deepStrictEqual([already.attrs.role, already.attrs.tabindex], ['button', '-1']);
  assert.ok(!('role' in link.attrs) && !('tabindex' in link.attrs));
  assert.deepStrictEqual([img.attrs.alt, named.attrs.alt], ['', 'Scout']);
  assert.strictEqual(fixRcControls(null), 0);
  assert.strictEqual(fixRcControls({}), 0);
});

test('a new screen focuses its own title, else its h1, without adding a Tab stop', async () => {
  const { focusScreenHeading } = await game('a11y.js');
  const h1 = el('H1', {}, 'RECLAIM CITY');
  const title = el('H2', { 'data-landing': '' }, 'The Gatehouse');
  assert.strictEqual(focusScreenHeading(rootOf([h1, title])), true);
  assert.deepStrictEqual([title.focused, h1.focused, title.attrs.tabindex], [1, 0, '-1']);
  const onlyH1 = el('H1', {}, 'THE TRAINING GROUNDS');
  assert.strictEqual(focusScreenHeading(rootOf([onlyH1])), true);
  assert.strictEqual(onlyH1.focused, 1);
  const own = el('H2', { tabindex: '-1', 'data-landing': '' }, 'x');
  focusScreenHeading(rootOf([own]));
  assert.strictEqual(own.attrs.tabindex, '-1');
  assert.strictEqual(focusScreenHeading(rootOf([])), false);
  assert.strictEqual(focusScreenHeading(null), false);
});

test('SETTINGS: every choice is a labelled radio in a named group, the current ones checked', async () => {
  const { displayPanelHtml } = await game('display-panel.js');
  const html = displayPanelHtml(DisplayPrefs, { textSize: 'large', font: 'plain', motion: 'system' });
  assert.match(html, /<dialog class="display-panel" aria-labelledby="display-title">/);
  assert.match(html, /<h2 id="display-title">/);
  for (const legend of ['Text size', 'Letters', 'Motion']) assert.match(html, new RegExp(`<legend>${legend}</legend>`));
  assert.strictEqual((html.match(/type="radio"/g) || []).length, 7);
  assert.strictEqual((html.match(/ checked/g) || []).length, 3);
  assert.match(html, /name="textSize" value="large" checked/);
  assert.match(html, /name="font" value="plain" checked/);
  assert.match(html, /name="motion" value="system" checked/);
  assert.match(html, /<label class="display-choice"><input type="radio" name="textSize" value="normal"> <span>Normal<\/span><\/label>/);
  assert.match(html, /data-display="open" aria-haspopup="dialog"><span aria-hidden="true">⚙<\/span> SETTINGS</);
  assert.doesNotMatch(html, /\bmin(ute)?s?\b|second/i);
  assert.doesNotMatch(html, /How much detail/, 'no level group without a level');
});

test('SETTINGS holds the detail level too: one more named group, the current level checked', async () => {
  const { displayPanelHtml } = await game('display-panel.js');
  const html = displayPanelHtml(DisplayPrefs, { textSize: 'normal', font: 'city', motion: 'system' }, 'technical');
  assert.match(html, /<legend>How much detail<\/legend>[\s\S]*<legend>Text size<\/legend>/, 'detail comes first');
  assert.strictEqual((html.match(/type="radio"/g) || []).length, 10);
  assert.match(html, /name="level" value="technical" checked/);
  assert.match(html, /name="level" value="new"> <span>I’m new to this<\/span>/);
  assert.match(html, /not what is checked\. Every fix still asks first/);
});

test('SETTINGS: picking a level hands it to the city; text choices are stored as before', async () => {
  const { attachDisplayPanel } = await game('display-panel.js');
  const fake = () => {
    const on = {};
    return { handlers: on, addEventListener: (ev, f) => { on[ev] = f; }, focus() {}, close() {}, showModal() {}, querySelectorAll: () => radios };
  };
  const radios = ['new', 'everyday', 'technical'].map((value) => ({ name: 'level', value, checked: false }));
  const dialog = fake();
  const parts = { dialog, '[data-display="open"]': fake(), '[data-display="close"]': fake() };
  const bar = { innerHTML: '', querySelector: (q) => parts[q] || null };
  const store = recordingStore();
  const picked = [];
  let level = 'everyday';
  assert.ok(attachDisplayPanel({ bar, host: null, storage: store, win: { DisplayPrefs }, level: () => level, setLevel: (v) => picked.push(v) }));
  assert.match(bar.innerHTML, /name="level" value="everyday" checked/);
  dialog.handlers.change({ target: { type: 'radio', name: 'level', value: 'technical' } });
  dialog.handlers.change({ target: { type: 'radio', name: 'level', value: 'expert' } });
  assert.deepStrictEqual(picked, ['technical'], 'an unknown level never reaches the city');
  // Opening reads the level afresh (the first-run cards can change it).
  level = 'new';
  parts['[data-display="open"]'].handlers.click();
  assert.deepStrictEqual(radios.map((r) => r.checked), [true, false, false]);
  dialog.handlers.change({ target: { type: 'radio', name: 'textSize', value: 'large' } });
  assert.strictEqual(DisplayPrefs.read(store).textSize, 'large');
});

test('applying: letters and motion go on the host, text size zooms the window by a known factor', async () => {
  const { applyDisplayPrefs } = await game('display-panel.js');
  const host = el('DIV');
  const zooms = [];
  applyDisplayPrefs(DisplayPrefs, host, { textSize: 'larger', font: 'plain', motion: 'less' }, { setZoom: (f) => zooms.push(f) });
  assert.deepStrictEqual([host.attrs['data-font'], host.attrs['data-motion'], host.attrs['data-text-size']], ['plain', 'less', 'larger']);
  assert.deepStrictEqual(zooms, [1.5]);
  // no preload, or one that throws: the page just stays at its usual size
  applyDisplayPrefs(DisplayPrefs, host, DisplayPrefs.read(recordingStore()), null);
  applyDisplayPrefs(DisplayPrefs, null, DisplayPrefs.read(recordingStore()), { setZoom: () => { throw new Error('no'); } });
  assert.strictEqual(host.attrs['data-text-size'], 'normal');
});

test('the controller draws SETTINGS and the polite line outside the frame, so redraws leave them alone', () => {
  const src = require('fs').readFileSync(path.join(__dirname, '..', 'renderer', 'game', 'controller.js'), 'utf8');
  assert.match(src, /id="display-bar"><\/div><div class="frame" id="frame"><\/div>'\s*\+ '<div class="sr-only" id="announce" role="status" aria-live="polite">/);
});

test('preload zooms only to the three text sizes', () => {
  const src = require('fs').readFileSync(path.join(__dirname, '..', 'preload.js'), 'utf8');
  const m = /setZoom: \(factor\) => \{ if \((\[[^\]]*\])\.includes\(factor\)\) webFrame\.setZoomFactor\(factor\); \}/.exec(src);
  assert.ok(m, 'setZoom checks its factor');
  assert.deepStrictEqual(JSON.parse(m[1]).sort(), DisplayPrefs.SIZES.map(DisplayPrefs.zoomFor).sort());
});
