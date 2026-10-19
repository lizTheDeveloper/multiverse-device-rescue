const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const { page, monitoring } = require('./page-harness.js');
const { forbiddenWrites, FORBIDDEN_ON_DISK, recordingStore } = require('./disk-words.js');
const StealthAftercare = require('../renderer/stealth-aftercare.js');

const KEY = 'device-rescue.display';
const SEED = 'device-rescue.city-seed';
const note = (p) => p.byId('aftercare-card').innerHTML;
const buttons = (p) => p.byId('aftercare-card').kids.map((b) => b.dataset.aftercare);
// Every key the page wrote, once each.
const keysWritten = (p) => [...new Set(p.storage.writes.map(([k]) => k))].sort();

test('"Yes, that’s part of it" shows the note on what city mode does, before anything starts', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('wifi');
  p.answer('yes');
  assert.deepStrictEqual(p.shown(), ['aftercare']);
  assert.deepStrictEqual(p.calls.scans, [], 'no scan yet');
  assert.deepStrictEqual(p.calls.game, [], 'the city isn’t opened yet');
  assert.match(note(p), /Thank you for telling us/);
  assert.strictEqual(p.sandbox.document.activeElement, p.byId('aftercare-title'), 'focus on the heading');
  assert.deepStrictEqual(buttons(p), ['go', 'visit']);
  p.aftercare('go');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(note(p), '', 'the note’s wording doesn’t stay in the hidden section');
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
  assert.deepStrictEqual(p.calls.scans, ['home_network_intrusion']);
});

test('the "watching me" worry shows it too, without the question', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.deepStrictEqual(p.shown(), ['aftercare']);
  assert.deepStrictEqual(p.calls.scans, []);
  p.aftercare('go');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.deepStrictEqual(p.calls.game, ['newWorry', 'showBoss']);
});

test('"No" and "I’d rather not say" never show it', () => {
  for (const answer of ['no', 'rather-not']) {
    const p = page({ store: {} });
    p.byId('btn-get-started').click();
    p.pick('wifi');
    p.answer(answer);
    assert.ok(!p.shown().includes('aftercare'), answer);
    assert.strictEqual(p.byId('aftercare-card').innerHTML, '', answer);
  }
});

test('the follow-up after monitoring software: "No, I don’t" shows it; "Yes, I know about it" doesn’t', async () => {
  for (const [answer, shows] of [['unknown', true], ['known', false], ['rather-not', false]]) {
    const p = page({ store: { [KEY]: 'standard' } });
    p.byId('btn-get-started').click();
    p.pick('unsure');
    await p.finish(monitoring);
    p.answer(answer);
    assert.strictEqual(p.shown().includes('aftercare'), shows, answer);
    if (shows) {
      assert.ok(!p.calls.game.includes('scanDone'), 'the results wait behind the note');
      p.aftercare('go');
      assert.ok(p.calls.game.includes('scanDone'));
      assert.deepStrictEqual(p.shown(), ['city']);
    }
  }
});

test('shown once per switch: not on launch in city mode, nor on a later worry, nor when it already was city', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  p.aftercare('go');
  p.sandbox.RescueHost.leaveGame();
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.ok(!p.shown().includes('aftercare'), 'a second worry: no note');
  // "Something changed?" → Yes, already city: no switch, no note.
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  p.answer('yes');
  assert.ok(!p.shown().includes('aftercare'));
  // Launching in city mode opens the city, not the note.
  const again = page({ store: { [KEY]: 'city' } });
  assert.deepStrictEqual(again.shown(), ['city']);
});

test('switching away and back shows it again (a new switch)', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.sandbox.RescueHost.leaveGame();
  p.byId('btn-start-over').click();
  p.byId('btn-get-started').click();
  p.byId('btn-something-changed').click();
  p.answer('no');
  assert.ok(!p.shown().includes('aftercare'));
  p.byId('btn-something-changed').click();
  p.answer('yes');
  assert.deepStrictEqual(p.shown(), ['aftercare']);
  p.aftercare('go');
  assert.deepStrictEqual(p.shown(), ['city'], 'from the worry screen, on into the city');
  assert.strictEqual(p.calls.last.name, 'showHome');
});

test('Esc on the note goes straight to the deck, with nothing started', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.answer('yes');
  p.key('Escape');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(note(p), '', 'Esc clears the note too');
  assert.deepStrictEqual(p.calls.game, ['showHome']);
  assert.strictEqual(p.calls.last.args[0].id, 'hacked', 'the worry is kept for the deck’s sweep');
  assert.deepStrictEqual(p.calls.scans, []);
  // The note is gone: a second Esc and its buttons do nothing more.
  p.key('Escape');
  assert.deepStrictEqual(p.calls.game, ['showHome']);
});

test('"Show me … first" opens the generated district over the deck', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.match(note(p), /Show me Pier 9 first/);
  p.aftercare('visit');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.deepStrictEqual(p.calls.game, ['showHome', 'openHelpPlace']);
  assert.deepStrictEqual(p.calls.scans, []);
});

test('the note names the install’s own district and how to get there', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('watched');
  const html = note(p);
  assert.match(html, /a place in the city called Pier 9\. Its tile is on the city, under ALSO IN TOWN\./);
  assert.match(html, /In Pier 9, press Esc to jump straight back to the game\./);
  assert.match(html, /“Something changed\?” in Pier 9/);
});

test('the game not ready: no name to show and no visit button, and the note still says how to get there', () => {
  const p = page({ store: {}, ready: false });
  p.byId('btn-get-started').click();
  p.pick('watched');
  assert.deepStrictEqual(p.shown(), ['aftercare']);
  assert.deepStrictEqual(buttons(p), ['go']);
  assert.match(note(p), /Help and quiet next steps are in a place in the city\. Its tile is on the city, under ALSO IN TOWN\./);
  p.key('Escape');
  assert.deepStrictEqual(p.shown(), ['scan'], 'without the game, on to the scan screen as before');
});

test('it is help content: it may say what the city never says, as text only, and nothing about it is stored', () => {
  const p = page({ store: {} });
  p.byId('btn-get-started').click();
  p.pick('wifi');
  p.answer('yes');
  const html = note(p);
  assert.match(html, /advocate/);
  assert.match(html, /National Domestic Violence Hotline: 1-800-799-7233\. Text “START” to 88788\./);
  assert.doesNotMatch(html, /href=|tel:|sms:|data-guide/, 'the help line is text, not a link');
  assert.ok(FORBIDDEN_ON_DISK.test(html), 'these are exactly the words kept off disk');
  p.aftercare('visit');
  assert.deepStrictEqual(forbiddenWrites(p.storage), []);
  assert.deepStrictEqual(keysWritten(p), [SEED, KEY].sort(), 'only the display preference and the seed');
  assert.deepStrictEqual(p.storage.writes.filter(([k]) => k === KEY), [[KEY, 'city']]);
});

test('from the district: "What this mode does" shows it again, back to the district after; Esc to the game', () => {
  const p = page({ store: { [KEY]: 'city' } });
  const before = p.storage.writes.length;
  p.sandbox.RescueHost.aboutCityMode();
  assert.deepStrictEqual(p.shown(), ['aftercare']);
  assert.match(note(p), /What this mode does/);
  assert.doesNotMatch(note(p), /Thank you for telling us/);
  assert.deepStrictEqual(buttons(p), ['go']);
  assert.match(note(p), /Back to Pier 9/);
  p.aftercare('go');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(p.calls.last.name, 'openHelpPlace');
  p.sandbox.RescueHost.aboutCityMode();
  p.key('Escape');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(p.calls.last.name, 'backToGame');
  assert.strictEqual(p.storage.writes.length, before, 'nothing written');
});

test('from the district: "Something changed?" asks again, then back to the district (or the game, in standard)', () => {
  const p = page({ store: { [KEY]: 'city' } });
  p.sandbox.RescueHost.somethingChanged();
  assert.deepStrictEqual(p.shown(), ['question']);
  p.answer('back');
  assert.strictEqual(p.calls.last.name, 'openHelpPlace');
  p.sandbox.RescueHost.somethingChanged();
  p.answer('no');
  assert.strictEqual(p.storage.getItem(KEY), 'standard');
  assert.deepStrictEqual(p.shown(), ['city']);
  assert.strictEqual(p.calls.last.name, 'backToGame');
});

test('the copy: short, calm, no time words, and the help line word for word from the Six Roses guide', () => {
  const six = fs.readFileSync(path.join(__dirname, 'fixtures', 'six-roses-excerpt.txt'), 'utf8');
  assert.ok(six.includes('National Domestic Violence Hotline: 1-800-799-7233'));
  assert.ok(six.includes('Text "START" to 88788'));
  for (const again of [false, true]) {
    const c = StealthAftercare.copy({ place: 'Pier 9', again });
    const all = [c.title, c.lede, ...c.points, c.help, c.go, c.visit, c.esc].join(' ');
    assert.ok(c.points.length >= 3 && c.points.length <= 5);
    assert.doesNotMatch(all, /\b(now|today|tonight|minutes?|hours?|days?|soon|later|immediately|urgent|danger|warning|hacked)\b/i);
    assert.ok(all.split(/\s+/).length < 190, 'a few short lines, not a wall');
  }
  assert.strictEqual(StealthAftercare.due('standard', 'city'), true);
  assert.strictEqual(StealthAftercare.due(null, 'city'), true);
  assert.strictEqual(StealthAftercare.due('city', 'city'), false);
  assert.strictEqual(StealthAftercare.due('city', 'standard'), false);
});

test('the note is escaped', () => {
  const html = StealthAftercare.html({ place: '<img src=x>' }, (v) => String(v).replace(/</g, '&lt;'));
  assert.doesNotMatch(html, /<img/);
});

// The controller's side: the real generated name, and the district's two quiet buttons.
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
async function controller(mode) {
  const { createController } = await game('controller.js');
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); },
    querySelector: () => ({ focus() {} }), querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const host = { about: 0, changed: 0 };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) }, addEventListener() {},
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' }, MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode, citySeed: () => 424242, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {},
      aboutCityMode() { host.about += 1; }, somethingChanged() { host.changed += 1; } },
    rescue: { recheckModule: async () => ({ ok: false }), openGuide: async () => true },
  };
  const storage = recordingStore();
  const ctl = createController({ win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await new Promise((r) => setTimeout(r, 0));
  const click = (attrs) => clicks.forEach((fn) => fn({ target: { closest: () => ({ getAttribute: (k) => (k in attrs ? attrs[k] : null) }) } }));
  return { ctl, frame, click, host, storage };
}

test('the controller gives the install’s real district name, and opens the district on request', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await controller('city');
  assert.strictEqual(t.ctl.helpPlace(), pickDistrict(424242).name);
  t.ctl.showHome({ id: 'city', title: 'Take back the city' });
  assert.strictEqual(t.ctl.openHelpPlace(), true);
  assert.match(t.frame.innerHTML, /id="side-title"/);
  assert.match(t.frame.innerHTML, /data-act="side-about-mode">WHAT THIS MODE DOES</);
  assert.match(t.frame.innerHTML, /data-act="side-change">SOMETHING CHANGED\?</);
  t.click({ 'data-act': 'side-about-mode' });
  t.click({ 'data-act': 'side-change' });
  assert.deepStrictEqual([t.host.about, t.host.changed], [1, 1]);
  t.ctl.backToGame();
  assert.doesNotMatch(t.frame.innerHTML, /id="side-title"/);
  t.click({ 'data-act': 'side-about-mode' });
  assert.strictEqual(t.host.about, 1, 'only from the district');
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('standard mode: no name, and the district doesn’t open', async () => {
  const t = await controller('standard');
  assert.strictEqual(t.ctl.helpPlace(), '');
  assert.strictEqual(t.ctl.openHelpPlace(), false);
});
