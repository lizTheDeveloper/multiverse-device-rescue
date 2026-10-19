// City mode is the cover: no game screen names a worry, so "I think someone
// is watching me" never shows on screen, alone or with other worries.
// Standard mode keeps the worry's name over the recommended lessons.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { recordingStore } = require('./disk-words.js');
const { SITUATIONS } = require('../renderer/app.js');
const Worries = require('../renderer/worries.js');

const tick = () => new Promise((r) => setTimeout(r, 0));
const GAME_DIR = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
const importLesson = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME_DIR, spec)).href);
const DOC = { schema_version: 1, platform: 'darwin', modules: [{ name: 'remote_login_check', category: 'security', status: 'ok', error: null, supported: true,
  findings: [{ title: 'Remote Login is on', description: 'd', severity: 'warning', category: 'security', data: {} }] }] };

async function setup(mode) {
  const { createController } = await import(pathToFileURL(path.join(GAME_DIR, 'controller.js')).href);
  const { loadLessons } = await import(pathToFileURL(path.join(GAME_DIR, 'training.js')).href);
  const lessons = await loadLessons(importLesson);
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener() {},
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode, citySeed: () => 424242, showList() {}, docChanged: () => true, wantsSafety: () => false,
      startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }), openGuide: async () => true },
  };
  const ctl = createController({ win, storage: recordingStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons, loadDrillBank: async () => [] });
  await tick();
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { ctl, click, html: () => frame.innerHTML };
}

// Every screen the game draws for a worry: training, the sweep, the city, the deck.
async function screensFor(mode, situation) {
  const t = await setup(mode);
  const seen = [];
  t.ctl.showTraining(situation); seen.push(t.html());
  t.ctl.showBoss(); seen.push(t.html());
  t.ctl.scanDone(DOC, situation); await tick(); seen.push(t.html());
  for (const go of ['map', 'training', 'side']) { t.click({ 'data-go': go }); seen.push(t.html()); }
  return seen;
}

const upper = (s) => s.toUpperCase();
const TITLES = SITUATIONS.filter((s) => Worries.CHECKLIST_IDS.includes(s.id)).map((s) => s.title);
const escaped = (s) => s.replace(/&/g, '&amp;');

test('city mode: no game screen names a worry, alone or several together', async () => {
  for (const ids of [['watched'], ['hacked', 'watched'], ['wifi', 'identity']]) {
    const situation = Worries.combine(ids, SITUATIONS);
    for (const html of await screensFor('city', situation)) {
      for (const title of TITLES) {
        assert.ok(!html.includes(escaped(title)) && !html.includes(upper(escaped(title))), `${ids}: ${title}`);
      }
      assert.doesNotMatch(html, /watching me/i);
    }
    const [training] = await screensFor('city', situation);
    assert.match(training, /RECOMMENDED FOR YOU/);
  }
});

test('city mode: the city\u2019s own home keeps its heading', async () => {
  const t = await setup('city');
  t.ctl.showTraining({ id: 'city', title: 'Take back the city' });
  assert.match(t.html(), /RECOMMENDED FOR “TAKE BACK THE CITY”/);
});

test('standard mode keeps the worries’ names over the recommended lessons', async () => {
  const situation = Worries.combine(['hacked', 'wifi'], SITUATIONS);
  const [training] = await screensFor('standard', situation);
  assert.ok(training.includes('RECOMMENDED FOR'), 'heading');
  assert.ok(training.includes(upper(situation.title).split(' AND ')[1].slice(0, 12)), 'names the worries');
});
