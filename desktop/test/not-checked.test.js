// One rule for what wasn't fully checked (renderer/not-checked.js), and the
// Plain list and the city counting the same things from it. The fixtures are
// recorded scans from the UX audit replays, trimmed (full: a real Mac scan;
// errors: six checks that couldn't run, two of them monitoring checks; held:
// monitoring software found), with the home folder renamed.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const NotChecked = require('../renderer/not-checked.js');
const app = require('../renderer/app.js');

const FIXTURES = ['replay-full.json', 'replay-errors.json', 'replay-held.json'];
const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', f), 'utf8'));
const tick = () => new Promise((r) => setTimeout(r, 0));
const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); } }; };

function stub() {
  const listeners = [];
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: () => {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: () => {}, markControlsHtml: () => '' },
    RescueHost: { showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }) },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, click };
}

async function city(doc) {
  const { createController } = await import('../renderer/game/controller.js');
  const t = stub();
  const ctl = createController({ win: t.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  ctl.show(doc, { id: 'unsure' });
  return { ...t, ctl, html: () => t.frame.innerHTML };
}

const num = (html, re) => { const m = re.exec(html); return m ? Number(m[1]) : 0; };
const chip = (html, label) => num(html, new RegExp(`data-act="sev:[a-z]+"[^>]*>${label} (\\d+)<`));
const hud = (html, label) => num(html, new RegExp(`<b>(\\d+)</b> <small>${label}</small>`));

test('the list, the game and the host all use the one rule', async () => {
  const signals = await import('../renderer/game/signals.js');
  const held = await import('../renderer/game/held.js');
  assert.strictEqual(app.isPartlyChecked, NotChecked.isPartlyChecked);
  assert.strictEqual(app.notCheckedSummary, NotChecked.notCheckedSummary);
  assert.strictEqual(app.notCheckedLine, NotChecked.notCheckedLine);
  assert.strictEqual(signals.isPartlyChecked, NotChecked.isPartlyChecked);
  assert.strictEqual(signals.notCheckedSummary, NotChecked.notCheckedSummary);
  assert.strictEqual(signals.notCheckedLine, NotChecked.notCheckedLine);
  assert.strictEqual(held.COULDNT_LOOK, NotChecked.COULDNT_LOOK);
  assert.strictEqual(held.isDetection, NotChecked.isDetection);
  const Q = require('../renderer/quiet-notes.js');
  assert.deepStrictEqual([...NotChecked.NOT_DETECTIONS].sort(), [...Q.NOT_DETECTIONS].sort());
  assert.deepStrictEqual([...NotChecked.MONITORING_MODULES].sort(), [...app.ALWAYS_SAFETY_MODULES].sort());
  // Loaded as a plain script before app.js, so app.js finds it as a global.
  const index = fs.readFileSync(path.join(__dirname, '../renderer/index.html'), 'utf8');
  assert.ok(index.indexOf('src="not-checked.js"') > 0 && index.indexOf('src="not-checked.js"') < index.indexOf('src="app.js"'));
});

test('a monitoring check that couldn’t look counts as one that couldn’t run; an iPhone backup scan not started is its own part', () => {
  const mvt = (code, extra = {}) => ({ name: 'mvt_spyware_scan', category: 'security', status: 'ok', supported: true,
    findings: [{ title: 't', severity: 'info', code }], ...extra });
  const looked = mvt('security.mvt_spyware_scan.mvt_clean_scan');
  const noScanner = mvt('security.mvt_spyware_scan.mvt_not_installed');
  const waiting = mvt('security.mvt_spyware_scan.mvt_scan_available');
  assert.strictEqual(NotChecked.couldntLook(noScanner), true);
  assert.strictEqual(NotChecked.couldntLook(looked), false);
  // Software found: the check did look.
  assert.strictEqual(NotChecked.couldntLook({ ...noScanner, findings: [...noScanner.findings, { title: 'x', severity: 'critical', code: 'security.mvt_spyware_scan.ioc' }] }), false);
  assert.strictEqual(NotChecked.couldntLook({ ...noScanner, name: 'disk_space' }), false, 'only the monitoring checks');
  const g = app.groupFindingsBySeverity({ modules: [noScanner, looked] });
  assert.deepStrictEqual(g.erroredModules, [{ name: 'mvt_spyware_scan', error: NotChecked.COULDNT_LOOK_REASON }]);
  assert.strictEqual(NotChecked.notCheckedSummary({ modules: [noScanner] }).couldntRun, 1);

  // A backup is here and the long scan asks first: not started, neither
  // couldn't-run nor clean. The engine says so (not_started), and older scans
  // are read by the note. The city still shows it as fog (couldntLook).
  for (const m of [waiting, { ...waiting, findings: [], not_started: true }]) {
    assert.strictEqual(NotChecked.notStarted(m), true);
    const parts = NotChecked.notCheckedParts({ modules: [m] });
    assert.deepStrictEqual(parts.notStarted, [{ name: 'mvt_spyware_scan' }]);
    assert.deepStrictEqual(parts.couldntRun, []);
    const sum = NotChecked.notCheckedSummary({ modules: [m] });
    assert.strictEqual(sum.notStarted, 1);
    assert.strictEqual(sum.count, 1, 'never a clean bill of health');
    assert.match(NotChecked.notCheckedLine(sum), /1 check waits for your go-ahead, so this isn’t a clean bill of health/);
  }
  assert.strictEqual(NotChecked.couldntLook(waiting), true, 'the city keeps it as fog');
  assert.strictEqual(NotChecked.notStarted({ ...waiting, findings: [...waiting.findings, { title: 'x', severity: 'critical', code: 'security.mvt_spyware_scan.ioc' }] }), false);
  assert.strictEqual(NotChecked.notStarted({ ...waiting, status: 'error' }), false);
});

for (const file of FIXTURES) {
  test(`${file}: the Plain list, the deck, its chips and a mission’s HUD give the same not-checked counts`, async () => {
    const doc = load(file);
    // Plain: the counts its "couldn't check" section and its top line use.
    const sum = app.notCheckedSummary(doc);
    const g = app.groupFindingsBySeverity(doc);
    assert.deepStrictEqual([g.erroredModules.length, g.unfinishedModules.length, g.partlyChecked.length],
      [sum.couldntRun, sum.unfinished, sum.partly]);
    assert.ok(sum.count > 0, 'every replay has something not fully checked');

    const t = await city(doc);
    const deck = t.html();
    assert.match(deck, /INCOMING SIGNALS/);
    // The deck's note is the list's top line, word for word.
    assert.ok(deck.includes(app.notCheckedLine(sum)), 'the deck says what the list says');
    // COULDN'T CHECK chip: every check that couldn't run, monitoring ones too
    // (unnamed), and the iPhone backup scan waiting for a go-ahead (fog).
    assert.strictEqual(chip(deck, 'COULDN’T CHECK'), sum.couldntRun + sum.notStarted);
    assert.doesNotMatch(deck, />ALL \d/, 'ALL carries no total of its own');
    // TO DO is what's left to sort in the queue: the deck's three chips.
    const todo = chip(deck, 'CRITICAL') + chip(deck, 'WARNING') + chip(deck, 'COULDN’T CHECK');
    assert.ok(todo > 0);
    assert.match(deck, new RegExp(`INCOMING SIGNALS · ${todo} TO DO`), 'the deck says the same TO DO');

    // A mission's HUD: the same COULDN'T CHECK, and the same TO DO.
    const mission = /data-go="(mission:[^"]+)"/.exec(deck) || /data-go="signal:([^"]+)"/.exec(deck);
    assert.ok(mission, 'a mission to open');
    const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
    const { splitHeld } = await import('../renderer/game/held.js');
    const first = findingsToCity(splitHeld(doc).doc).districts.flatMap((d) => d.missions)[0];
    t.click({ 'data-go': `mission:${first.id}` });
    const m = t.html();
    assert.match(m, /class="hud"/);
    assert.strictEqual(hud(m, 'TO DO'), todo);
    hudCouldnt.set(file, { got: hud(m, 'COULDN’T CHECK'), want: sum.couldntRun + sum.notStarted });
  });
}

// The mission HUD's COULDN'T CHECK is the deck's chip: couldn't run plus a
// scan waiting for a go-ahead (game/views/hud.js reads NotChecked.scanCounts).
const hudCouldnt = new Map();
test('the mission HUD’s COULDN’T CHECK matches the deck’s chip (fog includes a scan not started)', () => {
    for (const [file, { got, want }] of hudCouldnt) assert.strictEqual(got, want, file);
  });
