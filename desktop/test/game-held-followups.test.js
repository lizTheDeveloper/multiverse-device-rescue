// Follow-ups handed to the help district's task: what a monitoring check says
// when it found nothing, the district's seed, the panic key's edges, and the
// held findings' place on the map, in integrity and in sweeps.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const Q = require('../renderer/quiet-notes.js');
const { recordingStore, forbiddenWrites } = require('./disk-words.js');
const { page } = require('./page-harness.js');

const REAL = require('./fixtures/monitoring-descriptions.json');
const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const finding = (title, severity, extra = {}) => ({ title, description: `${title}.`, severity, category: 'security', data: {}, ...extra });
const MVT = 'security.mvt_spyware_scan.';

// A stubbed window like game-side-district-controller.test.js's, with a host
// that can be hidden and a held note's <details> that a redraw resets.
function stub({ mode = 'city', seed = 424242, hidden = false } = {}) {
  const clicks = [];
  const keys = [];
  const focused = [];
  const details = { open: false };
  let html = '';
  const frame = {
    get innerHTML() { return html; },
    set innerHTML(v) { html = v; details.open = false; },
    addEventListener: (type, fn) => { if (type === 'click') clicks.push(fn); },
    querySelector: (sel) => {
      if (sel === '.panel.held details') return /class="panel held"[\s\S]*<details/.test(html) ? details : null;
      if (sel === '#side-title') return html.includes('id="side-title" tabindex="-1"') ? { focus: () => focused.push(sel) } : null;
      const m = /^\[(data-[a-z]+)="(.*)"\]$/.exec(sel);
      return m && html.includes(`${m[1]}="${m[2]}"`) ? { focus: () => focused.push(sel) } : null;
    },
    querySelectorAll: () => [],
  };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const host = { attachShadow: () => shadow, closest: (sel) => (sel === '[hidden]' && hidden ? {} : null) };
  const RescueHost = { citySeed: () => seed, showList() {}, docChanged: () => true, wantsSafety: () => false,
    startCheckup() {}, scanTips: async () => [], leaveGame() {} };
  if (mode !== undefined && mode !== 'none') RescueHost.mode = () => mode;
  const win = {
    document: { getElementById: () => host },
    addEventListener: (type, fn) => { if (type === 'keydown') keys.push(fn); },
    QuietNotes: Q,
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost,
    rescue: { recheckModule: async () => ({ ok: false }), openGuide: async () => true },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const press = (key) => {
    const ev = { key, prevented: false, preventDefault() { this.prevented = true; }, stopPropagation() {} };
    keys.forEach((fn) => fn(ev));
    return ev;
  };
  return { win, frame, details, click, press, focused, html: () => html };
}

async function setup(opts = {}, doc = null) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const storage = opts.storage || recordingStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  if (doc) ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, ctl, storage, saved: () => JSON.parse(storage.getItem('device-rescue.game.v1') || 'null') };
}

// ---------------------------------------------------------------------------
// A monitoring check that found nothing reads like any other finding.
// ---------------------------------------------------------------------------

test('one list of "found nothing" codes, in QuietNotes and held.js, and each is a real code', async () => {
  const held = await game('held.js');
  assert.deepStrictEqual([...held.NOT_DETECTIONS].sort(), [...Q.NOT_DETECTIONS].sort());
  const real = new Set(REAL.map((r) => r.code));
  for (const code of Q.NOT_DETECTIONS) assert.ok(real.has(code), `${code} is one the checks really report`);
  // The same rule both sides, over every real description and the edge cases.
  const cases = [...REAL, { module: 'stalkerware_scan', severity: 'info' }, { module: 'stalkerware_scan', severity: 'warning' },
    { module: 'stalkerware_scan' }, { module: 'mvt_spyware_scan', severity: 'info', code: `${MVT}no_backups_found` }];
  for (const f of cases) assert.strictEqual(held.isDetection(f), Q.isDetection(f), JSON.stringify(f).slice(0, 80));
});

test('"No device backups found" and "No spyware indicators detected" read normally, in both modes', () => {
  for (const r of REAL.filter((x) => Q.NOT_DETECTIONS.has(x.code))) {
    const f = { module: r.module, code: r.code, severity: 'info', title: 't', description: r.description };
    for (const mode of ['city', 'standard']) {
      assert.strictEqual(Q.noteFor(mode, f), 'none', `${mode}: ${r.code}`);
      const card = Q.cardText(mode, f);
      assert.strictEqual(card.description, Q.quiet(r.description), r.code);
      assert.strictEqual(Q.heldHtml(card, String) + Q.lineHtml(card, String), '', r.code);
    }
  }
  // A real detection still is one, whatever its severity.
  for (const sev of ['critical', 'warning', 'info']) {
    assert.strictEqual(Q.noteFor('city', { module: 'stalkerware_scan', code: 'security.stalkerware_scan.monitoring_software_found', severity: sev }), 'held', sev);
  }
  assert.strictEqual(Q.noteFor('city', { module: 'mvt_spyware_scan', code: `${MVT}mvt_spyware_detected`, severity: 'critical' }), 'held');
  assert.strictEqual(Q.noteFor('city', { module: 'keylogger_indicators', code: 'security.keylogger_indicators.suspicious_input_monitoring', severity: 'info' }), 'held');
});

test('splitHeld holds every detection, at any severity, and never a "found nothing" line', async () => {
  const { splitHeld } = await game('held.js');
  const doc = scan(
    mod('mvt_spyware_scan', [finding('No device backups found', 'info', { code: `${MVT}no_backups_found` }),
      finding('Backup too large to scan', 'warning', { code: `${MVT}mvt_backup_too_large` })]),
    mod('stalkerware_scan', [finding('TeamViewer is on this computer (app)', 'info', { code: 'security.stalkerware_scan.monitoring_software_found' })]),
  );
  assert.deepStrictEqual(splitHeld(doc).held, [{ module: 'stalkerware_scan', title: 'TeamViewer is on this computer (app)' }]);
  // Nor does a "found nothing" line hold its district open, or point to a note that isn't there.
  const { heldOnly } = await game('held.js');
  const { findingsToCity } = await game('findings-to-city.js');
  const { heldDistrictIds } = await game('signals.js');
  const only = heldOnly(doc);
  assert.deepStrictEqual(only.modules.map((m) => m.findings.map((f) => f.code)),
    [[], ['security.stalkerware_scan.monitoring_software_found']]);
  assert.strictEqual(heldDistrictIds(findingsToCity(heldOnly(scan(doc.modules[0])))).size, 0);
});

test('the list in city mode: a "found nothing" card has no hold line, no fix and no mark; a detection keeps its hold line', async () => {
  const p = page({ store: { 'device-rescue.display': 'city' } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  await p.finish(scan(
    mod('mvt_spyware_scan', [finding('No device backups found', 'info', { code: `${MVT}no_backups_found`,
      fixable: { will_change: 'Turns something on.', how_to_undo: ['Turn it off again.'] } })]),
    mod('stalkerware_scan', [finding('Stalkerware found: mSpy', 'critical', { code: 'security.stalkerware_scan.monitoring_software_found' })]),
  ));
  const cards = p.byId('results-groups').innerHTML.split('<li class="finding-card').slice(1);
  const clean = cards.find((c) => c.includes('No device backups found'));
  const spy = cards.find((c) => c.includes('mSpy'));
  assert.ok(clean && spy);
  assert.doesNotMatch(clean, /Don’t remove it yet|Removing this can alert|\[FIX IT\]|\[IT IS MINE\]|data-fix-module|data-mark-card/);
  assert.match(clean, /No device backups found\./, 'its own description');
  assert.match(spy, /Don’t remove it yet/);
});

// ---------------------------------------------------------------------------
// The district's seed.
// ---------------------------------------------------------------------------

test('seedFrom: a number or its digits; anything else a random seed, never a constant', async () => {
  const { seedFrom } = await game('district-names.js');
  assert.strictEqual(seedFrom(424242), 424242);
  assert.strictEqual(seedFrom('424242'), 424242, 'a seed read back from storage is a string');
  assert.strictEqual(seedFrom(' 99 '), 99);
  const seeds = new Set();
  for (const bad of [null, undefined, 0, -3, 1.5, 'abc', '', '12x', NaN, 0x80000000, {}, '0']) {
    let r = 0;
    const a = seedFrom(bad, () => (r += 0.1) % 1);
    assert.ok(Number.isInteger(a) && a >= 1 && a <= 0x7fffffff, String(bad));
    seeds.add(seedFrom(bad, () => 0.25));
    seeds.add(seedFrom(bad, () => 0.75));
  }
  assert.strictEqual(seeds.size, 2, 'the seed follows the random source, not the bad input');
  assert.notStrictEqual(seedFrom(null, () => 0.5), 1);
});

test('the controller parses a string seed, and gives a bad one a random district for the session', async () => {
  const { pickDistrict, seedFrom } = await game('district-names.js');
  const tile = (h) => /data-go="side">([^<]*)</.exec(h)[1];
  const a = await setup({ seed: '12345' }, scan(mod('remote_login_check', [])));
  assert.ok(tile(a.html()).startsWith(pickDistrict(12345).name.toUpperCase()));
  const real = Math.random;
  try {
    const names = new Set();
    for (const r of [0.11, 0.52, 0.93]) {
      Math.random = () => r;
      const t = await setup({ seed: null }, scan(mod('remote_login_check', [])));
      const expected = pickDistrict(seedFrom(null, () => r)).name.toUpperCase();
      assert.ok(tile(t.html()).startsWith(expected), `${r}: ${tile(t.html())}`);
      // Cached for the session: a redraw keeps the same district.
      Math.random = () => 0.01;
      t.click({ 'data-act': 'toggle-low' });
      assert.ok(tile(t.html()).startsWith(expected), 'the same district all session');
      names.add(expected);
    }
    assert.ok(names.size > 1, 'installs with a bad seed don’t all get one district');
  } finally {
    Math.random = real;
  }
  const thrower = await setup({}, null);
  thrower.win.RescueHost.citySeed = () => { throw new Error('blocked'); };
  thrower.ctl.show(scan(mod('remote_login_check', [])), { id: 'city' });
  assert.match(thrower.html(), /data-go="side"/, 'a seed that can’t be read still gives a district');
});

// ---------------------------------------------------------------------------
// The panic key's edges.
// ---------------------------------------------------------------------------

test('Esc before any scan: back to the Training Grounds, focus on its checkup button', async () => {
  const t = await setup();
  t.ctl.showTraining({ id: 'city', title: 'Take back the city' });
  t.click({ 'data-go': 'side' });
  assert.match(t.html(), /side-title/);
  assert.strictEqual(t.press('Escape').prevented, true);
  assert.doesNotMatch(t.html(), /side-title/);
  assert.ok(t.focused.includes('[data-act="start-checkup"]'), t.focused.join(', '));
});

test('Esc from the district on a deck with signals: the deck at once, focus on the first district', async () => {
  const t = await setup({}, scan(mod('remote_login_check', [finding('Remote Login is on', 'warning')])));
  t.click({ 'data-go': 'side' });
  t.ctl.scanEvent({ type: 'module_start', name: 'x' }); // ignored: no scan running, still the district
  assert.match(t.html(), /side-title/);
  t.press('Escape');
  assert.match(t.html(), /INCOMING SIGNALS/);
  assert.ok(t.focused.some((x) => x.startsWith('[data-go="filter:')), t.focused.join(', '));
});

test('Esc is left alone while the city isn’t on screen (app.js’s own screens keep their Esc)', async () => {
  const t = await setup({ hidden: true }, scan(mod('remote_login_check', [])));
  t.click({ 'data-go': 'side' });
  assert.strictEqual(t.press('Escape').prevented, false);
  assert.match(t.html(), /side-title/);
});

// ---------------------------------------------------------------------------
// Held findings on the map, in integrity and in sweeps.
// ---------------------------------------------------------------------------

const SPY = () => mod('stalkerware_scan', [finding('Monitoring app', 'critical', { code: 'security.stalkerware_scan.monitoring_software_found', data: { path: '/m' } })]);
const NONE = () => mod('stalkerware_scan', []);

test('a district holding a monitoring finding never reads NOTHING FOUND: it says it was checked, and points to where it is said', async () => {
  const { findingsToCity } = await game('findings-to-city.js');
  const { HELD_DISTRICT_LINE } = await game('views/map.js');
  const { pickDistrict } = await game('district-names.js');
  const gate = findingsToCity(scan(SPY())).districts.find((d) => d.missions.length).id;
  for (const mode of ['city', 'standard', 'none']) {
    const t = await setup({ mode }, scan(SPY()));
    const card = t.html().split(`data-go="filter:${gate}"`)[1].split('</button>')[0];
    assert.doesNotMatch(card, /NOTHING FOUND|Nothing found|RECLAIMED/, mode);
    // City mode has no note above the map, only the generated district's tile.
    const want = mode === 'city' ? `Checked. See ${pickDistrict(424242).name}.` : HELD_DISTRICT_LINE;
    assert.ok(card.includes(want), `${mode}: ${card}`);
    if (mode === 'city') assert.doesNotMatch(t.html(), /note above/, 'nothing points to a note that isn’t there');
    assert.doesNotMatch(t.html(), /Nothing stood out in the checks that ran/, mode);
    // Once it is gone, the district reads as before.
    t.ctl.show(scan(NONE()), { id: 'city' });
    assert.match(t.html().split(`data-go="filter:${gate}"`)[1].split('</button>')[0], /NOTHING FOUND/, mode);
  }
});

test('held software going away is never DISTRICT SECURED or a CLEAN SWEEP, pays nothing and logs nothing', async () => {
  for (const mode of ['city', 'none']) {
    const t = await setup({ mode }, scan(SPY(), mod('remote_login_check', [])));
    t.ctl.show(scan(NONE(), mod('remote_login_check', [])), { id: 'city' });
    const html = t.html();
    assert.match(html, /<b>100%<\/b>/, `${mode}: the district is secure now`);
    assert.doesNotMatch(html, /DISTRICT SECURED|CLEAN SWEEP|SECURED<\/span>/, mode);
    assert.strictEqual(t.saved().deck.points, 0, mode);
    // The next clean sweep after it isn't a bonus either (it was already clean).
    t.ctl.show(scan(NONE(), mod('remote_login_check', [])), { id: 'city' });
    assert.doesNotMatch(t.html(), /CLEAN SWEEP/, mode);
    assert.strictEqual(t.saved().deck.points, 0, mode);
    assert.deepStrictEqual(forbiddenWrites(t.storage), [], mode);
  }
});

test('held software turning up is not scored either; an ordinary clean sweep still is', async () => {
  const t = await setup({ mode: 'city' }, scan(NONE(), mod('remote_login_check', [finding('Remote Login is on', 'warning')])));
  t.ctl.show(scan(SPY(), mod('remote_login_check', [])), { id: 'city' });
  assert.doesNotMatch(t.html(), /CLEAN SWEEP|DISTRICT SECURED/);
  // Without anything held: Remote Login fixed between sweeps is the ordinary clean sweep.
  const u = await setup({ mode: 'city' }, scan(NONE(), mod('remote_login_check', [finding('Remote Login is on', 'warning')])));
  u.ctl.show(scan(NONE(), mod('remote_login_check', [])), { id: 'city' });
  assert.match(u.html(), /CLEAN SWEEP/);
  assert.ok(u.saved().deck.points > 0);
});

test('a sweep counts held criticals and warnings, as numbers only', async () => {
  const { sweepCounts, cityIntegrity } = await game('signals.js');
  const { findingsToCity } = await game('findings-to-city.js');
  const { splitHeld, heldOnly } = await game('held.js');
  const doc = scan(SPY(), mod('remote_login_check', [finding('Remote Login is on', 'warning')]));
  const city = findingsToCity(splitHeld(doc).doc);
  const held = findingsToCity(heldOnly(doc));
  const c = sweepCounts(doc, city, cityIntegrity(city, [], held), held);
  assert.strictEqual(c.critical, 1);
  assert.strictEqual(c.warning, 1);
  assert.strictEqual(sweepCounts(doc, city, null).critical, 0, 'without the held city, as before');
  const t = await setup({ mode: 'city' }, doc);
  const sweep = t.saved().deck.sweeps.at(-1);
  assert.strictEqual(sweep.critical, 1);
  assert.doesNotMatch(JSON.stringify(t.saved()), /Monitoring app|stalkerware|\/m\b/);
});

test('the held note’s details stay open across redraws, like the known pile', async () => {
  for (const mode of ['standard', 'none']) {
    const t = await setup({ mode }, scan(SPY(), mod('remote_login_check', [finding('Remote Login is on', 'warning')])));
    assert.match(t.html(), /class="panel held"/, mode);
    t.details.open = true; // the person opened it
    t.click({ 'data-act': 'toggle-low' });
    assert.strictEqual(t.details.open, true, `${mode}: still open after a redraw`);
    t.details.open = false; // and closed it again
    t.click({ 'data-act': 'toggle-low' });
    assert.strictEqual(t.details.open, false, `${mode}: still closed`);
  }
});

// ---------------------------------------------------------------------------
// Fix round 1.
// ---------------------------------------------------------------------------

test('after a restart, held software gone is still no CLEAN SWEEP and no points; the flag on disk names nothing', async () => {
  for (const mode of ['city', 'none']) {
    const storage = recordingStore();
    const a = await setup({ mode, storage }, scan(SPY(), mod('remote_login_check', [])));
    assert.strictEqual(a.saved().deck.points, 0, mode);
    assert.strictEqual(a.saved().deck.sweep.carry, true, `${mode}: the sweep is marked`);
    // Restart: a new controller on the same storage, and a sweep without it.
    const b = await setup({ mode, storage }, scan(NONE(), mod('remote_login_check', [])));
    assert.match(b.html(), /<b>100%<\/b>/, mode);
    assert.doesNotMatch(b.html(), /CLEAN SWEEP|DISTRICT SECURED/, mode);
    assert.strictEqual(b.saved().deck.points, 0, mode);
    assert.strictEqual(b.saved().deck.sweep.carry, undefined, `${mode}: this sweep holds nothing`);
    assert.deepStrictEqual(forbiddenWrites(storage), [], mode);
    for (const [, v] of storage.writes) assert.doesNotMatch(v, /Monitoring app|stalkerware|"\/m"/, mode);
  }
});

test('recordSweep: a sweep that carries held software, or follows one, pays no clean bonus; the flag survives a reload', async () => {
  const { recordSweep } = await game('ledger.js');
  const { emptyDeck, cleanDeck, validDeck } = await game('progress.js');
  const dirty = { checks: 1, checked: 1, secured: 0 };
  const clean = { checks: 1, checked: 1, secured: 1 };
  let d = recordSweep(emptyDeck(), dirty, 'a', { carry: true }).deck;
  assert.strictEqual(d.sweep.carry, true);
  const reloaded = cleanDeck(JSON.parse(JSON.stringify(d)));
  assert.ok(validDeck(reloaded) && reloaded.sweep.carry === true);
  const r = recordSweep(reloaded, clean, 'b');
  assert.strictEqual(r.points, 0);
  assert.strictEqual(r.clean, false);
  // Without the flag the same pair pays, as before.
  d = recordSweep(emptyDeck(), dirty, 'a').deck;
  assert.strictEqual(recordSweep(d, clean, 'b').clean, true);
  assert.strictEqual(validDeck({ ...d, sweep: { ...d.sweep, carry: 'yes' } }), false);
});

test('a monitoring check that couldn’t look is COULDN’T CHECK, never NOTHING FOUND or 100%', async () => {
  const { findingsToCity } = await game('findings-to-city.js');
  const { splitHeld, COULDNT_LOOK } = await game('held.js');
  assert.deepStrictEqual([...COULDNT_LOOK].sort(), [`${MVT}mvt_backup_too_large`, `${MVT}mvt_not_installed`, `${MVT}mvt_requires_wsl`,
    `${MVT}mvt_scan_available`, `${MVT}no_backups_found`]);
  const real = new Set(REAL.map((r) => r.code));
  for (const code of COULDNT_LOOK) {
    assert.ok(real.has(code), code);
    const sev = code.endsWith('too_large') ? 'warning' : 'info';
    const doc = scan(mod('mvt_spyware_scan', [finding('x', sev, { code })]));
    const d = findingsToCity(splitHeld(doc).doc).districts.find((x) => x.fog.length);
    assert.ok(d, `${code}: fog`);
    assert.strictEqual(d.status, 'fog', code);
    for (const mode of ['city', 'standard', 'none']) {
      const t = await setup({ mode }, doc);
      const card = t.html().split(`data-go="filter:${d.id}"`)[1].split('</button>')[0];
      assert.match(card, /COULDN’T CHECK/, `${mode} ${code}`);
      assert.doesNotMatch(card, /NOTHING FOUND|Nothing found/, `${mode} ${code}`);
      assert.doesNotMatch(t.html(), /<b>100%<\/b>/, `${mode} ${code}`);
      // The district screen doesn't name the check.
      t.click({ 'data-go': `district:${d.id}` });
      assert.doesNotMatch(t.html(), /mvt|spyware/i, `${mode} ${code}`);
    }
  }
  // A clean scan did look: it reads as checked.
  const done = findingsToCity(splitHeld(scan(mod('mvt_spyware_scan', [finding('No spyware indicators detected', 'info', { code: `${MVT}mvt_clean_scan` })]))).doc);
  assert.ok(done.districts.every((x) => !x.fog.length));
  // A detection next to a couldn't-look line: the check looked, and it's held.
  const both = splitHeld(scan(mod('mvt_spyware_scan', [finding('Backup too large', 'warning', { code: `${MVT}mvt_backup_too_large` }),
    finding('Spyware found', 'critical', { code: `${MVT}mvt_spyware_detected` })])));
  assert.strictEqual(both.held.length, 1);
  assert.notStrictEqual(both.doc.modules[0].supported, false);
});

test('an empty queue while something is held: never CLEAR BOARD, and it points to the district by name', async () => {
  const { pickDistrict } = await game('district-names.js');
  const t = await setup({ mode: 'city' }, scan(SPY()));
  const q = t.html().split('INCOMING SIGNALS')[1].split('deck-city')[0];
  assert.doesNotMatch(q, /CLEAR BOARD|A clean checkup lowers the odds/);
  assert.match(q, /Nothing to sort here right now\./);
  assert.ok(q.includes(`Something new in ${pickDistrict(424242).name}.`), q);
  assert.doesNotMatch(q, /advocate|remove|monitor|watch|spy/i);
  const std = await setup({ mode: 'standard' }, scan(SPY()));
  const qs = std.html().split('INCOMING SIGNALS')[1].split('deck-city')[0];
  assert.doesNotMatch(qs, /CLEAR BOARD/);
  assert.match(qs, /Nothing to sort here right now\./);
  // Nothing held: the clear board, as before.
  const clean = await setup({ mode: 'city' }, scan(NONE()));
  assert.match(clean.html(), /CLEAR BOARD/);
});

test('the district: its sections are h3 headings under its h2, and opening it focuses the h2', async () => {
  const t = await setup({ mode: 'city' }, scan(SPY()));
  t.click({ 'data-go': 'side' });
  const html = t.html();
  assert.match(html, /<h2 class="hud-title" id="side-title" tabindex="-1">/);
  for (const label of ['QUIET FIRST STEPS', 'WHO CAN HELP', 'THE STORY OF SIX ROSES', 'Don’t remove it yet. Talk to an advocate first.']) {
    assert.ok(html.includes(`<h3 class="label">${label}</h3>`), label);
  }
  assert.doesNotMatch(html, /<div class="label">/);
  assert.ok(t.focused.includes('#side-title'), t.focused.join(', '));
});
