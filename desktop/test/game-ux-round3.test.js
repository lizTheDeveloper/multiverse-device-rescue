// UX round 3, the city: one set of numbers with the list (NotChecked.scanCounts),
// a stopped checkup shown honestly, the phone backup's long sweep as an
// optional, ask-first mission, duplicate missions merged by the engine's
// same_key, a failed re-check after a fix that never says nothing changed, the
// DNS filtering profile as a normal mission, and the LOOK CLOSER refresher.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');
const NotChecked = require('../renderer/not-checked.js');
const app = require('../renderer/app.js');
const { page } = require('./page-harness.js');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const memStore = () => { const s = {}; return { data: s, getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; } }; };
const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', f), 'utf8'));
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const finding = (title, severity, extra = {}) => ({ title, description: `${title}. Worth a look.`, severity, category: 'security', ...extra });

function stub({ mode = 'city', runScan = null, fixFlow = {}, markFlow = {} } = {}) {
  const clicks = [];
  const focused = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); },
    querySelector: (sel) => (sel === 'h2' ? { focus: () => focused.push('h2'), setAttribute() {}, hasAttribute: () => false } : null),
    querySelectorAll: () => [] };
  const shadow = { activeElement: null, innerHTML: '', getElementById: () => frame, addEventListener: () => {} };
  const calls = { runScan: [], docChanged: 0, marked: [] };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener: () => {},
    QuietNotes: require('../renderer/quiet-notes.js'),
    FixFlow: { attach() {}, fixControlsHtml: () => '<button data-fix>FIX</button>', resultHtml: () => '', ...fixFlow },
    MarkFlow: { attach() {}, markControlsHtml: (f) => { calls.marked.push(f); return '<button data-mark>MINE</button>'; }, ...markFlow },
    RescueHost: { mode: () => mode, citySeed: () => 7, showList() {}, docChanged: () => { calls.docChanged += 1; return true; },
      wantsSafety: () => true, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false, message: 'We couldn’t check again just now. You can try again.' }),
      runScan: async (profile) => { calls.runScan.push(profile); return runScan ? runScan(profile) : null; } },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, click, calls, focused, html: () => frame.innerHTML };
}

async function setup(doc, opts = {}) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const storage = opts.storage || memStore();
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: opts.loadTraining || (async () => []), loadDrillBank: async () => [] });
  await tick();
  if (doc) ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, ctl, storage };
}

const num = (html, re) => { const m = re.exec(html); return m ? Number(m[1]) : 0; };
const chip = (html, label) => num(html, new RegExp(`data-act="sev:[a-z]+"[^>]*>${label} (\\d+)<`));
const hud = (html, label) => num(html, new RegExp(`<b>(\\d+)</b> <small>${label}</small>`));

test('the fresh scan: every city number is the list’s number (NotChecked.scanCounts)', async () => {
  const doc = load('fresh-round3.json');
  const plain = NotChecked.scanCounts(doc, { mode: 'standard' });
  const city = NotChecked.scanCounts(doc, { mode: 'city' });
  // Nothing held in this scan: the two modes agree, number for number.
  const { byDistrict: _a, ...p } = plain;
  const { byDistrict: _b, ...c } = city;
  assert.deepStrictEqual(c, p);

  const t = await setup(doc);
  const deck = t.html();
  // LAST SWEEP: every check once, and what couldn't run or didn't finish, and what waits.
  assert.match(deck, new RegExp(`LAST SWEEP</small> [^·]+· ${plain.checks} CHECKS, ${plain.didntFinish} COULDN’T RUN OR DIDN’T FINISH, ${plain.notStarted} WAITING FOR YOU`));
  // The banner is the list's own line.
  assert.ok(deck.includes(app.notCheckedLine(app.notCheckedSummary(doc))));
  // The chips: one row per item (same items as the list), plus what wasn't checked.
  assert.strictEqual(chip(deck, 'CRITICAL') + chip(deck, 'WARNING'), plain.todo);
  // NOT CHECKED (round 5): every part named, from NotChecked; TO DO is the list's items.
  const { notCheckedChip } = await game('signals.js');
  assert.ok(deck.includes(`>NOT CHECKED: ${notCheckedChip(city)}<`));
  const todo = plain.todo;
  assert.match(deck, new RegExp(`INCOMING SIGNALS · ${todo} TO DO`));
  // The ops log's SWEEP line.
  assert.match(deck, new RegExp(`SWEEP</span> ${plain.checks} checks: ${plain.todo} to look at \\(${plain.critical} critical\\), ${plain.didntFinish} couldn’t run or didn’t finish, ${plain.notStarted} waiting for you\\.`));
  // District badges add up to the scan's not-fully-checked checks, each once.
  const badge = (label) => [...deck.matchAll(new RegExp(`(\\d+) ${label}</span>`, 'g'))].reduce((n, m) => n + Number(m[1]), 0);
  assert.strictEqual(badge('DIDN’T FINISH'), plain.unfinished);
  assert.strictEqual(badge('NOT STARTED'), plain.notStarted);
  assert.strictEqual(badge('COULDN’T CHECK'), plain.couldntRun);
  // A mission's HUD says the same TO DO and COULDN'T CHECK.
  t.click({ 'data-go': 'district:gatehouse' });
  const h = t.html();
  assert.strictEqual(hud(h, 'TO DO'), todo);
  assert.strictEqual(hud(h, 'NOT CHECKED'), plain.couldntRun + plain.unfinished + plain.notStarted);
});

test('Plain’s own “N things on your list” is the city’s mission count on the same scan', async () => {
  const doc = load('fresh-round3.json');
  const p = page({ store: { 'device-rescue.display': 'standard' } });
  p.byId('btn-get-started').click();
  p.pick('hacked');
  p.byId('btn-run-scan').click();
  await p.finish(doc);
  if (p.shown().includes('question')) p.answer('known');
  // Plain's own rendered list: the cards in its critical and warning groups.
  const groups = p.byId('results-groups').innerHTML.split('data-results-group="').slice(1);
  const listed = groups.filter((g) => /^(critical|warning)"/.test(g))
    .reduce((n, g) => n + g.split('<li class="finding-card').length - 1, 0);
  assert.ok(listed > 0, 'Plain lists cards');
  const { findingsToCity } = await game('findings-to-city.js');
  const missions = findingsToCity(doc).districts.flatMap((d) => d.missions);
  assert.strictEqual(listed, missions.length);
  assert.strictEqual(listed, NotChecked.scanCounts(doc, { mode: 'city' }).todo);
});

test('one item reported by several checks (same_key) is one mission, re-checked in each; severity is the list’s', async () => {
  const crash = (m) => mod(m, [finding('Chrome crashed 4 times', 'warning', { category: 'performance', same_key: 'crashes:chrome', data: { app: 'chrome' } })], { category: 'performance' });
  const doc = scan(crash('crash_reports'), crash('app_crash_audit'), crash('diagnostic_reports'),
    mod('disk_health', [finding('Disk is old', 'critical', { category: 'integrity' })], { category: 'integrity' }));
  const { findingsToCity } = await game('findings-to-city.js');
  const city = findingsToCity(doc);
  const missions = city.districts.flatMap((d) => d.missions);
  assert.strictEqual(missions.filter((x) => x.title === 'Chrome crashed 4 times').length, 1);
  assert.strictEqual(missions.find((x) => x.title === 'Chrome crashed 4 times').findings.length, 3);
  // Critical only where it is an alarm (security, network): the list shows it as a warning.
  assert.strictEqual(missions.find((x) => x.title === 'Disk is old').severity, 'warning');
  assert.strictEqual(NotChecked.scanCounts(doc, { mode: 'city' }).items, missions.length);

  const asked = [];
  const t = await setup(doc);
  t.win.rescue.recheckModule = async (n) => { asked.push(n); return { ok: false }; };
  const id = missions.find((x) => x.title === 'Chrome crashed 4 times').id;
  t.click({ 'data-go': `mission:${id}` });
  t.click({ 'data-act': 'i-did-it' });
  await tick(); await tick(); await tick();
  assert.deepStrictEqual(asked, ['crash_reports', 'app_crash_audit', 'diagnostic_reports']);
});

for (const stage of ['assembly', 'early']) {
  test(`a stopped checkup (${stage}): an honest banner in game words, nothing to fix or mark, no district clear`, async () => {
    const doc = scan(mod('launch_agent_audit', [finding('Unsigned helper', 'warning', { data: { label: 'x', plist: '/Library/LaunchAgents/x.plist' }, fixable: true, markable: { id: 'k' } })]),
      mod('firewall', [], { category: 'network' }),
      ...(stage === 'early' ? [mod('disk_health', [], { category: 'integrity', status: 'error', error: 'The checkup stopped before this check ran.', complete: false, error_kind: 'stopped' })] : []));
    doc.stopped = { stage, reason: 'exit', exit_code: 1, done: stage === 'early' ? 2 : 2, total: stage === 'early' ? 3 : 2 };
    doc.partial = { done: doc.stopped.done, total: doc.stopped.total, stopped: stage };
    const t = await setup(doc);
    const deck = t.html();
    assert.match(deck, stage === 'assembly' ? /THE SWEEP STOPPED AT THE END[\s\S]*All 2 checks reported/ : /THE SWEEP STOPPED EARLY[\s\S]*2 of 3 checks reported/);
    assert.match(deck, /Nothing on your computer was changed/);
    assert.doesNotMatch(deck, /NOTHING FOUND|Nothing found in the checks that ran|CLEAN SWEEP|CLEAR BOARD/);
    assert.doesNotMatch(deck, /engine exited|Traceback|exit_code/i);
    // The mission: no fix, no mark, no "I did it" (main refuses them for a stopped checkup).
    const { findingsToCity } = await game('findings-to-city.js');
    const id = findingsToCity(doc).districts.flatMap((d) => d.missions)[0].id;
    t.click({ 'data-go': `mission:${id}` });
    const m = t.html();
    assert.doesNotMatch(m, /data-fix|data-mark|data-act="i-did-it"/);
    assert.match(m, /stopped before its report was done/);
    // Its signal offers no "It's mine" either.
    t.click({ 'data-go': 'map' });
    t.click({ 'data-go': `signal:${id}` });
    t.click({ 'data-act': 'tag:mine' });
    assert.doesNotMatch(t.html(), /data-mark/);
    // Nothing secured, so no district reads as reclaimed or at 100%.
    assert.doesNotMatch(t.html(), /<b>100%<\/b>/);
  });
}

test('the phone backup waiting for a go-ahead: an optional mission in game words, asked first, never “couldn’t run”', async () => {
  const mvt = mod('mvt_spyware_scan', [finding('1 device backup found (scan available)', 'info', { code: 'security.mvt_spyware_scan.mvt_scan_available' })], { not_started: true });
  const doc = scan(mod('firewall', [finding('Firewall is off', 'warning')]), mvt);
  const after = scan({ ...mvt, not_started: false, findings: [finding('No spyware indicators detected', 'info', { code: 'security.mvt_spyware_scan.mvt_clean_scan' })] });
  const t = await setup(doc, { runScan: async () => after });
  const deck = t.html();
  const row = /<li><button[^>]*data-go="signal:(waiting\|[^"]+)"[\s\S]*?<\/li>/.exec(deck);
  assert.ok(row, 'a waiting row');
  assert.match(row[0], /NOT STARTED/);
  assert.doesNotMatch(row[0], /COULDN’T CHECK|couldn’t run/);
  assert.doesNotMatch(deck, /spyware|mvt|iPhone/i, 'city mode names no check');
  t.click({ 'data-go': `signal:${row[1]}` });
  const panel = t.html();
  assert.match(panel, /A phone backup can get its own long sweep/);
  assert.doesNotMatch(panel, /spyware|tag:mine|tag:noted/i);
  assert.match(panel, /isn’t checked, so it isn’t clear either/);
  // Ask first: START opens the question; nothing runs until YES.
  t.click({ 'data-act': 'waiting-start' });
  assert.match(t.html(), /Start the long sweep now\? It only reads the backup\./);
  assert.deepStrictEqual(t.calls.runScan, []);
  t.click({ 'data-act': 'waiting-no' });
  assert.doesNotMatch(t.html(), /data-act="waiting-yes"/);
  // A forged YES without the question open does nothing.
  t.click({ 'data-act': 'waiting-yes' });
  assert.deepStrictEqual(t.calls.runScan, []);
  t.click({ 'data-act': 'waiting-start' });
  t.click({ 'data-act': 'waiting-yes' });
  assert.deepStrictEqual(t.calls.runScan, ['iphone_spyware_check']);
  assert.match(t.html(), /LONG SWEEP<\/span> Started\./);
  await tick(); await tick();
  // Its result joins this checkup: the list is told, the waiting row goes.
  assert.strictEqual(t.calls.docChanged, 1);
  assert.doesNotMatch(t.html(), /data-go="signal:waiting/);
  assert.doesNotMatch(t.html(), /NOT STARTED/);
  assert.match(t.html(), /Firewall is off/, 'the rest of the checkup stays');
});

test('standard mode says what the waiting sweep is for', async () => {
  const mvt = mod('mvt_spyware_scan', [finding('1 device backup found (scan available)', 'info', { code: 'security.mvt_spyware_scan.mvt_scan_available' })]);
  const t = await setup(scan(mvt), { mode: 'standard' });
  assert.match(t.html(), /Your phone’s backup can be swept for spyware/);
});

test('a re-check that fails after a fix ran says the change was made, never “Nothing was changed”', async () => {
  const f = finding('Unsigned helper', 'warning', { data: { label: 'x', plist: '/Library/LaunchAgents/x.plist' }, fixable: true });
  const doc = scan(mod('launch_agent_audit', [f]));
  let onResult = null;
  const t = await setup(doc, { fixFlow: { attach: (_f, _r, o) => { onResult = o.onResult; },
    recheckFailedText: require('../renderer/fix-flow.js').recheckFailedText } });
  const { findingsToCity } = await game('findings-to-city.js');
  const id = findingsToCity(doc).districts.flatMap((d) => d.missions)[0].id;
  t.click({ 'data-go': `mission:${id}` });
  onResult({ kind: 'fix', module: 'launch_agent_audit', result: { applied: true, quarantine_id: 'q1' }, described: { tone: 'success' } });
  await tick(); await tick(); await tick();
  const html = t.html();
  assert.match(html, /COULDN’T RE-CHECK/);
  assert.strictEqual((html.match(/COULDN’T RE-CHECK/g) || []).length, 1, 'one heading');
  assert.match(html, /The change was made/);
  assert.doesNotMatch(html, /Nothing was changed/i);
  assert.ok(t.focused.includes('h2'), 'focus lands on the result');
});

test('the DNS filtering profile is a normal mission: its evidence, the removal warning, and “It’s mine”', async () => {
  const f = { title: 'Your DNS goes through a filtering profile (NextDNS)', severity: 'warning', category: 'security',
    code: 'security.dns_poisoning_check.dns_filtering_profile',
    description: "A profile's owner can see every website name looked up. Check it's yours.\n\nAddresses: 45.90.28.163, 45.90.30.163 (profile abc123).\n\nIf you think someone close to you set this up to monitor you, changing it can alert them. Talk to an advocate first (US National Domestic Violence Hotline: 1-800-799-7233, or text START to 88788).\n\nWhat to do: Sign in to your account with that provider and check the profile is yours. If it isn't, set DNS back to automatic.",
    data: { check: 'dns_filtering_profile', provider: 'NextDNS', servers: ['45.90.28.163', '45.90.30.163'], profile_ids: ['abc123'] },
    markable: { id: 'dns1', kind: 'dns_profile' },
    // As the engine sends it: the walkthrough is marked monitoring_risk, so it carries the safety note.
    remediation: { title: 'Fix DNS hijacking or poisoning', steps: [{ number: 1, title: 'Check the DNS servers', body: '' }],
      safety_note: 'Before you remove or turn anything off: if you think someone close to you set this up to watch you, removing it can alert them. Talk to an advocate first. In the US: National Domestic Violence Hotline, 1-800-799-7233, or text START to 88788.' } };
  const doc = scan(mod('dns_poisoning_check', [f]));
  const t = await setup(doc);
  assert.match(t.html(), /Your DNS goes through a filtering profile \(NextDNS\)/, 'a signal, not held');
  const { findingsToCity } = await game('findings-to-city.js');
  const id = findingsToCity(doc).districts.flatMap((d) => d.missions)[0].id;
  t.click({ 'data-go': `mission:${id}` });
  const html = t.html().replace(/<wbr>/g, '');
  const what = html.split('WHAT IT IS')[1];
  assert.match(what, /NextDNS/);
  assert.match(what, /45\.90\.28\.163/);
  assert.match(what, /abc123/);
  assert.strictEqual((html.match(/Removing this can alert whoever installed it/g) || []).length, 1);
  assert.doesNotMatch(html, /799-7233|88788/, 'the hotline lives in the help district');
  assert.match(html, /data-mark/);
  assert.strictEqual(t.calls.marked.at(-1).code, f.code);
});

test('LOOK CLOSER on something the person said they knew offers the refresher (the line the audit couldn’t trigger)', async () => {
  const { saveProfile, markKnown, emptyProfile } = await game('profile/player-profile.js');
  const { loadLessons } = await game('training.js');
  const storage = memStore();
  const T = '2026-10-18T00:00:00.000Z';
  saveProfile(storage, markKnown(emptyProfile(T), ['where-it-lives', 'who-made-it'], T), { seed: 99 });
  const lessonsDir = path.join(__dirname, '..', 'renderer', 'game');
  const loadTraining = () => loadLessons((spec) => import(pathToFileURL(path.join(lessonsDir, spec)).href));
  const f = finding('Unsigned helper', 'warning', { data: { label: 'x', program: '/tmp/x' }, made_by: [{ name: 'Unknown maker', verified: false }] });
  const doc = scan(mod('launch_agent_audit', [f]));
  const t = await setup(null, { storage, loadTraining });
  await tick(); await tick();
  t.ctl.show(doc, { id: 'city' });
  const { findingsToCity } = await game('findings-to-city.js');
  const id = findingsToCity(doc).districts.flatMap((d) => d.missions)[0].id;
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'clue:where' });
  t.click({ 'data-act': 'tag:closer' });
  assert.match(t.html(), /Want the 2 questions on Where it lives\?/);
  // No gap is recorded for it: saying "I'm not sure" isn't evidence.
  const { loadProfile } = await game('profile/player-profile.js');
  const p = loadProfile(storage, T);
  assert.ok(!(p.concepts['where-it-lives'].gaps && p.concepts['where-it-lives'].gaps.n));
});

test('clues: the maker in a few words, and what the check itself saw; LOOK CLOSER adds only the rows the clues didn’t show', async () => {
  const f = finding('Baba Is You.app was changed after it was signed', 'critical', { code: 'security.code_signature_audit.tampered',
    data: { name: 'Baba Is You', path: '/Applications/Baba Is You.app', detail: 'codesign --verify failed: /Applications/Baba Is You.app: a sealed resource is missing or invalid' },
    made_by: [{ subject: '/Applications/Baba Is You.app', name: 'AMZN Mobile LLC', verified: false, how: 'claims to be made by AMZN Mobile LLC; couldn’t verify' }] });
  const { cluesFor, scoutRead } = await game('clues.js');
  const clues = cluesFor(f);
  assert.deepStrictEqual(clues.find((c) => c.kind === 'maker').lines, ['AMZN Mobile LLC · not verified']);
  assert.deepStrictEqual(clues.find((c) => c.kind === 'saw').lines, ['a sealed resource is missing or invalid']);
  assert.match(scoutRead({ severity: 'critical', finding: f }, 'threat'), /the check saw this: a sealed resource is missing or invalid/);
  const doc = scan(mod('code_signature_audit', [f]));
  const t = await setup(doc);
  const { findingsToCity } = await game('findings-to-city.js');
  const id = findingsToCity(doc).districts.flatMap((d) => d.missions)[0].id;
  t.click({ 'data-go': `signal:${id}` });
  for (const k of ['maker', 'where', 'saw']) t.click({ 'data-act': `clue:${k}` });
  t.click({ 'data-act': 'tag:closer' });
  const ev = t.html().split('It stays in your queue.')[1].replace(/<wbr>/g, '');
  assert.doesNotMatch(ev, /<dt>Made by|<dt>Signature check said|<dt>Where/);
});

test('a district splits many items into missions of a few each; a waiting check is offered, not listed as couldn’t check', async () => {
  const many = Array.from({ length: 14 }, (_, i) => finding(`Task ${i}`, 'warning', { data: { label: `t${i}` } }));
  const mvt = mod('mvt_spyware_scan', [finding('1 device backup found (scan available)', 'info', { code: 'security.mvt_spyware_scan.mvt_scan_available' })]);
  const t = await setup(scan(mod('launch_agent_audit', many), mvt));
  t.click({ 'data-go': 'district:gatehouse' });
  const html = t.html();
  // 14 items, at most 4 per mission: four parts, folded into one district row (UX audit P1-4).
  assert.match(html, /4 parts · 14 items/);
  assert.strictEqual((html.split('mx-notes-label')[0].match(/data-go="mx:/g) || []).length, 1, 'one row for the four parts');
  assert.doesNotMatch(html, /5 parts/);
  assert.match(html, /WAITING FOR YOUR GO-AHEAD/);
  assert.doesNotMatch(html.split('WAITING FOR YOUR GO-AHEAD')[0], /COULDN’T CHECK HERE/);
});

test('city check names come from the scan (check_name), never the module id', async () => {
  const doc = scan(mod('code_signature_audit', [], { status: 'error', error: 'timed out after 60.0s', check_name: 'App signatures' }));
  const t = await setup(doc);
  assert.match(t.html(), /App signatures took too long/);
  assert.doesNotMatch(t.html(), /Code signature audit/);
});
