// UX round 2, the city: the evidence block on missions, LOOK CLOSER, district
// rows and the help district (held: no clipboard); one help-district name per
// install; kind-only deck filters; TO DO that follows the deck's chips; a
// HUD without seconds or empty counts; voices that fit their place; and
// Plain's "Your progress" without the Skills panel that repeated Lessons.
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const game = (f) => import(pathToFileURL(path.join(__dirname, '..', 'renderer', 'game', f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const memStore = () => { const s = {}; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, removeItem: (k) => { delete s[k]; } }; };
const load = (f) => JSON.parse(fs.readFileSync(path.join(__dirname, 'fixtures', f), 'utf8'));

const LAUNCH = {
  title: "Background task 'ai.hermes.gateway-deflock' runs from a hidden folder", severity: 'warning', category: 'security',
  code: 'security.launch_agent_audit.hidden_dir',
  description: "The background task 'ai.hermes.gateway-deflock' runs a program from /Users/ann/.hermes/venv/bin/python, which is inside a hidden folder. Hidden folders are often used by developers, but they can also be used to hide unwanted software.\n\nThis is not automatically dangerous, but you should verify that you installed this app.\n\nWhat to do: Open System Settings > General > Login Items & Extensions.",
  data: { label: 'ai.hermes.gateway-deflock', program: '/Users/ann/.hermes/venv/bin/python', plist: '/Users/ann/Library/LaunchAgents/ai.hermes.gateway-deflock.plist' },
  remediation: { title: 'Review and clean launchd persistence (LaunchAgents/LaunchDaemons)', safety_note: 'Removing this can alert whoever installed it.',
    steps: [{ number: 1, title: 'Remove high-risk background tasks', body: '' }] },
};
const mod = (name, findings, extra = {}) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings, ...extra });
const DOC = { schema_version: 1, platform: 'darwin', modules: [
  mod('launch_agent_audit', [LAUNCH, { ...LAUNCH, title: 'Login item: Amical', data: { label: 'a.one', plist: '/Library/LaunchAgents/a.one.plist' } },
    { ...LAUNCH, title: 'Login item: Amical', data: { label: 'a.two', plist: '/Library/LaunchAgents/a.two.plist' } }]),
  mod('stalkerware_scan', [{ title: 'mSpy is on this computer (app)', severity: 'critical', code: 'security.stalkerware_scan.monitoring_software_found',
    data: { stalkerware_name: 'mSpy', detected_as: 'app', location: '/Applications/mSpy.app' } }]),
  mod('code_signature_audit', [], { status: 'error', error: 'timed out after 60.0s', supported: true }),
] };

function stub({ mode = 'city', seed = 424242, commands = null } = {}) {
  const clicks = [];
  const frame = { innerHTML: '', addEventListener: (t, fn) => { if (t === 'click') clicks.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, innerHTML: '', getElementById: () => frame, addEventListener: () => {} };
  const calls = { commands: [] };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    addEventListener: () => {},
    QuietNotes: require('../renderer/quiet-notes.js'),
    FixFlow: { attach() {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach() {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode, citySeed: () => seed, showList() {}, docChanged: () => true, wantsSafety: () => true,
      startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: { recheckModule: async () => ({ ok: false }),
      ...(commands ? { moduleCommands: async (n) => { calls.commands.push(n); return commands; } } : {}) },
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    clicks.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, shadow, click, calls, html: () => frame.innerHTML };
}

async function setup(opts = {}, doc = DOC) {
  const { createController } = await game('controller.js');
  const t = stub(opts);
  const ctl = createController({ win: t.win, storage: memStore(), scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => [], loadDrillBank: async () => [] });
  await tick();
  ctl.show(doc, { id: 'city', title: 'Take back the city' });
  return { ...t, ctl };
}
const missionId = async (doc, title) => {
  const { findingsToCity } = await game('findings-to-city.js');
  const { splitHeld } = await game('held.js');
  return findingsToCity(splitHeld(doc).doc).districts.flatMap((d) => d.missions).find((m) => m.title === title).id;
};

test('a mission: WHAT IT IS is the evidence block and one line; no walkthrough source line, no generic prose', async () => {
  const t = await setup();
  t.click({ 'data-go': `mission:${await missionId(DOC, LAUNCH.title)}` });
  const html = t.html().replace(/<wbr>/g, ''); // break chances (evidence.js breakable)
  const what = html.split('WHAT IT IS')[1].split('</div></div>')[0] + html.split('WHAT IT IS')[1];
  assert.match(what, /class="evidence"/);
  assert.match(what, /<dt>Background task<\/dt><dd><code class="evidence-mono">ai\.hermes\.gateway-deflock<\/code>/);
  assert.match(what, /<dt>Runs<\/dt><dd><code class="evidence-mono">~\/\.hermes\/venv\/bin\/python<\/code>/);
  assert.match(html, /<p class="intel why">The background task &#39;ai\.hermes\.gateway-deflock&#39; runs a program from ~\/\.hermes\/venv\/bin\/python, which is inside a hidden folder\.<\/p>/);
  assert.doesNotMatch(html, /\/Users\/ann/, 'home folders read ~');
  assert.doesNotMatch(html, /Hidden folders are often used|not automatically dangerous/, 'the generic prose goes to the lesson');
  assert.doesNotMatch(html, /From the walkthrough/);
  // The description's "What to do" leads the walkthrough's steps, once.
  assert.strictEqual((html.match(/Login Items &amp; Extensions/g) || []).length, 1);
  assert.ok(html.indexOf('Login Items') > html.indexOf('YOUR MOVE'));
  // The removal warning, once, in game words.
  assert.strictEqual((html.match(/Removing this can alert whoever installed it/g) || []).length, 1);
  // Copy buttons on mono rows: fine on a mission (only held items get none).
  assert.match(html, /data-evidence-copy=/);
  assert.match(t.shadow.innerHTML, /<style>\s*\.evidence\{/, 'the block’s styles are in the shadow root once');
});

test('the commands a check ran arrive later and are drawn into the block in place', async () => {
  const t = await setup({ commands: [['/usr/bin/plutil', '-p', '/Library/LaunchAgents/x.plist']] });
  const els = [{ innerHTML: '', getAttribute: () => 'launch_agent_audit' }];
  t.frame.querySelectorAll = (sel) => (sel === '[data-ev-module]' ? els : []);
  t.click({ 'data-go': `mission:${await missionId(DOC, LAUNCH.title)}` });
  await tick(); await tick();
  assert.deepStrictEqual(t.calls.commands, ['launch_agent_audit']);
  // The path the command looked at stays in view.
  assert.match(els[0].innerHTML.replace(/<wbr>/g, ''), /<dt>Checked with<\/dt><dd><code class="evidence-mono"[^>]*>plutil -p \/Library\/LaunchAgents\/x\.plist<\/code>/);
});

test('missionText: the first sentence, the first paragraph, and the "What to do" text', async () => {
  const { missionText } = await game('views/briefing.js');
  const t = missionText(LAUNCH.description);
  assert.strictEqual(t.why, "The background task 'ai.hermes.gateway-deflock' runs a program from /Users/ann/.hermes/venv/bin/python, which is inside a hidden folder.");
  assert.strictEqual(t.todo, 'Open System Settings > General > Login Items & Extensions.');
  assert.deepStrictEqual(missionText(''), { why: '', lead: '', todo: '' });
});

test('LOOK CLOSER shows what the scan saw under the next move; before a tag, the clues stay a game', async () => {
  const t = await setup();
  const id = await missionId(DOC, LAUNCH.title);
  t.click({ 'data-go': `signal:${id}` });
  assert.doesNotMatch(t.html().split('sig-panel')[1], /class="evidence"/);
  t.click({ 'data-act': 'tag:closer' });
  const panel = t.html().split('sig-panel')[1];
  assert.match(panel, /It stays in your queue\.<\/p><div data-ev-module="launch_agent_audit"><section class="evidence"/);
});

test('P2-14: district rows carry one line of evidence, so two with one title can be told apart', async () => {
  const t = await setup();
  t.click({ 'data-go': 'district:gatehouse' });
  const html = t.html();
  assert.match(html, /Login item: Amical<small class="mission-detail"><code>a\.one<\/code><\/small>/);
  assert.match(html, /Login item: Amical<small class="mission-detail"><code>a\.two<\/code><\/small>/);
  const { renderDistrict } = await game('views/district.js');
  const d = { id: 'g', name: 'G', status: 'warn', missions: [1, 2].map((i) => ({ id: `m${i}`, title: 'Same', severity: 'warning' })), notes: [], fog: [], unfinished: [] };
  const plain = renderDistrict({ district: d, progress: { missions: {} }, scout: () => '' });
  assert.match(plain, /Same \(1 of 2\)/);
  assert.match(plain, /Same \(2 of 2\)/);
});

test('the help district: held evidence, large, with the paper line, and no clipboard anywhere', async () => {
  const t = await setup();
  t.click({ 'data-go': 'side' });
  const html = t.html();
  assert.match(html, /class="evidence evidence--held"/);
  assert.match(html, /Write this on paper or on another device\./);
  assert.match(html, /<dt>Name<\/dt><dd><span>mSpy<\/span>/);
  assert.doesNotMatch(html, /COPY TO WRITE DOWN|side-copy|data-evidence-copy|Copy all/);
  const src = fs.readFileSync(path.join(__dirname, '../renderer/game/controller.js'), 'utf8');
  assert.doesNotMatch(src, /side-copy|heldText|copyHeld/, 'no clipboard path for a held item is left');
});

test('one install, one help-district name: the mission warning, the deck tile, the notice and the district itself', async () => {
  const { pickDistrict } = await game('district-names.js');
  for (const seed of [1, 7, 424242]) {
    const name = pickDistrict(seed).name;
    const t = await setup({ seed });
    const deck = t.html();
    assert.ok(deck.includes(`${name.toUpperCase()} ▶`), 'the tile');
    assert.ok(deck.includes(`Something new in ${name}.`), 'the notice');
    t.click({ 'data-go': `mission:${await missionId(DOC, LAUNCH.title)}` });
    assert.ok(t.html().includes(`Stop by ${name} before you change it.`), 'the mission’s warning');
    t.click({ 'data-go': 'side' });
    assert.ok(t.html().includes(`id="side-title" tabindex="-1">${name.toUpperCase()}</h2>`), 'the district’s own header');
    const others = pickDistrict(seed + 1).name;
    if (others !== name) assert.ok(!t.html().includes(others.toUpperCase()));
  }
});

test('voices fit their place: every name has one, and no dome over a print shop', async () => {
  const { NAMES, VOICES, VOICE_OF, pickDistrict } = await game('district-names.js');
  for (const n of NAMES) assert.ok(VOICES.some((v) => v.id === VOICE_OF[n]), n);
  for (const v of VOICES) assert.doesNotMatch(`${v.hello} ${v.bye}`, /dome|soldering/i, 'lines that only fit one kind of place');
  assert.strictEqual(VOICE_OF['The Print Shop'], 'workshop');
  for (let seed = 1; seed <= 200; seed += 1) {
    const d = pickDistrict(seed);
    assert.strictEqual(d.voice.id, VOICE_OF[d.name]);
  }
});

test('deck filters are kinds only; the districts are reached from their cards', async () => {
  const t = await setup();
  const q = t.html().split('INCOMING SIGNALS')[1].split('deck-city')[0];
  assert.match(q, /data-act="sev:all"/);
  assert.doesNotMatch(q, /data-go="filter:/);
  assert.match(t.html(), /data-go="district:gatehouse"/);
});

test('TO DO follows the deck: tagging NOTED (or MINE) takes a row off the HUD as off the chip', async () => {
  const doc = load('replay-full.json');
  const t = await setup({}, doc);
  const num = (html, re) => { const m = re.exec(html); return m ? Number(m[1]) : 0; };
  const todoDeck = () => num(t.html(), /INCOMING SIGNALS · (\d+) TO DO/);
  const hudTodo = () => {
    t.click({ 'data-go': 'district:gatehouse' });
    return num(t.html(), /<b>(\d+)<\/b> <small>TO DO<\/small>/);
  };
  const before = todoDeck();
  assert.ok(before > 0);
  assert.strictEqual(hudTodo(), before);
  t.click({ 'data-go': 'map' });
  t.click({ 'data-act': 'sev:couldnt' });
  // One a person can note (a monitoring check that couldn't run never is).
  const MON = /stalkerware_scan|mvt_spyware_scan|keylogger_indicators/;
  const id = [...t.html().matchAll(/data-go="signal:(couldnt\|[^"]+)"/g)].map((m) => m[1]).find((x) => !MON.test(x));
  assert.ok(id, 'a couldn’t-check row to note');
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'tag:noted' });
  t.click({ 'data-act': 'close-signal' });
  t.click({ 'data-act': 'sev:all' });
  assert.strictEqual(todoDeck(), before - 1);
  assert.strictEqual(hudTodo(), before - 1);
  // Repeats count once here: said in one short line when it makes the list's count larger.
  t.click({ 'data-go': 'map' });
  const { REPEATS_LINE } = await game('views/deck.js');
  const { repeatsMerged } = await game('signals.js');
  assert.strictEqual(t.html().includes(REPEATS_LINE), repeatsMerged(await cityOf(doc)) > 0);
});
async function cityOf(doc) {
  const { findingsToCity } = await game('findings-to-city.js');
  const { splitHeld } = await game('held.js');
  const { foldPartly } = await game('signals.js');
  return findingsToCity(require('../renderer/quiet-notes.js').quietDoc(foldPartly(splitHeld(doc).doc).doc, 'city'));
}

test('the HUD keeps to the essentials: no zero CONFIRMED or YOU REPORTED; LAST SWEEP without seconds; RE-SWEEP sits with it', async () => {
  const { renderHud } = await game('views/hud.js');
  const hud = renderHud({ title: 'X', city: { districts: [] }, progress: { missions: {} }, counts: { confirmed: 0, reported: 0 }, rank: { name: 'R', points: 0 }, todo: 3 });
  assert.doesNotMatch(hud, /CONFIRMED|YOU REPORTED/);
  assert.match(renderHud({ title: 'X', city: { districts: [] }, progress: { missions: {} }, counts: { confirmed: 2, reported: 1 }, rank: { name: 'R', points: 0 } }),
    /<b>2<\/b> <small>CONFIRMED<\/small>[\s\S]*<b>1<\/b> <small>YOU REPORTED<\/small>/);
  const { renderDeck } = await game('views/deck.js');
  const deck = renderDeck({ title: 'X', rank: { name: 'R', points: 0 }, lastSweep: { at: '2026-10-18T23:40:37Z', checks: 10, fog: 1 } });
  const stat = /<span class="stat grey sweep-stat">([\s\S]*?)<\/span>/.exec(deck)[1];
  assert.doesNotMatch(stat, /:\d\d:\d\d/, 'no seconds');
  assert.match(stat, /data-act="resweep"/);
  assert.match(stat, /class="btn-t" data-act="resweep"/, 'a quiet button, not a second primary');
});

test('P3-34: Plain’s "Your progress" has no Skills panel, and says where the lessons are played', async () => {
  const { renderProfile } = await game('views/profile.js');
  const { PLAIN_WHERE } = await game('views/profile-core.js');
  const summary = { rank: { name: 'R', points: 0, level: 1, of: 5, next: null, toNext: 0 }, lessons: [{ id: 'a', title: 'A', concepts: [{ id: 'x', state: 'not-yet' }] }],
    skills: [{ title: 'Skill S', depth: 'introduced' }], drills: { tried: 0, total: 0, over: 0, under: 0, lastTen: { of: 0, right: 0 } },
    city: { reclaimed: 0, later: 0, yours: 0, lastSweep: null }, migrations: [] };
  const plain = renderProfile({ summary, theme: 'plain' });
  assert.ok(plain.includes(PLAIN_WHERE));
  assert.ok(!plain.includes('Skill S'));
  const gameHtml = renderProfile({ summary, theme: 'game' });
  assert.ok(gameHtml.includes('Skill S') && !gameHtml.includes(PLAIN_WHERE));
});
