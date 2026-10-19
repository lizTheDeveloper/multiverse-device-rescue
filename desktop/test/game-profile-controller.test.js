// The player profile wired into game mode: the recipe box on disk, adaptive
// lesson visits, every answer kept as evidence, "learned" only from the IRT
// rule, city mode's skipped families, and a save problem said on screen.
// Stubbed window, as in game-deck-controller.test.js.
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { pathToFileURL } = require('url');
const { recordingStore, forbiddenWrites, FORBIDDEN_ON_DISK } = require('./disk-words.js');
const { PROFILE_KEY, savedProfile } = require('./profile-read.js');

const OLD_KEY = 'device-rescue.game.v1';
const NOW = '2026-10-18T12:00:00.000Z';
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
const importModule = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME, spec)).href);
const game = (f) => import(pathToFileURL(path.join(GAME, f)).href);
const tick = () => new Promise((r) => setTimeout(r, 0));
const f = (title, severity, data = {}, extra = {}) => ({ title, description: `${title}: what it is.`, severity, category: 'security', data, ...extra });
const mod = (name, findings) => ({ name, category: 'security', status: 'ok', error: null, supported: true, findings });
const scan = (...mods) => ({ schema_version: 1, platform: 'darwin', modules: mods });
const drill = (id, answer) => ({ id, district: 'gatehouse', severity: 'warning', modules: [], title: `Drill ${id}`, setup: '',
  clues: { maker: { name: 'Unknown maker', verified: false, how: 'unsigned' }, path: '/tmp/d', what: 'Practice only.', when: null },
  answer, why: `Why ${id}.`, sources: [] });
const DRILLS = [drill('upd8r-hidden-cache', 'threat'), drill('zoom-helper-signed', 'mine')];
const DOC = scan(mod('launch_agent_audit', [f('Unsigned helper', 'critical', { program: '/tmp/x' },
  { code: 'security.launch_agent_audit.tmp', made_by: [{ name: 'Unknown maker', verified: false, how: 'unsigned' }] })]));
// What city mode must never put on a game screen from a lesson.
const KNOWN_PERSON = /frightened|someone you know|partner|housemate|family member|safety note/i;

function stub(mode) {
  const listeners = [];
  const keys = [];
  const focused = [];
  // A control is found when the drawn HTML has it: enough to see where focus goes.
  const found = (sel) => {
    const html = frame.innerHTML;
    let m = /^\[([a-z-]+)="([^"]*)"\]$/.exec(sel);
    if (m && html.includes(`${m[1]}="${m[2]}"`)) return m;
    m = /^#([a-z-]+)$/.exec(sel);
    if (m && html.includes(`id="${m[1]}"`)) return m;
    return sel === '[data-autofocus]' && html.includes('data-autofocus') ? [sel] : null;
  };
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); if (type === 'keydown') keys.push(fn); },
    querySelector: (sel) => {
      if (!found(sel)) return null;
      const html = frame.innerHTML;
      const what = sel === '[data-autofocus]' ? /<[^>]*data-autofocus[^>]*>/.exec(html)[0] : sel;
      return { focus: () => focused.push(what), getAttribute: () => null };
    },
    querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const view = { hidden: false };
  const host = { attachShadow: () => shadow, closest: (sel) => (sel === '[hidden]' && view.hidden ? host : null) };
  const calls = { clipboard: [], objectUrls: 0, downloads: [] };
  const win = {
    document: { getElementById: () => host, createElement: () => ({ click() { calls.downloads.push(this.download); } }) },
    URL: { createObjectURL: () => { calls.objectUrls += 1; return 'blob:test'; }, revokeObjectURL: () => {} },
    Blob: class { constructor(parts) { this.parts = parts; } },
    navigator: { clipboard: { writeText: async (text) => { calls.clipboard.push(text); } } },
    setTimeout: (fn) => setTimeout(fn, 0),
    FixFlow: { attach: () => {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: () => {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode.now, showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: {},
  };
  // `checked`: for a checkbox, whether it is ticked after the click.
  const click = (attrs, checked) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null), checked: !!checked };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  const key = (k) => keys.forEach((fn) => fn({ key: k, target: { closest: () => null }, preventDefault() {} }));
  return { win, frame, click, key, view, calls, focused };
}

// `publishReady`: the school side ready, through the test seams (the app
// itself always uses PUBLISH_READY, which is false).
async function readySeam() {
  const [core, pub] = await Promise.all([game('views/profile-core.js'), game('profile/publish.js')]);
  return { ready: true, renderProfile: core.createProfileRenderer(true), renderPublishSheet: core.createPublishSheet(true),
    deliver: pub.createPublisher({ ready: true }) };
}

async function setup({ storage = recordingStore(), mode = 'standard', doc = DOC, loadDrillBank = async () => DRILLS, publishReady = false } = {}) {
  const [{ createController }, training] = await Promise.all([game('controller.js'), game('training.js')]);
  const lessons = await training.loadLessons(importModule);
  const m = { now: mode };
  const t = stub(m);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons, loadDrillBank, ...(publishReady ? { publishing: await readySeam() } : {}) });
  await tick();
  if (doc) ctl.show(doc, { id: 'unsure' });
  return { ...t, ctl, storage, lessons, mode: m, html: () => t.frame.innerHTML, lesson: (id) => lessons.find((l) => l.id === id) };
}
const correctIndex = (q) => q.options.findIndex((o) => o.correct);
const qCount = (html) => Number((/QUESTION \d+ OF (\d+)/.exec(html) || [])[1]);
const escaped = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
// Answers the visit on screen to its end (rightly), returning the prompts it asked.
function answerVisit(t, { finish = true } = {}) {
  const asked = [];
  const n = qCount(t.html());
  for (let i = 0; i < n; i += 1) {
    const all = t.lessons.flatMap((l) => l.questions.flatMap((q) => [q, ...(q.variants || [])]));
    const q = all.find((x) => t.html().includes(escaped(x.prompt)) || t.html().includes(x.prompt));
    assert.ok(q, `question ${i + 1} is one of the lessons' items`);
    asked.push(q);
    t.click({ 'data-act': `answer:${correctIndex(q)}` });
    if (i < n - 1) t.click({ 'data-act': 'next-question' });
    else if (finish) t.click({ 'data-act': 'finish-lesson' });
  }
  return asked;
}

test('the profile is a recipe box from the first run: nothing literal written; city mode retires the old store, standard keeps it', async () => {
  const v3 = JSON.stringify({ version: 3, missions: {}, lessons: { 'locked-door': { completedAt: '2026-10-01T00:00:00.000Z' } },
    deck: { points: 120, rank: 1, drills: { right: 1, tried: 2 }, tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] } });
  const city = await setup({ storage: recordingStore({ [OLD_KEY]: v3 }), mode: 'city' });
  assert.strictEqual(city.storage.data[OLD_KEY], undefined);
  assert.strictEqual(savedProfile(city.storage).rank.points, 120);
  assert.deepStrictEqual(forbiddenWrites(city.storage), []);
  const std = await setup({ storage: recordingStore({ [OLD_KEY]: v3 }), mode: 'standard' });
  assert.strictEqual(std.storage.data[OLD_KEY], v3, 'kept, frozen, for an older build');
  assert.deepStrictEqual(forbiddenWrites(std.storage), []);
  assert.ok(std.storage.data[PROFILE_KEY].startsWith('{"kitchen":'));
});

test('switching to city mode retires the old store at once (profileModeChanged)', async () => {
  const v3 = JSON.stringify({ version: 3, missions: {}, lessons: {}, deck: { points: 5, rank: 0, drills: { right: 0, tried: 0 }, tags: {}, confirmed: {}, once: {}, sweep: { at: null, keys: {} }, sweeps: [] } });
  const t = await setup({ storage: recordingStore({ [OLD_KEY]: v3 }), mode: 'standard' });
  assert.strictEqual(t.storage.data[OLD_KEY], v3);
  t.mode.now = 'city';
  t.ctl.profileModeChanged();
  assert.strictEqual(t.storage.data[OLD_KEY], undefined);
  assert.strictEqual(savedProfile(t.storage).rank.points, 5);
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('a first visit is the lesson as written; the next asks variants; every answer is saved as evidence', async () => {
  const t = await setup();
  const l = t.lesson('couldnt-check');
  t.click({ 'data-go': 'lesson:couldnt-check' });
  assert.ok(t.html().includes(`QUESTION 1 OF ${l.questions.length}`));
  l.questions.forEach((q, n) => {
    t.click({ 'data-act': `answer:${correctIndex(q)}` });
    t.click({ 'data-act': n === l.questions.length - 1 ? 'finish-lesson' : 'next-question' });
  });
  const p = savedProfile(t.storage);
  const answered = Object.values(p.concepts).flatMap((c) => (c.seen || []).map((e) => e[0]));
  assert.deepStrictEqual(answered.sort(), l.questions.map((q) => q.key).sort(), 'each question as written, once');
  assert.ok(p.lessons['couldnt-check'].visited, 'the visit makes it done for the game');
  t.click({ 'data-go': 'lesson:couldnt-check' });
  const variants = l.questions.flatMap((q) => q.variants.map((v) => v.prompt));
  assert.ok(variants.some((v) => t.html().includes(escaped(v)) || t.html().includes(v)), 'the second visit asks a variant');
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('the drill bank failing to load still leaves lesson visits measured', async () => {
  const t = await setup({ doc: null, loadDrillBank: () => Promise.reject(new Error('no drills')) });
  t.click({ 'data-go': 'lesson:locked-door' });
  t.click({ 'data-act': 'answer:0' });
  assert.deepStrictEqual(savedProfile(t.storage).concepts['auto-updates'].seen.map((e) => e[0]), ['update-where']);
});

test('city mode: the families about someone the person knows are never asked, drawn or counted', async () => {
  const t = await setup({ mode: 'city' });
  const l = t.lesson('whos-on-wifi');
  const skipped = l.questions.filter((q) => q.key === 'cut-off-order' || q.key === 'remove-everyone');
  assert.strictEqual(skipped.length, 2, 'the lesson still has both families (standard mode asks them)');
  const skippedKeys = new Set(skipped.flatMap((q) => [q.key, ...q.variants.map((v) => v.key)]));
  // Visit after visit, nothing from those families reaches the screen.
  for (let visit = 0; visit < 4; visit += 1) {
    t.click({ 'data-go': 'lesson:whos-on-wifi' });
    if (visit === 0) assert.strictEqual(qCount(t.html()), l.questions.length - 2, 'the first visit is the lesson as written, without them');
    assert.doesNotMatch(t.html(), KNOWN_PERSON);
    const asked = answerVisit(t);
    for (const q of asked) assert.ok(!skippedKeys.has(q.key), `${q.key} is not asked in city mode`);
  }
  const p = savedProfile(t.storage);
  const answered = Object.values(p.concepts).flatMap((c) => (c.seen || []).map((e) => e[0]));
  assert.ok(answered.length > 0);
  assert.ok(answered.every((k) => !skippedKeys.has(k)));
  assert.strictEqual(p.concepts['cut-off-order'], undefined, 'its concept never gets a gap or an answer');
  // Done for the game, with nothing waiting: the Training Grounds shows it DONE.
  t.click({ 'data-go': 'training' });
  assert.match(t.html(), /class="lesson done[^"]*" data-go="lesson:whos-on-wifi"/);
  assert.doesNotMatch(t.html(), KNOWN_PERSON);
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);

  // The same lesson in standard mode asks every family.
  const std = await setup({ mode: 'standard' });
  std.click({ 'data-go': 'lesson:whos-on-wifi' });
  assert.strictEqual(qCount(std.html()), l.questions.length);
});

test('a player whose concepts are learned (by the IRT rule alone) is not routed back to lessons, and a DONE district opens no quiz', async () => {
  const [pp, ib, training] = await Promise.all([game('profile/player-profile.js'), game('profile/item-bank.js'), game('training.js')]);
  const lessons = await training.loadLessons(importModule);
  const bank = ib.buildBank(lessons, DRILLS);
  // Every item answered right, twice (over two visits' worth): evidence only.
  // No lesson is marked visited.
  let p = pp.emptyProfile(NOW);
  for (let pass = 0; pass < 2; pass += 1) {
    for (const [key, it] of bank.items) if (it.kind === 'lesson') p = pp.recordAnswer(p, bank, key, true, NOW);
  }
  for (const c of bank.concepts.keys()) {
    if ([...bank.lessons.values()].some((l) => l.concepts.includes(c))) assert.strictEqual(pp.conceptState(p, bank, c), 'learned', c);
  }
  assert.deepStrictEqual(Object.keys(p.lessons), [], 'nothing visited');
  const storage = recordingStore();
  assert.strictEqual(pp.saveProfile(storage, p, { seed: 4242, mode: 'standard' }), true);

  const t = await setup({ storage, doc: null });
  // The Training Grounds: every lesson DONE, none waiting to START.
  t.ctl.showTraining({ id: 'unsure' });
  for (const l of lessons) assert.match(t.html(), new RegExp(`class="lesson done[^"]*" data-go="lesson:${l.id}"`), l.id);
  assert.doesNotMatch(t.html(), /START ▶/);
  // The sweep: every district with a lesson reads as done, with only the optional review.
  t.ctl.showBoss();
  assert.doesNotMatch(t.html(), /data-go="learn:/, 'no district card opens a quiz');
  assert.match(t.html(), /data-go="review:gatehouse"/);
  // A stale click on a done district opens nothing.
  t.click({ 'data-go': 'learn:gatehouse' });
  assert.doesNotMatch(t.html(), /QUESTION \d+ OF/);
  // Finishing the checkup lands in the city, not the lessons.
  t.ctl.scanDone(DOC, { id: 'unsure' });
  assert.match(t.html(), /YOUR COMPUTER/, 'the deck');
  assert.doesNotMatch(t.html(), /QUESTION \d+ OF/);
});

test('a save that fails says so on screen, calmly; in city mode only in game words', async () => {
  const broken = () => {
    const s = recordingStore();
    s.setItem = () => { throw new Error('quota'); };
    return s;
  };
  const city = await setup({ storage: broken(), mode: 'city' });
  assert.match(city.html(), /The city couldn’t save your last move\. It keeps trying\./);
  const notice = (/<p class="link-notice save-notice"[\s\S]*?<\/p>/.exec(city.html()) || [''])[0];
  assert.ok(notice);
  assert.doesNotMatch(notice.replace(/<[^>]+>/g, ' '), FORBIDDEN_ON_DISK);
  assert.doesNotMatch(notice, /profile|progress|monitor/i);
  // Every message city mode can show is in game words.
  const { saveProblemText } = await game('controller.js');
  for (const code of ['encode', 'too-big', 'spare', 'write', 'salvaged', 'spare-full', 'unreadable', 'unreadable-too-big', 'old-kept', 'anything-else']) {
    assert.doesNotMatch(saveProblemText(code, true), /profile|progress|safety|monitor|partner|\bsafe\b|watch|stalk/i, code);
    assert.doesNotMatch(saveProblemText(code, true) + saveProblemText(code, false), /just now|next/i, code);
  }
  city.click({ 'data-act': 'dismiss-save-notice' });
  assert.doesNotMatch(city.html(), /couldn’t save/);
  const std = await setup({ storage: broken(), mode: 'standard' });
  assert.match(std.html(), /Your progress couldn’t be saved\. It keeps trying\./);
});

test('a save that works again clears the save notice', async () => {
  const s = recordingStore();
  const real = s.setItem;
  let fail = true;
  s.setItem = (k, v) => { if (fail) throw new Error('quota'); real(k, v); };
  const t = await setup({ storage: s });
  assert.match(t.html(), /couldn’t be saved/);
  fail = false;
  t.click({ 'data-go': 'lesson:locked-door' });
  t.click({ 'data-act': 'answer:0' });
  assert.doesNotMatch(t.html(), /couldn’t be saved/);
  assert.ok(savedProfile(s).concepts['auto-updates']);
});

// Every concept learned by evidence alone, saved to a fresh store.
async function learnedStore(lessons) {
  const [pp, ib] = await Promise.all([game('profile/player-profile.js'), game('profile/item-bank.js')]);
  const bank = ib.buildBank(lessons, DRILLS);
  let p = pp.emptyProfile(NOW);
  for (let pass = 0; pass < 2; pass += 1) {
    for (const [key, it] of bank.items) if (it.kind === 'lesson') p = pp.recordAnswer(p, bank, key, true, NOW);
  }
  const storage = recordingStore();
  pp.saveProfile(storage, p, { seed: 4242, mode: 'city' });
  return storage;
}

test('city mode opens on the command deck, with or without learned concepts; the sweep is the main action and nothing routes to lessons', async () => {
  const training = await game('training.js');
  const lessons = await training.loadLessons(importModule);
  for (const storage of [recordingStore(), await learnedStore(lessons)]) {
    const t = await setup({ storage, mode: 'city', doc: null });
    t.ctl.showHome({ id: 'city', title: 'Take back the city' });
    const home = t.html();
    assert.match(home, /class="panel pre-sweep"/);
    assert.match(home, /class="btn-p" data-act="start-checkup"/, 'the sweep is the main action');
    assert.match(home, /<button type="button" data-go="training">TRAINING<\/button>/, 'Training is reachable from the deck');
    assert.doesNotMatch(home, /QUESTION \d+ OF|class="lesson[ "]/, 'not a lesson, not the Training Grounds');
    assert.doesNotMatch(home, KNOWN_PERSON);
    // A district's lesson is a visit from the deck, and finishing it comes back to the deck.
    const learn = /data-go="(learn|review):([a-z-]+)"/.exec(home);
    assert.ok(learn, 'districts link their lessons');
    t.click({ 'data-go': `${learn[1]}:${learn[2]}` });
    assert.match(t.html(), /QUESTION 1 OF/);
    answerVisit(t);
    assert.match(t.html(), /class="panel pre-sweep"/, 'back on the deck');
    // Leaving the DRILL RANGE and a failed checkup also come back to the deck.
    t.click({ 'data-go': 'range' });
    t.click({ 'data-act': 'leave-range' });
    assert.match(t.html(), /class="panel pre-sweep"/);
    t.ctl.showBoss();
    t.ctl.scanFailed('The checkup stopped.');
    assert.match(t.html(), /class="panel pre-sweep"[\s\S]*The checkup stopped\./);
  }
  // With every concept learned, every district offers only the optional review.
  const t = await setup({ storage: await learnedStore(lessons), mode: 'city', doc: null });
  t.ctl.showHome({ id: 'city', title: 'Take back the city' });
  assert.doesNotMatch(t.html(), /data-go="learn:/);
  assert.match(t.html(), /data-go="review:gatehouse"/);
});

test('no display mode chosen yet: the families about someone the person knows stay hidden', async () => {
  const t = await setup({ mode: null });
  const l = t.lesson('whos-on-wifi');
  t.click({ 'data-go': 'lesson:whos-on-wifi' });
  assert.strictEqual(qCount(t.html()), l.questions.length - 2);
  assert.doesNotMatch(t.html(), KNOWN_PERSON);
  answerVisit(t);
  assert.doesNotMatch(t.html(), KNOWN_PERSON);
});

test('profileModeChanged saves, but draws only while the city is on screen', async () => {
  const t = await setup();
  t.click({ 'data-go': 'training' });
  t.view.hidden = true;
  t.frame.innerHTML = 'untouched';
  t.mode.now = 'city';
  t.ctl.profileModeChanged();
  assert.strictEqual(t.html(), 'untouched');
  t.view.hidden = false;
  t.ctl.profileModeChanged();
  assert.notStrictEqual(t.html(), 'untouched');
});

test('the pre-sweep panel and the top bar agree, with or without an earlier sweep', async () => {
  const v3 = JSON.stringify({ version: 3, missions: {}, lessons: {}, deck: { points: 0, rank: 0, drills: { right: 0, tried: 0 }, tags: {}, confirmed: {}, once: {},
    sweep: { at: '2026-10-17T09:00:00.000Z', keys: {} }, sweeps: [{ at: '2026-10-17T09:00:00.000Z', checks: 40, critical: 0, warning: 1, fog: 0, open: 1, secured: 3, districts: 5 }] } });
  for (const storage of [recordingStore(), recordingStore({ [OLD_KEY]: v3 })]) {
    const t = await setup({ storage, mode: 'city', doc: null });
    t.ctl.showHome({ id: 'city', title: 'Take back the city' });
    assert.ok((t.html().match(/NO SWEEP YET/g) || []).length <= 1, 'said once at most');
    assert.match(t.html(), /class="panel pre-sweep"><div class="label">SWEEP THE CITY</);
  }
});

test('a standard-mode worry after the city home: a failed scan lands on the Training Grounds, not the deck', async () => {
  const t = await setup({ mode: 'standard', doc: null });
  t.ctl.showHome({ id: 'city', title: 'Take back the city' });
  t.ctl.newWorry({ id: 'wifi', title: 'Wi-Fi' });
  t.ctl.showBoss();
  t.ctl.scanFailed('The checkup stopped.');
  assert.doesNotMatch(t.html(), /class="panel pre-sweep"/);
  assert.match(t.html(), /data-go="lesson:/, 'the Training Grounds');
});

test('a wrong drill on a concept the person said they knew offers 2 questions; YES opens them; STILL KNOW IT declines', async () => {
  const { saveProfile, markKnown, emptyProfile } = await import('../renderer/game/profile/player-profile.js');
  const storage = recordingStore();
  saveProfile(storage, markKnown(emptyProfile('2026-10-18T00:00:00.000Z'), ['where-it-lives'], '2026-10-18T00:00:00.000Z'), { seed: 99 });
  const t = await setup({ storage });
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-go': 'signal:drill:upd8r-hidden-cache' });
  t.click({ 'data-act': 'tag:mine' });
  assert.match(t.html(), /Want the 2 questions on Where it lives\?/);
  assert.match(t.html(), /data-act="offer-yes:where-it-lives"/);
  t.click({ 'data-act': 'offer-yes:where-it-lives' });
  assert.match(t.html(), /QUESTION 1 OF 2/);
  const p = savedProfile(t.storage);
  assert.ok(p.concepts['where-it-lives'].offered, 'the offer is remembered, so it isn’t made again this sweep');
  assert.strictEqual(p.drills.calls.threat.mine, 1);
});

test('STILL KNOW IT records the decline and the offer goes', async () => {
  const { saveProfile, markKnown, emptyProfile } = await import('../renderer/game/profile/player-profile.js');
  const storage = recordingStore();
  saveProfile(storage, markKnown(emptyProfile('2026-10-18T00:00:00.000Z'), ['where-it-lives'], '2026-10-18T00:00:00.000Z'), { seed: 99 });
  const t = await setup({ storage });
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-go': 'signal:drill:upd8r-hidden-cache' });
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'offer-no:where-it-lives' });
  assert.doesNotMatch(t.html(), /Want the 2 questions/);
  assert.strictEqual(savedProfile(t.storage).concepts['where-it-lives'].offered.declined, 1);
});

test('when Scout reads a real finding differently, the profile notes a gap for its concepts', async () => {
  const t = await setup();
  const { buildSignals } = await import('../renderer/game/signals.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const id = buildSignals(findingsToCity(DOC), null).find((x) => x.kind === 'real').id;
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'tag:mine' }); // the scan marked it critical: Scout reads THREAT
  const p = savedProfile(t.storage);
  assert.strictEqual(p.concepts['who-made-it'].gaps.call, 1);
  assert.ok(!JSON.stringify(p.concepts).includes('/tmp/x'), 'only the concept, never the finding');
});

test('city mode: an offer and its questions write nothing forbidden, come back to the range, and a hidden concept is never offered', async () => {
  const { saveProfile, markKnown, emptyProfile } = await import('../renderer/game/profile/player-profile.js');
  const storage = recordingStore();
  saveProfile(storage, markKnown(emptyProfile('2026-10-18T00:00:00.000Z'), ['where-it-lives', 'cut-off-order'], '2026-10-18T00:00:00.000Z'), { seed: 99 });
  const t = await setup({ storage, mode: 'city' });
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-go': 'signal:drill:upd8r-hidden-cache' });
  t.click({ 'data-act': 'tag:mine' });
  assert.doesNotMatch(t.html(), /offer-yes:cut-off-order/);
  t.click({ 'data-act': 'offer-yes:where-it-lives' });
  assert.match(t.html(), /QUESTION 1 OF 2/);
  assert.doesNotMatch(t.html(), KNOWN_PERSON);
  answerVisit(t);
  assert.match(t.html(), /data-act="next-drill"|DRILL RANGE/, 'the questions come back to the range');
  // A hidden concept can't be opened by a stale or forged act either.
  t.click({ 'data-act': 'offer-yes:cut-off-order' });
  assert.doesNotMatch(t.html(), /QUESTION 1 OF/);
  assert.deepStrictEqual(forbiddenWrites(storage), []);
});

test('re-tagging the same finding in a sweep notes one call gap, not one per tag', async () => {
  const t = await setup();
  const { buildSignals } = await import('../renderer/game/signals.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const id = buildSignals(findingsToCity(DOC), null).find((x) => x.kind === 'real').id;
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'clue:maker' });
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'tag:closer' });
  t.click({ 'data-act': 'tag:mine' });
  assert.strictEqual(savedProfile(t.storage).concepts['who-made-it'].gaps.call, 1);
});

test('a drill answered again in the range is practice: only its first answer this sweep is evidence', async () => {
  const t = await setup();
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-act': 'tag:mine' });
  t.click({ 'data-act': 'next-drill' });
  t.click({ 'data-act': 'next-drill' }); // two drills: back to the first one
  t.click({ 'data-act': 'tag:threat' });
  const p = savedProfile(t.storage);
  const total = Object.values(p.drills.calls).flatMap((row) => Object.values(row)).reduce((a, b) => a + b, 0);
  assert.strictEqual(total, 1);
  assert.strictEqual(p.drills.recent.length, 1);
});

test('city mode: a call gap from the lessons behind a finding never touches the hidden concept', async () => {
  const doc = scan(mod('lan_device_inventory', [f('Unknown device on the network', 'critical', { ip: '192.168.1.40' })]));
  const t = await setup({ mode: 'city', doc });
  const { buildSignals } = await import('../renderer/game/signals.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const id = buildSignals(findingsToCity(doc), null).find((x) => x.kind === 'real').id;
  t.click({ 'data-go': `signal:${id}` });
  t.click({ 'data-act': 'tag:mine' }); // no clues opened: the concepts of the lessons that teach this module
  const p = savedProfile(t.storage);
  assert.strictEqual(p.concepts['wifi-and-mining'].gaps.call, 1);
  assert.ok(!(p.concepts['cut-off-order'] && p.concepts['cut-off-order'].gaps));
  assert.doesNotMatch(t.html(), /offer-yes:cut-off-order/);
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('monitoring software gives no call gap and no offer, even from a made-up click', async () => {
  const doc = scan(mod('stalkerware_scan', [f('Monitoring app found', 'critical', { program: '/tmp/m' })]),
    mod('launch_agent_audit', [f('Unsigned helper', 'critical', { program: '/tmp/x' })]));
  const t = await setup({ doc });
  const { buildSignals } = await import('../renderer/game/signals.js');
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const city = findingsToCity(doc);
  assert.ok(!buildSignals(city, null).some((x) => x.module === 'stalkerware_scan'));
  for (const m of city.districts.flatMap((d) => d.missions || []).filter((x) => x.module === 'stalkerware_scan')) {
    t.click({ 'data-go': `signal:${m.id}` });
    t.click({ 'data-act': 'clue:maker' });
    t.click({ 'data-act': 'tag:mine' });
  }
  const { callConcepts } = await import('../renderer/game/profile/player-profile.js');
  const { buildBank } = await import('../renderer/game/profile/item-bank.js');
  assert.deepStrictEqual(callConcepts(buildBank(t.lessons, DRILLS), 'stalkerware_scan', ['maker', 'where']), []);
  const p = savedProfile(t.storage);
  assert.ok(Object.values(p.concepts).every((c) => !c.gaps && !c.offered));
  assert.doesNotMatch(t.html(), /offer-yes/);
});

test('an offer answer that isn’t the offer on screen does nothing', async () => {
  const { saveProfile, markKnown, emptyProfile } = await import('../renderer/game/profile/player-profile.js');
  const storage = recordingStore();
  saveProfile(storage, markKnown(emptyProfile('2026-10-18T00:00:00.000Z'), ['where-it-lives', 'who-made-it'], '2026-10-18T00:00:00.000Z'), { seed: 99 });
  const t = await setup({ storage });
  // Stale: nothing offered yet.
  t.click({ 'data-act': 'offer-no:where-it-lives' });
  assert.ok(!(savedProfile(t.storage).concepts['where-it-lives'] || {}).offered);
  t.click({ 'data-go': 'range' });
  await tick();
  t.click({ 'data-go': 'signal:drill:upd8r-hidden-cache' });
  t.click({ 'data-act': 'tag:mine' });
  // Mismatched: the offer is on where it lives.
  t.click({ 'data-act': 'offer-no:who-made-it' });
  t.click({ 'data-act': 'offer-yes:who-made-it' });
  assert.match(t.html(), /data-act="offer-yes:where-it-lives"/);
  assert.doesNotMatch(t.html(), /QUESTION 1 OF/);
  const p = savedProfile(t.storage);
  assert.ok(!(p.concepts['who-made-it'] || {}).offered);
  assert.strictEqual(p.concepts['where-it-lives'].offered.declined, 0);
});

test('drill items are the same in the full bank and the city bank, so drill evidence is measured alike', async () => {
  const { cityLessons } = await game('controller.js');
  const { buildBank } = await import('../renderer/game/profile/item-bank.js');
  const t = await setup({ doc: null });
  const drills = (b) => [...b.items].filter(([k]) => k.startsWith('drill:'));
  assert.deepStrictEqual(drills(buildBank(cityLessons(t.lessons), DRILLS)), drills(buildBank(t.lessons, DRILLS)));
});

// YOUR FILE (Task 20).
const text = (html) => html.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ');
const chipCount = (html) => Number((/aria-label="Your file: [^"]*, (\d+) lessons? learned"/.exec(html) || [])[1]);
const headline = (html) => Number((/<p>(\d+) of \d+ learned<\/p>/.exec(html) || [])[1]);

test('YOUR FILE opens from the rank chip and the Training Grounds, and Escape closes it', async () => {
  const t = await setup();
  assert.match(t.html(), /class="stat lime rank-chip" data-go="profile"/);
  t.click({ 'data-go': 'profile' });
  assert.match(t.html(), /<h2 id="profile-title" tabindex="-1">YOUR FILE<\/h2>/);
  assert.ok(t.html().includes('Updates and the locked door'));
  t.key('Escape');
  assert.doesNotMatch(t.html(), /profile-title/);
  assert.match(t.html(), /YOUR COMPUTER/, 'back on the deck');
  t.click({ 'data-go': 'training' });
  assert.match(t.html(), /<button type="button" data-go="profile">YOUR FILE<\/button>/);
  t.click({ 'data-go': 'profile' });
  assert.match(t.html(), /profile-title/);
  t.click({ 'data-act': 'profile-close' });
  assert.match(t.html(), /THE TRAINING GROUNDS/, 'back where it was opened');
});

test('YOUR FILE: focus moves in on open, to the question and back, and to what opened it on close', async () => {
  const t = await setup();
  t.click({ 'data-go': 'profile' });
  assert.strictEqual(t.focused.at(-1), '#profile-title');
  t.click({ 'data-act': 'profile-start-over' });
  assert.match(t.focused.at(-1), /data-act="profile-start-over-no"/, 'Keep my progress, the safe choice');
  t.key('Escape');
  assert.doesNotMatch(t.html(), /role="alertdialog"/, 'Escape closes the question first');
  assert.strictEqual(t.focused.at(-1), '[data-act="profile-start-over"]');
  assert.match(t.html(), /profile-title/, 'and leaves YOUR FILE open');
  t.key('Escape');
  assert.doesNotMatch(t.html(), /profile-title/);
  assert.strictEqual(t.focused.at(-1), '[data-go="profile"]', 'back on the rank chip');
});

test('Start over asks first, then clears the game’s record and nothing else', async () => {
  const t = await setup();
  t.click({ 'data-go': 'lesson:locked-door' });
  t.click({ 'data-act': 'answer:0' });
  const confirmed = t.storage.data['device-rescue.scan-confirmed'];
  t.click({ 'data-go': 'profile' });
  t.click({ 'data-act': 'profile-start-over-yes' });
  assert.ok(savedProfile(t.storage).concepts['auto-updates'], 'YES without the question does nothing');
  t.click({ 'data-act': 'profile-start-over' });
  assert.match(t.html(), /role="alertdialog"/);
  t.click({ 'data-act': 'profile-start-over-no' });
  assert.doesNotMatch(t.html(), /role="alertdialog"/);
  assert.ok(savedProfile(t.storage).concepts['auto-updates']);
  t.click({ 'data-act': 'profile-start-over' });
  t.click({ 'data-act': 'profile-start-over-yes' });
  assert.deepStrictEqual(savedProfile(t.storage).missions, {});
  assert.deepStrictEqual(savedProfile(t.storage).concepts, {});
  assert.strictEqual(t.storage.data['device-rescue.scan-confirmed'], confirmed, 'other stores untouched');
  assert.deepStrictEqual(forbiddenWrites(t.storage), []);
});

test('city mode: no route builds or hands over a payload, even with the school side ready', async () => {
  const t = await setup({ mode: 'city', publishReady: true });
  t.click({ 'data-go': 'profile' });
  assert.doesNotMatch(t.html(), /profile-publish|school profile|school-profile/i);
  for (const act of ['profile-publish', 'pub-toggle:lessons', 'publish-save', 'publish-copy']) t.click({ 'data-act': act }, true);
  await tick();
  assert.doesNotMatch(t.html(), /pub-preview|role="dialog"/);
  assert.deepStrictEqual([t.calls.clipboard, t.calls.objectUrls, t.calls.downloads], [[], 0, []]);
});

test('city mode: YOUR FILE is in game words only', async () => {
  const t = await setup({ mode: 'city' });
  t.click({ 'data-go': 'profile' });
  t.click({ 'data-act': 'profile-start-over' });
  const words = text(t.html());
  assert.match(words, /YOUR FILE/);
  assert.doesNotMatch(words, /profile|safety|monitor|partner|school/i);
  assert.doesNotMatch(words, KNOWN_PERSON);
  assert.doesNotMatch(words, /The order to do things in/, 'a hidden concept is never listed');
});

test('standard mode, before the school side is ready: the control is absent and no route opens the sheet', async () => {
  const t = await setup({ mode: 'standard' });
  t.click({ 'data-go': 'profile' });
  assert.doesNotMatch(t.html(), /profile-publish/);
  for (const act of ['profile-publish', 'pub-toggle:lessons', 'publish-save', 'publish-copy']) t.click({ 'data-act': act }, true);
  await tick();
  assert.doesNotMatch(t.html(), /pub-preview|role="dialog"/);
  assert.deepStrictEqual([t.calls.clipboard, t.calls.objectUrls, t.calls.downloads], [[], 0, []]);
});

test('standard mode, school side ready: every box unticked, the preview is the payload, Save and Copy hand it over; city mode closes the sheet', async () => {
  const t = await setup({ mode: 'standard', publishReady: true });
  t.click({ 'data-go': 'profile' });
  const writes = t.storage.writes.length;
  t.click({ 'data-act': 'profile-publish' });
  assert.match(t.html(), /role="dialog"/);
  assert.match(t.html(), /<div inert>[\s\S]*profile-title[\s\S]*<\/div>\s*<div class="sheet"/, 'YOUR FILE is inert behind the sheet');
  assert.match(t.focused.at(-1), /^(#pub-title|\[id="pub-title"\])$/, 'focus moves into the sheet');
  assert.doesNotMatch(t.html(), /type="checkbox"[^>]* checked/, 'every box unticked');
  assert.match(t.html(), /Nothing ticked yet\./);
  t.click({ 'data-act': 'publish-copy' });
  t.click({ 'data-act': 'publish-save' });
  await tick();
  assert.deepStrictEqual([t.calls.clipboard, t.calls.downloads], [[], []], 'nothing ticked, nothing handed over');
  t.click({ 'data-act': 'pub-toggle:drills-tried' }, true);
  assert.match(t.html(), /city_drills_tried/);
  assert.match(t.html(), /id="pub-drills-tried" data-act="pub-toggle:drills-tried" checked/);
  t.click({ 'data-act': 'publish-copy' });
  await tick();
  assert.strictEqual(t.calls.clipboard.length, 1);
  assert.deepStrictEqual(Object.keys(JSON.parse(t.calls.clipboard[0]).play), ['city_drills_tried']);
  assert.ok(t.html().includes(escaped(t.calls.clipboard[0])), 'the preview is exactly what was copied');
  t.click({ 'data-act': 'publish-save' });
  await tick();
  assert.deepStrictEqual(t.calls.downloads, ['school-profile.json']);
  assert.strictEqual(t.storage.writes.length, writes, 'the sheet writes nothing to disk');
  t.key('Escape');
  assert.doesNotMatch(t.html(), /role="dialog"/, 'Escape closes the sheet first');
  assert.strictEqual(t.focused.at(-1), '[data-act="profile-publish"]', 'focus back on the control that opened it');
  assert.match(t.html(), /profile-title/);
  t.click({ 'data-act': 'profile-publish' });
  t.mode.now = 'city';
  t.click({ 'data-act': 'pub-toggle:lessons' }, true);
  assert.doesNotMatch(t.html(), /pub-preview|profile-publish/);
  t.click({ 'data-act': 'publish-copy' });
  await tick();
  assert.strictEqual(t.calls.clipboard.length, 1, 'nothing more handed over');
});

test('the lessons-learned count is one rule: YOUR FILE, the rank chip and the published number agree; city mode reads the city bank', async () => {
  const [pp, ib, training, pub] = await Promise.all([game('profile/player-profile.js'), game('profile/item-bank.js'), game('training.js'), game('profile/publish.js')]);
  const { cityLessons } = await game('controller.js');
  const lessons = await training.loadLessons(importModule);
  const bank = ib.buildBank(lessons, DRILLS);
  // Everything learned, except the hidden concept (missed every time).
  let p = pp.emptyProfile(NOW);
  for (let pass = 0; pass < 2; pass += 1) {
    for (const [key, it] of bank.items) if (it.kind === 'lesson') p = pp.recordAnswer(p, bank, key, it.concept !== 'cut-off-order', NOW);
  }
  assert.notStrictEqual(pp.conceptState(p, bank, 'cut-off-order'), 'learned');
  const full = pp.summary(p, bank);
  const shown = pub.lessonsLearned(full);
  assert.ok(shown > full.lessons.filter((l) => l.state === 'learned').length, 'the hidden concept would otherwise hold its lesson back');
  // The city bank: the hidden concept isn't part of any lesson there.
  const c = ib.buildBank(cityLessons(lessons), DRILLS);
  const city = pp.summary(p, { items: bank.items, lessons: c.lessons, concepts: c.concepts });
  assert.ok(city.lessons.every((l) => l.concepts.every((x) => x.id !== 'cut-off-order')));
  assert.strictEqual(city.lessons.find((l) => l.id === 'whos-on-wifi').state, 'learned');
  assert.strictEqual(pub.lessonsLearned(city), shown);
  for (const mode of ['standard', 'city']) {
    const storage = recordingStore();
    pp.saveProfile(storage, p, { seed: 4242, mode });
    const t = await setup({ storage, mode, publishReady: true });
    assert.strictEqual(chipCount(t.html()), shown, `${mode}: the rank chip`);
    t.click({ 'data-go': 'profile' });
    assert.strictEqual(headline(t.html()), shown, `${mode}: YOUR FILE`);
    assert.match(t.html(), /profile-lesson learned"><span class="stamp">LEARNED<\/span>\s*<b>[^<]*Wi/);
    if (mode === 'standard') {
      t.click({ 'data-act': 'profile-publish' });
      t.click({ 'data-act': 'pub-toggle:lessons' }, true);
      t.click({ 'data-act': 'publish-copy' });
      await tick();
      assert.strictEqual(JSON.parse(t.calls.clipboard[0]).security.city_lessons_learned.by['reclaim-city'].value, shown, 'the published number');
    }
  }
});

test('a lesson opened from YOUR FILE comes back to it', async () => {
  const t = await setup();
  t.click({ 'data-go': 'profile' });
  t.click({ 'data-go': 'lesson:locked-door' });
  answerVisit(t);
  assert.match(t.html(), /profile-title/);
  t.click({ 'data-act': 'profile-close' });
  assert.match(t.html(), /YOUR COMPUTER/, 'and closing it still goes back to the deck');
});

test('both modes: every write in a session (lesson answers, a drill, a later, the file, Start over) is recipe words only', async () => {
  const loud = scan(mod('launch_agent_audit', [f('Partner safety monitor watch', 'warning', { program: '/Users/ann/stalk/spy.sh' },
    { code: 'security.launch_agent_audit.tmp' })]));
  const { findingsToCity } = await import('../renderer/game/findings-to-city.js');
  const missionId = findingsToCity(loud).districts.flatMap((d) => d.missions)[0].id;
  for (const mode of ['standard', 'city']) {
    const t = await setup({ mode, doc: loud, publishReady: true });
    t.click({ 'data-go': 'lesson:whos-on-wifi' });
    t.click({ 'data-act': `answer:${correctIndex(t.lesson('whos-on-wifi').questions[0])}` });
    t.click({ 'data-go': 'range' });
    await tick();
    t.click({ 'data-go': 'signal:drill:zoom-helper-signed' });
    t.click({ 'data-act': 'tag:threat' });
    t.click({ 'data-go': `mission:${missionId}` });
    t.click({ 'data-act': 'later' });
    t.click({ 'data-go': 'profile' });
    if (mode === 'standard') {
      t.click({ 'data-act': 'profile-publish' });
      t.click({ 'data-act': 'pub-toggle:lessons' }, true);
      t.click({ 'data-act': 'publish-close' });
    }
    assert.ok(t.storage.writes.length >= 3, `${mode}: something was saved`);
    assert.deepStrictEqual(forbiddenWrites(t.storage), [], mode);
    assert.ok(t.storage.writes.every(([k]) => k === PROFILE_KEY || k === 'device-rescue.city-seed'), `${mode}: only the box (and the seed)`);
    assert.strictEqual(savedProfile(t.storage).missions[missionId].title, 'Partner safety monitor watch', `${mode}: the title is kept, disguised`);
    t.click({ 'data-act': 'profile-start-over' });
    t.click({ 'data-act': 'profile-start-over-yes' });
    assert.deepStrictEqual(forbiddenWrites(t.storage), [], `${mode}: Start over`);
    assert.deepStrictEqual(savedProfile(t.storage).missions, {});
  }
});

// Task 21: a tick for an id that isn't on the publish list is ignored, and
// plain view's Start over is read back by the game (reloadProfile).
test('YOUR FILE: a tick for anything not on the publish list is ignored, so the real ticks still hand over', async () => {
  const t = await setup({ publishReady: true });
  t.click({ 'data-go': 'profile' });
  t.click({ 'data-act': 'profile-publish' });
  t.click({ 'data-act': 'pub-toggle:lessons' }, true);
  t.click({ 'data-act': 'pub-toggle:bogus' }, true);
  t.click({ 'data-act': 'publish-copy' });
  await tick();
  assert.strictEqual(t.calls.clipboard.length, 1, 'deliver would refuse a consent naming an unknown field');
  assert.deepStrictEqual(Object.keys(JSON.parse(t.calls.clipboard[0])), ['security']);
});

test('reloadProfile: a profile plain view wrote is the one the game shows and saves next', async () => {
  const pp = await game('profile/player-profile.js');
  const storage = recordingStore();
  const t = await setup({ storage });
  const before = pp.loadProfile(storage, NOW);
  pp.saveProfile(storage, { ...before, rank: { points: 777, index: 2 } }, { seed: 4242, mode: 'standard' });
  t.ctl.reloadProfile();
  t.click({ 'data-go': 'profile' });
  assert.match(t.html(), /777 POINTS/);
  t.ctl.profileModeChanged();
  assert.strictEqual(savedProfile(storage).rank.points, 777, 'the next save keeps it');
});
