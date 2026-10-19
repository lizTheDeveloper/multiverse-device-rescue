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
  const frame = { innerHTML: '', addEventListener: (type, fn) => { if (type === 'click') listeners.push(fn); },
    querySelector: () => null, querySelectorAll: () => [] };
  const shadow = { activeElement: null, getElementById: () => frame, addEventListener: () => {} };
  const win = {
    document: { getElementById: () => ({ attachShadow: () => shadow }) },
    FixFlow: { attach: () => {}, fixControlsHtml: () => '', resultHtml: () => '' },
    MarkFlow: { attach: () => {}, markControlsHtml: () => '' },
    RescueHost: { mode: () => mode.now, showList() {}, docChanged: () => true, wantsSafety: () => false, startCheckup() {}, scanTips: async () => [], leaveGame() {} },
    rescue: {},
  };
  const click = (attrs) => {
    const el = { getAttribute: (k) => (k in attrs ? attrs[k] : null) };
    listeners.forEach((fn) => fn({ target: { closest: () => el } }));
  };
  return { win, frame, click };
}

async function setup({ storage = recordingStore(), mode = 'standard', doc = DOC, loadDrillBank = async () => DRILLS } = {}) {
  const [{ createController }, training] = await Promise.all([game('controller.js'), game('training.js')]);
  const lessons = await training.loadLessons(importModule);
  const m = { now: mode };
  const t = stub(m);
  const ctl = createController({ win: t.win, storage, scoutSprite: () => '', loadGame: () => new Promise(() => {}),
    loadTraining: async () => lessons, loadDrillBank });
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
  assert.match(city.html(), /The city couldn’t save your last move just now/);
  const notice = (/<p class="link-notice save-notice"[\s\S]*?<\/p>/.exec(city.html()) || [''])[0];
  assert.ok(notice);
  assert.doesNotMatch(notice.replace(/<[^>]+>/g, ' '), FORBIDDEN_ON_DISK);
  assert.doesNotMatch(notice, /profile|progress|monitor/i);
  // Every message city mode can show is in game words.
  const { saveProblemText } = await game('controller.js');
  for (const code of ['encode', 'too-big', 'spare', 'write', 'salvaged', 'spare-full', 'unreadable-too-big', 'old-kept', 'anything-else']) {
    assert.doesNotMatch(saveProblemText(code, true), /profile|progress|safety|monitor|partner|\bsafe\b|watch|stalk/i, code);
  }
  city.click({ 'data-act': 'dismiss-save-notice' });
  assert.doesNotMatch(city.html(), /couldn’t save/);
  const std = await setup({ storage: broken(), mode: 'standard' });
  assert.match(std.html(), /Your progress couldn’t be saved just now/);
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
