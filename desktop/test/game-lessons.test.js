const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');
const { pathToFileURL } = require('url');

const ROOT = path.join(__dirname, '..', '..');
const GAME = path.join(__dirname, '..', 'renderer', 'game');
const VENDOR_PHISHING = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');

// The same specifiers the controller passes, mapped onto files on disk.
const importModule = (spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR_PHISHING : path.join(GAME, spec)).href);
const loadAll = async () => {
  const training = await import(pathToFileURL(path.join(GAME, 'training.js')).href);
  return { training, lessons: await training.loadLessons(importModule) };
};

// A UI path is two or more capitalised segments joined by " > " or " → ",
// e.g. "System Settings > Privacy & Security > FileVault".
const SEG = "[A-Z][\\w&]*(?: [\\w&]+)*";
const PATH_RE = new RegExp(`${SEG}(?: (?:>|→) ${SEG})+`, 'g');
const TICKS_RE = /`([^`]+)`/g;
const norm = (s) => String(s).replace(/\s+/g, ' ');

function ownText(lesson) {
  // For the phishing lesson, the messages and their tells are Reclaim City's
  // content. Only Device Rescue's wrapper text is checked here.
  // Every item in a question's bank (the question and its variants) is checked.
  const items = (q) => [q, ...(Array.isArray(q.variants) ? q.variants : [])];
  const qs = lesson.questions.flatMap((q) => (lesson.type === 'phishing'
    ? [q.prompt, q.teach]
    : items(q).flatMap((it) => [it.prompt, it.teach, ...it.options.flatMap((o) => [o.text, o.feedback])])));
  return [lesson.title, lesson.briefing, lesson.whatTheScanLooksFor, ...qs].filter((t) => t != null);
}

// The lessons written before item banks. Every lesson after them gives each
// question a `concept` and at least two `variants`, so IRT has several items
// per concept (docs/superpowers/specs/2026-10-18-player-profile-proposal.md,
// owner decision 4).
const BEFORE_ITEM_BANKS = new Set(['password-asker', 'starts-on-its-own', 'locked-door', 'whos-on-wifi', 'browser-add-ons',
  'couldnt-check', 'poisoned-packages', 'spot-the-fake']);

function sourceText(lesson) {
  return norm(lesson.sources.map((s) => fs.readFileSync(path.join(ROOT, s), 'utf8')).join('\n'));
}

// Checks one piece of lesson text against the source text; returns the problems.
function unsourced(text, src) {
  const bad = [];
  for (const p of norm(text).match(PATH_RE) || []) if (!src.includes(p)) bad.push(`UI path "${p}"`);
  for (const [, inner] of norm(text).matchAll(TICKS_RE)) if (!src.includes(inner)) bad.push(`\`${inner}\``);
  return bad;
}

function moduleExists(name) {
  const mods = path.join(ROOT, 'modules');
  return fs.readdirSync(mods).some((cat) => fs.existsSync(path.join(mods, cat, name)));
}

test('every lesson file loads, and ids are unique', async () => {
  const { training, lessons } = await loadAll();
  assert.strictEqual(lessons.length, training.LESSON_FILES.length + 1, 'every lesson plus Spot the fake message');
  assert.strictEqual(new Set(lessons.map((l) => l.id)).size, lessons.length);
});

test('every lesson cites sources that exist, and modules that exist', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    assert.ok(Array.isArray(l.sources) && l.sources.length > 0, `${l.id} has no sources`);
    for (const s of l.sources) assert.ok(fs.existsSync(path.join(ROOT, s)), `${l.id}: missing source ${s}`);
    for (const m of l.modules) assert.ok(moduleExists(m), `${l.id}: no module ${m}`);
  }
});

// The renderer only learns a module's category from the scan, so each lesson
// names its districts. Each must be one a module it teaches really sweeps.
function moduleDistricts(name, districtIdFor) {
  const mods = path.join(ROOT, 'modules');
  return fs.readdirSync(mods).filter((cat) => fs.existsSync(path.join(mods, cat, name))).map((cat) => districtIdFor(cat));
}

test('every lesson is reachable: from a district on the sweep, or from ALL LESSONS', async () => {
  const { training, lessons } = await loadAll();
  const { DISTRICTS, districtIdFor } = await import(pathToFileURL(path.join(GAME, 'findings-to-city.js')).href);
  const ids = new Set(DISTRICTS.map((d) => d.id));
  for (const l of lessons) {
    assert.ok(Array.isArray(l.districts), `${l.id} names its districts (an empty list is fine)`);
    const backed = new Set(l.modules.flatMap((m) => moduleDistricts(m, districtIdFor)));
    for (const d of l.districts) {
      assert.ok(ids.has(d), `${l.id}: no district ${d}`);
      assert.ok(backed.has(d), `${l.id}: none of its modules is swept in ${d}`);
    }
    if (l.modules.length) assert.ok(l.districts.length, `${l.id} teaches checks, so a district opens it`);
  }
  const by = training.lessonsByDistrict(lessons, 'unsure');
  const onSweep = new Set(Object.values(by).flat().map((l) => l.id));
  // These teach no one check; ALL LESSONS and the sweep's WHILE YOU WAIT offer them.
  assert.deepStrictEqual(lessons.filter((l) => !onSweep.has(l.id)).map((l) => l.id).sort(),
    ['after-a-finding', 'couldnt-check', 'spot-the-fake', 'what-a-checkup-sees']);
  // ALL LESSONS is the Training Grounds, which lists every lesson.
  const { recommended, other } = training.orderLessons(lessons, 'unsure');
  assert.strictEqual(recommended.length + other.length, lessons.length);
});

test('every UI path and every backticked bit in a lesson appears word for word in its sources', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    const src = sourceText(l);
    for (const text of ownText(l)) {
      assert.deepStrictEqual(unsourced(text, src), [], `${l.id}: not word for word in ${l.sources.join(', ')}`);
      if (/\bSystem Settings\b/.test(text)) assert.ok(src.includes('System Settings'), `${l.id}: names System Settings without a source that does`);
    }
  }
});

test('no lesson tells the person what is wrong with their own computer, or how long things take', async () => {
  const { training, lessons } = await loadAll();
  for (const l of lessons) {
    for (const text of ownText(l)) {
      const lower = text.toLowerCase();
      for (const phrase of training.DIAGNOSTIC_PHRASES) assert.ok(!lower.includes(phrase), `${l.id}: "${phrase}" in "${text}"`);
      assert.doesNotMatch(text, training.TIME_WORDS, `${l.id}: time word in "${text}"`);
    }
  }
});

test('every question has two or more options, exactly one right answer, and feedback on every option', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons) {
    assert.ok(l.questions.length >= 1 && l.questions.length <= 5, `${l.id}: 1–5 questions`);
    for (const q of l.questions.flatMap((x) => [x, ...(x.variants || [])])) {
      assert.ok(q.options.length >= 2, `${l.id}: "${q.prompt}" needs options`);
      assert.strictEqual(q.options.filter((o) => o.correct === true).length, 1, `${l.id}: "${q.prompt}" needs exactly one right answer`);
      for (const o of q.options) assert.ok(typeof o.feedback === 'string' && o.feedback.trim(), `${l.id}: "${o.text}" has no feedback`);
    }
  }
});

test('recommendedFor uses only real worry ids, and matches the app’s worries', async () => {
  const { training, lessons } = await loadAll();
  const { SITUATIONS } = require('../renderer/app.js');
  assert.deepStrictEqual([...training.WORRY_IDS].sort(), SITUATIONS.map((s) => s.id).sort());
  for (const l of lessons) for (const w of l.recommendedFor) assert.ok(training.WORRY_IDS.includes(w), `${l.id}: unknown worry ${w}`);
});

test('the accuracy check catches a made-up path or command, and accepts real ones', () => {
  const src = norm(fs.readFileSync(path.join(ROOT, 'desktop', 'renderer', 'permissions-content.json'), 'utf8')
    + fs.readFileSync(path.join(ROOT, 'docs', 'trust-and-safety.md'), 'utf8'));
  assert.deepStrictEqual(unsourced('go to System Settings → Privacy & Security → Full Disk Access.', src), []);
  assert.deepStrictEqual(unsourced('Run `Apply this update?` now', src), []);
  assert.strictEqual(unsourced('go to Settings > Privacy > Make Me Safe', src).length, 1);
  assert.strictEqual(unsourced('go to Settings → Apps → fake thing', src).length, 1);
  assert.strictEqual(unsourced('Run `rescue make-me-safe --now`', src).length, 1);
});

test('each question carries its own what-to-know, and the accuracy check reads it', async () => {
  const { lessons } = await loadAll();
  for (const l of lessons.filter((x) => x.type !== 'phishing')) {
    for (const q of l.questions) assert.ok(typeof q.teach === 'string' && q.teach.trim(), `${l.id}: "${q.prompt}" teaches nothing above it`);
  }
  const fake = { title: 'T', briefing: 'B', whatTheScanLooksFor: 'W',
    questions: [{ teach: 'Open System Settings > Make Me Safe.', prompt: 'P', options: [] }] };
  assert.ok(ownText(fake).includes('Open System Settings > Make Me Safe.'));
  const banked = { ...fake, questions: [{ teach: 'T', prompt: 'P', options: [], variants: [{ prompt: 'Run `rescue nuke`', options: [] }] }] };
  assert.ok(ownText(banked).includes('Run `rescue nuke`'), 'variants are checked too');
});

test('every lesson after the first eight has an item bank: a concept and two or more variants per question', async () => {
  const { lessons } = await loadAll();
  const banked = lessons.filter((l) => !BEFORE_ITEM_BANKS.has(l.id));
  assert.ok(banked.length >= 5, 'the new lessons are loaded');
  for (const l of banked) {
    const concepts = l.questions.map((q) => q.concept);
    for (const q of l.questions) {
      assert.match(String(q.concept || ''), /^[a-z0-9-]+$/, `${l.id}: "${q.prompt}" names its concept`);
      assert.ok(Array.isArray(q.variants) && q.variants.length >= 2, `${l.id}: "${q.concept}" has two or more variants`);
      const prompts = [q.prompt, ...q.variants.map((v) => v.prompt)];
      assert.strictEqual(new Set(prompts).size, prompts.length, `${l.id}: "${q.concept}" variants ask different questions`);
    }
    assert.strictEqual(new Set(concepts).size, concepts.length, `${l.id}: each question is its own concept`);
  }
});
