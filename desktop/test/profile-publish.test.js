const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');

const NOW = '2026-10-18T12:00:00.000Z';
const DAY = '2026-10-18';
const load = async () => {
  const [pub, pp, ib] = await Promise.all([
    import('../renderer/game/profile/publish.js'),
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
  ]);
  const bank = ib.buildBank(LESSONS, DRILLS);
  let p = pp.salvage(V3, NOW).profile;
  p = pp.recordAnswer(p, bank, 'b1', true, NOW);
  return { ...pub, summary: pp.summary(p, bank), profile: p };
};
const ALL = ['lessons', 'drills-right', 'drills-tried', 'rank', 'skills'];

test('the payload is an MVProfile fragment in its own provenance slot, with only the ticked fields', async () => {
  const { buildPayload, summary } = await load();
  const doc = JSON.parse(buildPayload(summary, ['lessons', 'rank'], { mode: 'standard', now: NOW }));
  assert.deepStrictEqual(doc, {
    security: { city_lessons_learned: { by: { 'reclaim-city': { value: 1, at: DAY, seq: 1 } } } },
    play: { city_rank_level: { by: { 'reclaim-city': { value: 3, at: DAY, seq: 2 } } } },
  });
});

test('nothing ticked, city mode, or no summary: no payload at all', async () => {
  const { buildPayload, summary } = await load();
  assert.strictEqual(buildPayload(summary, [], { mode: 'standard', now: NOW }), null);
  assert.strictEqual(buildPayload(summary, ALL, { mode: 'city', now: NOW }), null);
  assert.strictEqual(buildPayload(summary, ALL, { mode: null, now: NOW }), null);
  assert.strictEqual(buildPayload(null, ALL, { mode: 'standard', now: NOW }), null);
});

test('everything ticked still says nothing about the computer, the lessons or the answers', async () => {
  const { buildPayload, summary, profile } = await load();
  const text = buildPayload(summary, ALL, { mode: 'standard', now: NOW });
  const never = [
    ...Object.keys(profile.missions), ...Object.values(profile.missions).map((m) => m.title),
    ...Object.keys(profile.lessons), ...Object.keys(profile.concepts), 'a1', 'b1', 'launch_agent_audit', '/tmp', 'gatehouse',
    ...Object.keys(profile.deck.tags), ...Object.keys(profile.deck.confirmed), 'NETRUNNER', 'points',
  ];
  for (const s of never) assert.ok(!text.includes(s), `payload contains "${s}"`);
  const doc = JSON.parse(text);
  assert.deepStrictEqual(Object.keys(doc).sort(), ['play', 'security']);
  assert.deepStrictEqual(Object.keys(doc.security.city_skills.by['reclaim-city'].value).sort(), ['honest-results', 'reading-makers']);
});

test('a value that is not on the list refuses the whole payload', async () => {
  const { buildPayload, summary } = await load();
  assert.strictEqual(buildPayload({ ...summary, drills: { ...summary.drills, right: -1 } }, ['drills-right'], { mode: 'standard', now: NOW }), null);
  assert.strictEqual(buildPayload({ ...summary, skills: [{ id: 'made-up', depth: 'practiced' }] }, ['skills'], { mode: 'standard', now: NOW }), '{\n  "security": {\n    "city_skills": {\n      "by": {\n        "reclaim-city": {\n          "value": {},\n          "at": "2026-10-18",\n          "seq": 1\n        }\n      }\n    }\n  }\n}');
});

test('the control exists only in standard mode, and only once the school side is ready', async () => {
  const { publishOffered, PUBLISH_READY } = await load();
  assert.strictEqual(PUBLISH_READY, false, 'flip only after the school-repo prerequisites in the plan land');
  assert.strictEqual(publishOffered('standard'), false);
  assert.strictEqual(publishOffered('standard', true), true);
  assert.strictEqual(publishOffered('city', true), false);
  assert.strictEqual(publishOffered(null, true), false);
});

// The owner's hard rules for publishing, one test each.
const { FORBIDDEN_ON_DISK } = require('./disk-words.js');

// Every key and string value in a parsed payload, at any depth.
function strings(x, out = []) {
  if (typeof x === 'string') out.push(x);
  else if (x && typeof x === 'object') for (const [k, v] of Object.entries(x)) { out.push(k); strings(v, out); }
  return out;
}
// A summary that throws if anything reads it.
const untouchable = () => new Proxy({}, { get(_, k) { throw new Error(`read summary.${String(k)}`); }, has(_, k) { throw new Error(`has summary.${String(k)}`); } });

test('rule 1: the payload is built from the allow-list, whatever else the summary carries', async () => {
  const { buildPayload, summary, PUBLISH_FIELDS } = await load();
  assert.deepStrictEqual(PUBLISH_FIELDS.map((f) => f.id), ALL);
  const noisy = {
    ...summary,
    findings: [{ title: 'Unsigned helper', data: { path: '/Library/LaunchAgents/x.plist' } }],
    computer: { name: 'Kitchen-MacBook', serial: 'C02XYZ' },
    city: { ...summary.city, lastSweep: 42 },
  };
  const text = buildPayload(noisy, [...ALL, 'findings', 'computer', 'city', 'concepts', 'lessons-list'], { mode: 'standard', now: NOW });
  for (const s of ['Unsigned', 'LaunchAgents', '/Library', 'Kitchen', 'C02XYZ', 'serial', 'lastSweep', 'findings', 'computer']) {
    assert.ok(!text.includes(s), `payload contains "${s}"`);
  }
  const doc = JSON.parse(text);
  const allowed = new Map(PUBLISH_FIELDS.map((f) => [f.field, f.group]));
  const sent = Object.entries(doc).flatMap(([g, fields]) => Object.keys(fields).map((f) => [g, f]));
  assert.strictEqual(sent.length, ALL.length);
  for (const [g, f] of sent) assert.strictEqual(allowed.get(f), g, `${g}.${f} is not on the list`);
  for (const [g, f] of sent) assert.deepStrictEqual(Object.keys(doc[g][f].by), ['reclaim-city']);
});

test('rule 2: a hidden concept never appears, even if a summary names it as a skill', async () => {
  const { buildPayload, summary } = await load();
  const { CONCEPTS } = await import('../renderer/game/profile/skills.js');
  const hidden = CONCEPTS.filter((c) => c.hidden);
  assert.ok(hidden.some((c) => c.id === 'cut-off-order'));
  const sneaky = { ...summary, skills: [...summary.skills, ...hidden.map((c) => ({ id: c.id, title: c.title, depth: 'practiced' }))] };
  for (const s of [summary, sneaky]) {
    const text = buildPayload(s, ALL, { mode: 'standard', now: NOW });
    assert.ok(text);
    for (const c of hidden) {
      assert.ok(!text.includes(c.id), `payload contains hidden concept "${c.id}"`);
      assert.ok(!text.includes(c.title), `payload contains hidden concept title "${c.title}"`);
    }
  }
});

test('rule 3: no string in the payload, its labels or its note matches FORBIDDEN_ON_DISK', async () => {
  const { buildPayload, summary, PUBLISH_FIELDS, STAYS_HERE, WORKBOOK } = await load();
  const { SKILLS } = await import('../renderer/game/profile/skills.js');
  // Every skill at its deepest, so every skill id that could ever be sent is in the text.
  const full = { ...summary, skills: SKILLS.map((k) => ({ id: k.id, depth: 'practiced' })) };
  const text = buildPayload(full, ALL, { mode: 'standard', now: NOW });
  const all = [...strings(JSON.parse(text)), text, WORKBOOK, STAYS_HERE, ...PUBLISH_FIELDS.flatMap((f) => [f.id, f.group, f.field, f.label])];
  const bad = all.filter((s) => FORBIDDEN_ON_DISK.test(s));
  assert.deepStrictEqual(bad, []);
  assert.strictEqual(Object.keys(JSON.parse(text).security.city_skills.by[WORKBOOK].value).length, SKILLS.length);
});

test('rule 4: in city mode, publishing refuses and builds nothing', async () => {
  const { buildPayload, createPublisher } = await load();
  const deliver = createPublisher({ ready: true });
  for (const mode of ['city', null, undefined, 'Standard']) {
    assert.strictEqual(buildPayload(untouchable(), ALL, { mode, now: NOW }), null);
    let calls = 0;
    const r = await deliver(untouchable(), { fields: ALL }, { mode, now: NOW, send: () => { calls += 1; } });
    assert.deepStrictEqual(r, { sent: false, reason: 'not-offered' });
    assert.strictEqual(calls, 0);
  }
});

test('rule 5: nothing is handed over without a consent that names exactly the fields being sent', async () => {
  const { createPublisher, buildPayload, summary } = await load();
  const deliver = createPublisher({ ready: true });
  const opts = (send) => ({ mode: 'standard', now: NOW, send });
  const refused = [
    [undefined, 'no-consent'], [null, 'no-consent'], [true, 'no-consent'], [['lessons'], 'no-consent'],
    [{}, 'no-consent'], [{ fields: 'lessons' }, 'no-consent'], [{ fields: [] }, 'no-consent'],
    [{ fields: ['lessons', 'lessons'] }, 'consent-mismatch'], [{ fields: ['lessons', 'findings'] }, 'consent-mismatch'],
    [{ fields: ['lessons'], extra: ['rank'] }, 'consent-mismatch'],
  ];
  for (const [consent, reason] of refused) {
    let calls = 0;
    const r = await deliver(summary, consent, opts(() => { calls += 1; }));
    assert.deepStrictEqual(r, { sent: false, reason }, JSON.stringify(consent));
    assert.strictEqual(calls, 0);
  }
  // A value off the list builds nothing, so nothing goes.
  let calls = 0;
  assert.deepStrictEqual(await deliver({ ...summary, drills: { ...summary.drills, right: -1 } }, { fields: ['drills-right'] }, opts(() => { calls += 1; })), { sent: false, reason: 'refused' });
  assert.strictEqual(calls, 0);
  // Exactly the consented fields, in the exact text buildPayload shows.
  const got = [];
  const r = await deliver(summary, { fields: ['rank', 'lessons'] }, opts((t) => { got.push(t); }));
  const expected = buildPayload(summary, ['lessons', 'rank'], { mode: 'standard', now: NOW });
  assert.deepStrictEqual(r, { sent: true, text: expected });
  assert.deepStrictEqual(got, [expected]);
  assert.deepStrictEqual(Object.keys(JSON.parse(got[0])).sort(), ['play', 'security']);
  assert.deepStrictEqual(Object.keys(JSON.parse(got[0]).play), ['city_rank_level']);
  assert.deepStrictEqual(Object.keys(JSON.parse(got[0]).security), ['city_lessons_learned']);
});

test('rule 5: switched off (PUBLISH_READY false) means nothing is handed over, consent or not', async () => {
  const { deliver, summary, PUBLISH_READY } = await load();
  assert.strictEqual(PUBLISH_READY, false);
  let calls = 0;
  const send = () => { calls += 1; };
  assert.deepStrictEqual(await deliver(summary, { fields: ALL }, { mode: 'standard', now: NOW, send }), { sent: false, reason: 'not-offered' });
  assert.deepStrictEqual(await deliver(summary, { fields: ALL }, { mode: 'standard', now: NOW, ready: 'yes', send }), { sent: false, reason: 'not-offered' });
  assert.strictEqual(calls, 0);
});

test('rule 6: the hand-over is injected; without one nothing goes, a failing one is reported, and no network code exists', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { createPublisher, summary } = await load();
  const deliver = createPublisher({ ready: true });
  const opts = { mode: 'standard', now: NOW };
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, opts), { sent: false, reason: 'no-transport' });
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, { ...opts, send: 'https://example.org' }), { sent: false, reason: 'no-transport' });
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, { ...opts, send: () => { throw new Error('disk full'); } }), { sent: false, reason: 'send-failed' });
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, { ...opts, send: async () => { throw new Error('cancelled'); } }), { sent: false, reason: 'send-failed' });
  const src = fs.readFileSync(path.join(__dirname, '../renderer/game/profile/publish.js'), 'utf8').replace(/\/\/.*$/gm, '');
  for (const word of ['fetch', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'http:', 'https:', 'require(', 'import(']) {
    assert.ok(!src.includes(word), `publish.js uses ${word}`);
  }
});

// Fix round 1.

test('fix 1: the off-switch cannot be bypassed: deliver takes no ready option, and only tests use createPublisher', async () => {
  const fs = require('node:fs');
  const path = require('node:path');
  const { deliver, createPublisher, summary } = await load();
  let calls = 0;
  const send = () => { calls += 1; };
  for (const ready of [true, 'yes', 1]) {
    assert.deepStrictEqual(await deliver(summary, { fields: ALL }, { mode: 'standard', now: NOW, ready, send }), { sent: false, reason: 'not-offered' });
  }
  assert.deepStrictEqual(await createPublisher({ ready: false })(summary, { fields: ALL }, { mode: 'standard', now: NOW, send }), { sent: false, reason: 'not-offered' });
  assert.deepStrictEqual(await createPublisher({ ready: 'yes' })(summary, { fields: ALL }, { mode: 'standard', now: NOW, send }), { sent: false, reason: 'not-offered' });
  assert.strictEqual(calls, 0);
  // Every source file outside the tests and node_modules: only publish.js names the seam.
  const root = path.join(__dirname, '..');
  const offenders = [];
  const walk = (dir) => {
    for (const e of fs.readdirSync(dir, { withFileTypes: true })) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) { if (!['node_modules', 'test', 'dist', '.git'].includes(e.name)) walk(full); continue; }
      if (!/\.(c|m)?js$|\.html$/.test(e.name)) continue;
      if (full === path.join(root, 'renderer', 'game', 'profile', 'publish.js')) continue;
      if (fs.readFileSync(full, 'utf8').includes('createPublisher')) offenders.push(path.relative(root, full));
    }
  };
  walk(root);
  assert.deepStrictEqual(offenders, []);
  // buildPayload is preview-only, and says so.
  const src = fs.readFileSync(path.join(root, 'renderer', 'game', 'profile', 'publish.js'), 'utf8');
  assert.match(src, /PREVIEW ONLY[^\n]*never sends[^\n]*\n(?:\/\/[^\n]*\n)*export function buildPayload/);
});

test('fix 2: the date is the day only, in UTC, and anything that is not a valid date refuses', async () => {
  const { buildPayload, summary } = await load();
  const at = (now) => {
    const t = buildPayload(summary, ['rank'], { mode: 'standard', now });
    return t && JSON.parse(t).play.city_rank_level.by['reclaim-city'].at;
  };
  assert.strictEqual(at(NOW), DAY);
  assert.strictEqual(at(new Date(NOW)), DAY);
  assert.strictEqual(at('2026-10-18T23:59:59.999-05:00'), '2026-10-19');
  assert.strictEqual(at('2026-10-18T00:30:00+02:00'), '2026-10-17');
  const text = buildPayload(summary, ALL, { mode: 'standard', now: NOW });
  assert.ok(!/\d{2}:\d{2}|T\d|Z"/.test(text), 'payload carries a time of day');
  for (const bad of [undefined, null, '', 'yesterday', 'undefined', 0, 1760788800000, true, {}, [], new Date('nope')]) {
    assert.strictEqual(buildPayload(summary, ALL, { mode: 'standard', now: bad }), null, `now = ${String(bad)}`);
  }
  assert.strictEqual(buildPayload(summary, ALL, { mode: 'standard' }), null);
});

// A bank with a lesson that measures one shown concept and the hidden one.
async function withHiddenLesson() {
  const [pub, pp, ib] = await Promise.all([
    import('../renderer/game/profile/publish.js'),
    import('../renderer/game/profile/player-profile.js'),
    import('../renderer/game/profile/item-bank.js'),
  ]);
  const o2 = () => [{ text: 'Yes', correct: true, feedback: 'Right.' }, { text: 'No', correct: false, feedback: 'No.' }];
  const fam = (key, concept) => ({ key, concept, teach: `Teach ${key}`, prompt: `Prompt ${key}`, options: o2(),
    variants: [{ key: `${key}-2`, prompt: `Prompt ${key}-2`, options: o2() }, { key: `${key}-3`, prompt: `Prompt ${key}-3`, options: o2() }] });
  const lessons = [...LESSONS, { id: 'lesson-c', title: 'Lesson C', modules: [], questions: [fam('c1', 'wifi-and-mining'), fam('c9', 'cut-off-order')] }];
  const bank = ib.buildBank(lessons, DRILLS);
  // lesson-c finished under the old rule: both its concepts start out learned.
  const base = pp.salvage({ ...V3, lessons: { ...V3.lessons, 'lesson-c': { completedAt: '2026-10-13T08:00:00.000Z' } } }, NOW).profile;
  const answer = (p, right) => ['c9', 'c9-2', 'c9-3', 'c9', 'c9-2', 'c9-3'].reduce((q, k) => pp.recordAnswer(q, bank, k, right, NOW), p);
  return { pub, pp, bank, base, answer };
}

test('fix 3: hidden-concept evidence never changes the published skill levels', async () => {
  const { pub, pp, bank, base, answer } = await withHiddenLesson();
  const { SKILLS, isHidden } = await import('../renderer/game/profile/skills.js');
  assert.ok(SKILLS.every((k) => k.concepts.some((c) => !isHidden(c))), 'a skill made only of hidden concepts would be left out');
  const skillsOf = (p) => JSON.parse(pub.buildPayload(pp.summary(p, bank), ['skills'], { mode: 'standard', now: NOW })).security.city_skills.by['reclaim-city'].value;
  const none = skillsOf(base);
  assert.strictEqual(none['your-network'], 'practiced');
  assert.deepStrictEqual(skillsOf(answer(base, false)), none);
  assert.deepStrictEqual(skillsOf(answer(base, true)), none);
});

test('fix 5: hidden concepts never count toward the published lesson total, and no lesson or drill is about monitoring', async () => {
  const { pub, pp, bank, base, answer } = await withHiddenLesson();
  const count = (p) => JSON.parse(pub.buildPayload(pp.summary(p, bank), ['lessons'], { mode: 'standard', now: NOW })).security.city_lessons_learned.by['reclaim-city'].value;
  const wrong = answer(base, false);
  // The in-app total moves with the hidden concept; the published one doesn't.
  const byState = (p) => pp.summary(p, bank).lessons.filter((l) => l.state === 'learned').length;
  assert.strictEqual(byState(base), 2);
  assert.strictEqual(byState(wrong), 1);
  assert.strictEqual(count(base), 2);
  assert.strictEqual(count(wrong), 2);
  assert.strictEqual(count(answer(base, true)), 2);
  // A lesson whose only concept is hidden never counts, learned or not.
  const s = pp.summary(base, bank);
  const onlyHidden = { ...s, lessons: [...s.lessons, { id: 'x', state: 'learned', concepts: [{ id: 'cut-off-order', state: 'learned' }] }] };
  assert.strictEqual(JSON.parse(pub.buildPayload(onlyHidden, ['lessons'], { mode: 'standard', now: NOW })).security.city_lessons_learned.by['reclaim-city'].value, 2);
  // Without per-lesson concepts there is nothing safe to count.
  assert.strictEqual(pub.buildPayload({ ...s, lessons: undefined }, ['lessons'], { mode: 'standard', now: NOW }), null);
  // The real lessons and drills: none is tied to a monitoring check.
  const path = require('node:path');
  const { pathToFileURL } = require('node:url');
  const GAME = path.join(__dirname, '..', 'renderer', 'game');
  const VENDOR = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src', 'data', 'phishing.js');
  const training = await import(pathToFileURL(path.join(GAME, 'training.js')).href);
  const real = await training.loadLessons((spec) => import(pathToFileURL(spec === '../rc/data/phishing.js' ? VENDOR : path.join(GAME, spec)).href));
  const { MONITORING_MODULES } = await import('../renderer/game/ledger.js');
  assert.ok(real.length > 0);
  for (const l of real) assert.ok(!(l.modules || []).some((m) => MONITORING_MODULES.has(m)), `${l.id} is tied to a monitoring check`);
  const { DRILL_CONCEPTS, isHidden } = await import('../renderer/game/profile/skills.js');
  for (const c of Object.values(DRILL_CONCEPTS)) assert.ok(c === null || !isHidden(c), `a drill measures hidden concept ${c}`);
});
