const test = require('node:test');
const assert = require('node:assert');
const { LESSONS, DRILLS, V3 } = require('./profile-fixtures.js');

const NOW = '2026-10-18T12:00:00.000Z';
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
    security: { city_lessons_learned: { by: { 'reclaim-city': { value: 1, at: NOW, seq: 1 } } } },
    play: { city_rank_level: { by: { 'reclaim-city': { value: 3, at: NOW, seq: 2 } } } },
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
  assert.strictEqual(buildPayload({ ...summary, lessonsLearned: -1 }, ['lessons'], { mode: 'standard', now: NOW }), null);
  assert.strictEqual(buildPayload({ ...summary, skills: [{ id: 'made-up', depth: 'practiced' }] }, ['skills'], { mode: 'standard', now: NOW }), '{\n  "security": {\n    "city_skills": {\n      "by": {\n        "reclaim-city": {\n          "value": {},\n          "at": "2026-10-18T12:00:00.000Z",\n          "seq": 1\n        }\n      }\n    }\n  }\n}');
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
  const { buildPayload, deliver } = await load();
  for (const mode of ['city', null, undefined, 'Standard']) {
    assert.strictEqual(buildPayload(untouchable(), ALL, { mode, now: NOW }), null);
    let calls = 0;
    const r = await deliver(untouchable(), { fields: ALL }, { mode, now: NOW, ready: true, send: () => { calls += 1; } });
    assert.deepStrictEqual(r, { sent: false, reason: 'not-offered' });
    assert.strictEqual(calls, 0);
  }
});

test('rule 5: nothing is handed over without a consent that names exactly the fields being sent', async () => {
  const { deliver, buildPayload, summary } = await load();
  const opts = (send) => ({ mode: 'standard', now: NOW, ready: true, send });
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
  assert.deepStrictEqual(await deliver({ ...summary, lessonsLearned: -1 }, { fields: ['lessons'] }, opts(() => { calls += 1; })), { sent: false, reason: 'refused' });
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
  const { deliver, summary } = await load();
  const opts = { mode: 'standard', now: NOW, ready: true };
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, opts), { sent: false, reason: 'no-transport' });
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, { ...opts, send: 'https://example.org' }), { sent: false, reason: 'no-transport' });
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, { ...opts, send: () => { throw new Error('disk full'); } }), { sent: false, reason: 'send-failed' });
  assert.deepStrictEqual(await deliver(summary, { fields: ['lessons'] }, { ...opts, send: async () => { throw new Error('cancelled'); } }), { sent: false, reason: 'send-failed' });
  const src = fs.readFileSync(path.join(__dirname, '../renderer/game/profile/publish.js'), 'utf8').replace(/\/\/.*$/gm, '');
  for (const word of ['fetch', 'XMLHttpRequest', 'WebSocket', 'sendBeacon', 'EventSource', 'http:', 'https:', 'require(', 'import(']) {
    assert.ok(!src.includes(word), `publish.js uses ${word}`);
  }
});
