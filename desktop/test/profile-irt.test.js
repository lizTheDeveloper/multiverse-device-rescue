const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/profile/irt.js');

// Answers as a string of 1 (right) and 0 (wrong), oldest first, alternating
// between two items so the "different items" rule is met.
const seq = (s, c = 1 / 3, b = 0) => s.split('').map((ch, i) => ({ key: `k${i % 2}`, x: ch === '1' ? 1 : 0, b, c }));
const near = (a, b, tol, msg) => assert.ok(Math.abs(a - b) <= tol, `${msg}: ${a} vs ${b}`);

test('the response curve: known values', async () => {
  const { pCorrect, guessFloor } = await load();
  assert.strictEqual(pCorrect(0, 0, 0), 0.5);
  near(pCorrect(0, 0, 1 / 3), 2 / 3, 1e-12, 'guessing floor lifts the middle');
  near(pCorrect(1, 0, 0), 0.7310585786, 1e-9, 'σ(1)');
  assert.strictEqual(guessFloor(3), 1 / 3);
  assert.strictEqual(guessFloor(2), 0.5);
  assert.strictEqual(guessFloor(4), 0.25);
  assert.strictEqual(guessFloor(1), 0);
  assert.strictEqual(guessFloor(undefined), 0);
});

test('item information: known values', async () => {
  const { information } = await load();
  near(information(0, 0, 0), 0.25, 1e-12, 'Rasch at θ = b');
  near(information(0, 0, 1 / 3), 0.125, 1e-12, 'with a 1/3 guessing floor');
  assert.ok(information(0, 0, 0) > information(2, 0, 0), 'an item says most where θ is near b');
});

test('the estimate: known values for the model the plan fixes (prior N(0,1), every answer counts in full, 3 options, medium items)', async () => {
  const { estimate } = await load();
  assert.deepStrictEqual(estimate([]), { mean: 0, sd: 1, n: 0, items: 0 });
  const cases = { 1: [0.207, 0.978], 111: [0.566, 0.918], '0111': [0.121, 0.863], 110: [-0.047, 0.884], 1110: [0.121, 0.863], 11100: [-0.216, 0.818], '000': [-0.923, 0.8], 1111: [0.718, 0.887], 111000: [-0.478, 0.783] };
  for (const [s, [mean, sd]] of Object.entries(cases)) {
    const e = estimate(seq(s));
    assert.strictEqual(e.mean, mean, `${s} mean`);
    assert.strictEqual(e.sd, sd, `${s} sd`);
    assert.strictEqual(e.n, s.length);
  }
  assert.strictEqual(estimate(seq('111', 0.5)).mean, 0.396, 'two options: right answers say less');
});

test('the estimate agrees with an independent, finer integration', async () => {
  const { estimate, pCorrect } = await load();
  function fine(rs, decay = 1, floor = 0) {
    let num = 0; let den = 0;
    for (let t = -6; t <= 6; t += 0.001) {
      let lp = -(t * t) / 2;
      rs.forEach((r, k) => { const p = pCorrect(t, r.b, r.c); lp += Math.max(floor, decay ** (rs.length - 1 - k)) * (r.x ? Math.log(p) : Math.log(1 - p)); });
      const w = Math.exp(lp); num += w * t; den += w;
    }
    return num / den;
  }
  for (const s of ['1', '111', '0111', '110', '000', '10101']) near(estimate(seq(s)).mean, fine(seq(s)), 0.01, s);
  // recency weighting with a floor is still there when asked for
  for (const s of ['0111', '0000111111', '10101']) {
    const e = estimate(seq(s), undefined, 0.9, 0.5);
    near(e.mean, fine(seq(s), 0.9, 0.5), 0.01, `${s} weighted`);
  }
  assert.strictEqual(estimate(seq('0111'), undefined, 0.9, 0.5).mean, 0.181);
});

test('the estimate can climb and settle: 200 right answers give a high mean and a small sd', async () => {
  const { estimate } = await load();
  const rs = Array.from({ length: 200 }, (_, i) => ({ key: `k${i % 4}`, x: 1, b: 0, c: 1 / 3 }));
  const e = estimate(rs);
  assert.ok(e.mean >= 1.5, `mean ${e.mean}`);
  assert.ok(e.sd <= 0.35, `sd ${e.sd}`);
});

test('a prior from a lesson finished under the old rule starts the estimate higher', async () => {
  const { estimate, BEFORE_PRIOR } = await load();
  assert.deepStrictEqual(estimate([], BEFORE_PRIOR), { mean: 0.5, sd: 0.8, n: 0, items: 0 });
  assert.strictEqual(estimate(seq('0'), BEFORE_PRIOR).mean, 0.158);
  assert.strictEqual(estimate(seq('000'), BEFORE_PRIOR).mean, -0.321);
  assert.strictEqual(estimate(seq('111'), BEFORE_PRIOR).mean, 0.834);
});

test('learned: four right on two items is enough; three is not; one slip does not take it away', async () => {
  const { estimate, isLearned, enoughEvidence } = await load();
  assert.strictEqual(isLearned(estimate(seq('111'))), false, 'too few answers');
  assert.strictEqual(isLearned(estimate(seq('1111'))), true);
  assert.strictEqual(isLearned(estimate(seq('0111111'))), true, 'a wrong answer first, then recovery');
  assert.strictEqual(isLearned(estimate(seq('1101'))), false);
  const sameItem = [1, 1, 1, 1, 1].map((x) => ({ key: 'only', x, b: 0, c: 1 / 3 }));
  assert.strictEqual(enoughEvidence(estimate(sameItem)), false, 'one item five times is one example');
  assert.strictEqual(isLearned(estimate(sameItem)), false);
  assert.strictEqual(isLearned(estimate(seq('11110')), true), true, 'a slip after learning');
  assert.strictEqual(isLearned(estimate(seq('111000')), true), false, 'three wrong in a row takes it away');
  assert.strictEqual(isLearned(estimate([]), true), false, 'nothing to keep with no answers');
  assert.strictEqual(isLearned(undefined, true), false);
  assert.strictEqual(isLearned({ mean: 2, sd: 0.2, n: 0, items: 0 }, true), false, 'no answers behind it');
});

test('learned needs a settled estimate, not just a high mean', async () => {
  const { isLearned } = await load();
  assert.strictEqual(isLearned({ mean: 0.8, sd: 0.95, n: 5, items: 3 }), false, 'sd too wide');
  assert.strictEqual(isLearned({ mean: 0.8, sd: 0.85, n: 5, items: 3 }), true);
  assert.strictEqual(isLearned({ mean: 0.45, sd: 0.85, n: 5, items: 3 }), false, 'mean too low');
});

// A deterministic simulation of the learned rule: 10,000 seeded people each answer up
// to 20 questions (items rotate over four, all at b = 0); we count how many are ever
// called "learned" along the way.
function mulberry32(seed) {
  let a = seed;
  return () => {
    a = (a + 0x6D2B79F5) | 0;
    let t = Math.imul(a ^ (a >>> 15), 1 | a);
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t;
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
  };
}

async function learnedRate({ c, theta, answers, runs = 10000, seed = 7 }) {
  const { estimate, isLearned, pCorrect } = await load();
  const rand = mulberry32(seed);
  let hits = 0;
  for (let r = 0; r < runs; r += 1) {
    const rs = [];
    const p = theta === null ? c : pCorrect(theta, 0, c);
    for (let k = 0; k < answers; k += 1) {
      rs.push({ key: `k${k % 4}`, x: rand() < p ? 1 : 0, b: 0, c });
      if (isLearned(estimate(rs))) { hits += 1; break; }
    }
  }
  return hits / runs;
}

test('simulation: a random guesser almost never reaches learned (2 and 3 options, 20 answers)', async () => {
  for (const c of [1 / 2, 1 / 3]) {
    const rate = await learnedRate({ c, theta: null, answers: 20 });
    assert.ok(rate <= 0.02, `guessing at c=${c}: ${rate}`);
  }
});

test('simulation: someone who knows it (θ = 1.5) reaches learned within 8 answers', async () => {
  for (const c of [1 / 3, 1 / 4]) {
    const rate = await learnedRate({ c, theta: 1.5, answers: 8 });
    assert.ok(rate >= 0.8, `knower at c=${c}: ${rate}`);
  }
  // 2-option items say less per answer, so the same person needs longer (the trade-off, pinned)
  assert.ok(await learnedRate({ c: 1 / 2, theta: 1.5, answers: 8 }) >= 0.45, 'two options within 8');
  assert.ok(await learnedRate({ c: 1 / 2, theta: 1.5, answers: 20 }) >= 0.85, 'two options within 20');
});

test('responses that are not answers are ignored, never thrown on', async () => {
  const { estimate } = await load();
  const junk = [null, {}, { x: 2, b: 0, c: 0 }, { x: 1, b: NaN, c: 0 }, { x: 1, b: 0, c: 1 }, { key: 'a', x: 1, b: 0, c: 1 / 3 }];
  assert.deepStrictEqual(estimate(junk), estimate([{ key: 'a', x: 1, b: 0, c: 1 / 3 }]));
  assert.deepStrictEqual(estimate(undefined), estimate([]));
});

test('a malformed prior falls back to N(0, 1)', async () => {
  const { estimate } = await load();
  const base = estimate(seq('0111'));
  for (const bad of [{ mean: 0, sd: 0 }, { mean: 0, sd: -1 }, { mean: NaN, sd: 1 }, { mean: 0, sd: Infinity }, {}, null, 'x']) {
    assert.deepStrictEqual(estimate(seq('0111'), bad), base, JSON.stringify(bad));
  }
});

test('information never returns NaN', async () => {
  const { information } = await load();
  for (const th of [-1000, 1000, Infinity, -Infinity, NaN]) {
    const v = information(th, 0, 1 / 3);
    assert.ok(Number.isFinite(v) && v >= 0, `θ = ${th}: ${v}`);
  }
  assert.strictEqual(information(1000, 0, 0), 0);
});

test('difficulty moves by an Elo step, shrinking with use, and stays within 1 of its level', async () => {
  const { updateDifficulty, levelB } = await load();
  assert.deepStrictEqual(updateDifficulty({ b: 0, n: 0 }, 1, 0, 0), { b: -0.05, n: 1 }, 'right when expected 50%: K = 0.1, so 0.1·(0.5 − 1)');
  assert.deepStrictEqual(updateDifficulty({ b: 0, n: 5 }, 0, 0, 1 / 3), { b: 0.0333, n: 6 }, 'K = 0.1/(1+0.2·5) = 0.05; 0.05·(2/3)');
  assert.deepStrictEqual(updateDifficulty({ b: -1.95, n: 0 }, 1, 3, 0, 'easy'), { b: -1.9507, n: 1 });
  assert.deepStrictEqual(updateDifficulty({ b: 1.99, n: 0 }, 0, 4, 0, 'hard'), { b: 2, n: 1 }, 'clamped at level + 1');
  assert.deepStrictEqual(updateDifficulty({}, 1, 0, 0), { b: -0.05, n: 1 }, 'no record yet: starts at the level');
  for (const bad of [NaN, Infinity, -Infinity, undefined, 'x']) {
    const rec = { b: 0.3, n: 4 };
    assert.deepStrictEqual(updateDifficulty(rec, 1, bad, 1 / 3), { b: 0.3, n: 4 }, `θ ${bad}`);
    assert.deepStrictEqual(updateDifficulty(rec, 1, 0, bad), { b: 0.3, n: 4 }, `c ${bad}`);
  }
  assert.deepStrictEqual(updateDifficulty(undefined, 1, 0, 0), { b: -0.05, n: 1 });
  assert.deepStrictEqual(updateDifficulty(null, 1, 0, 0), { b: -0.05, n: 1 });
  assert.strictEqual(levelB('easy'), -1);
  assert.strictEqual(levelB('nonsense'), 0);
});
