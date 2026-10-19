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

test('the estimate: known values for the model the plan fixes (prior N(0,1), decay 0.7, 3 options, medium items)', async () => {
  const { estimate } = await load();
  assert.deepStrictEqual(estimate([]), { mean: 0, sd: 1, n: 0, items: 0 });
  const cases = { 1: [0.207, 0.978], 111: [0.43, 0.944], '0111': [0.261, 0.921], 110: [-0.191, 0.898], 1110: [-0.129, 0.893], 11100: [-0.441, 0.858], '000': [-0.75, 0.836] };
  for (const [s, [mean, sd]] of Object.entries(cases)) {
    const e = estimate(seq(s));
    assert.strictEqual(e.mean, mean, `${s} mean`);
    assert.strictEqual(e.sd, sd, `${s} sd`);
    assert.strictEqual(e.n, s.length);
  }
  assert.strictEqual(estimate(seq('111', 0.5)).mean, 0.295, 'two options: right answers say less');
});

test('the estimate agrees with an independent, finer integration', async () => {
  const { estimate, pCorrect, DECAY } = await load();
  function fine(rs) {
    let num = 0; let den = 0;
    for (let t = -6; t <= 6; t += 0.001) {
      let lp = -(t * t) / 2;
      rs.forEach((r, k) => { const p = pCorrect(t, r.b, r.c); lp += DECAY ** (rs.length - 1 - k) * (r.x ? Math.log(p) : Math.log(1 - p)); });
      const w = Math.exp(lp); num += w * t; den += w;
    }
    return num / den;
  }
  for (const s of ['1', '111', '0111', '110', '000', '10101']) near(estimate(seq(s)).mean, fine(seq(s)), 0.01, s);
});

test('a prior from a lesson finished under the old rule starts the estimate higher', async () => {
  const { estimate, BEFORE_PRIOR } = await load();
  assert.deepStrictEqual(estimate([], BEFORE_PRIOR), { mean: 0.5, sd: 0.8, n: 0, items: 0 });
  assert.strictEqual(estimate(seq('0'), BEFORE_PRIOR).mean, 0.158);
  assert.strictEqual(estimate(seq('000'), BEFORE_PRIOR).mean, -0.153);
  assert.strictEqual(estimate(seq('111'), BEFORE_PRIOR).mean, 0.752);
});

test('learned: three right on two items is enough; two is not; a recovery counts; one slip does not take it away', async () => {
  const { estimate, isLearned, enoughEvidence } = await load();
  assert.strictEqual(isLearned(estimate(seq('11'))), false, 'too few answers');
  assert.strictEqual(isLearned(estimate(seq('111'))), true);
  assert.strictEqual(isLearned(estimate(seq('0111'))), true, 'older answers count less');
  assert.strictEqual(isLearned(estimate(seq('110'))), false);
  const sameItem = [1, 1, 1].map((x) => ({ key: 'only', x, b: 0, c: 1 / 3 }));
  assert.strictEqual(enoughEvidence(estimate(sameItem)), false, 'one item three times is one example');
  assert.strictEqual(isLearned(estimate(seq('1110')), true), true, 'a slip after learning');
  assert.strictEqual(isLearned(estimate(seq('11100')), true), false, 'two in a row takes it away');
});

test('responses that are not answers are ignored, never thrown on', async () => {
  const { estimate } = await load();
  const junk = [null, {}, { x: 2, b: 0, c: 0 }, { x: 1, b: NaN, c: 0 }, { x: 1, b: 0, c: 1 }, { key: 'a', x: 1, b: 0, c: 1 / 3 }];
  assert.deepStrictEqual(estimate(junk), estimate([{ key: 'a', x: 1, b: 0, c: 1 / 3 }]));
  assert.deepStrictEqual(estimate(undefined), estimate([]));
});

test('difficulty moves by an Elo step, shrinking with use, and stays within 1 of its level', async () => {
  const { updateDifficulty, levelB } = await load();
  assert.deepStrictEqual(updateDifficulty({ b: 0, n: 0 }, 1, 0, 0), { b: -0.05, n: 1 }, 'right when expected 50%: K = 0.1, so 0.1·(0.5 − 1)');
  assert.deepStrictEqual(updateDifficulty({ b: 0, n: 5 }, 0, 0, 1 / 3), { b: 0.0333, n: 6 }, 'K = 0.1/(1+0.2·5) = 0.05; 0.05·(2/3)');
  assert.deepStrictEqual(updateDifficulty({ b: -1.95, n: 0 }, 1, 3, 0, 'easy'), { b: -1.9507, n: 1 });
  assert.deepStrictEqual(updateDifficulty({ b: 1.99, n: 0 }, 0, 4, 0, 'hard'), { b: 2, n: 1 }, 'clamped at level + 1');
  assert.deepStrictEqual(updateDifficulty({}, 1, 0, 0), { b: -0.05, n: 1 }, 'no record yet: starts at the level');
  assert.strictEqual(levelB('easy'), -1);
  assert.strictEqual(levelB('nonsense'), 0);
});
