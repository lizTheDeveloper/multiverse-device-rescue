// Item response theory for one person on one computer. Pure maths, no storage.
//
// Model: a Rasch (one-parameter logistic) model with a fixed guessing floor.
// For a person with ability θ on a concept, and an item with difficulty b and
// k answer options,
//
//     P(right | θ, b) = c + (1 − c) · σ(θ − b),   σ(z) = 1 / (1 + e^(−z)),
//     c = min(0.5, 1/k)   (blind guessing on a k-option item).
//
// Nothing per item is estimated except b, and c is known from the item, so the
// model stays honest with a handful of answers. Discrimination is fixed at 1.
//
// Ability is the posterior mean (EAP) over a grid θ ∈ [−4, 4], step 0.1, with
// a normal prior N(μ0, σ0²): N(0, 1) normally, N(0.5, 0.8²) for a concept whose
// lesson was finished under the old rule ("before"). Every answer counts in
// full (DECAY = 1), so `mean` and `sd` are the true posterior mean and sd given
// all the answers, and the estimate can reach high values and a small sd after
// a long run of right answers. A person who starts badly and then learns is
// carried by the "stays learned" rule and by new answers outweighing old ones
// as they pile up; recency weighting is still available through `decay` < 1,
// where the k-th of n answers gets weight w_k = max(floor, decay^(n−1−k)) on its
// log-likelihood. (Plain decay without a floor caps the effective sample size,
// which made `sd` meaningless and the mean unable to pass about 0.6.)
//
//     log post(θ) = −(θ − μ0)² / (2σ0²) + Σ_k w_k · [x_k log P_k(θ) + (1 − x_k) log(1 − P_k(θ))]
//     θ̂ = Σ θ_j post(θ_j) / Σ post(θ_j),   sd = sqrt(Σ (θ_j − θ̂)² post(θ_j) / Σ post(θ_j))
//
// With the default weights (all 1) `sd` is the posterior sd. If a caller passes
// decay < 1 it is the sd of a down-weighted posterior: still a fair measure of
// how settled the estimate is, but not a confidence interval.
//
// Item difficulty starts at its authored level (easy −1, medium 0, hard +1)
// and moves by an Elo-style step after each answer, using θ̂ from before it:
//
//     b ← b + K(n) · (P(right | θ̂, b) − x),   K(n) = 0.1 / (1 + 0.2 n),
//
// clamped to within 1 of the authored level, so one person's answers can tune
// an item but never turn an easy one hard.
export const GRID = Object.freeze(Array.from({ length: 81 }, (_, i) => Math.round((-4 + i * 0.1) * 10) / 10));
export const PRIOR = Object.freeze({ mean: 0, sd: 1 });
export const BEFORE_PRIOR = Object.freeze({ mean: 0.5, sd: 0.8 });
export const DECAY = 1;
export const LEVEL_B = Object.freeze({ easy: -1, medium: 0, hard: 1 });
export const WEIGHT_FLOOR = 0.5;
// "Learned": enough evidence (at least MIN_RESPONSES answers on at least
// MIN_ITEMS different items), the estimate at or above LEARNED_AT, and the
// estimate settled (sd at or below LEARNED_SD_CAP). The sd condition scales the
// evidence needed by the guessing floor: items with more guessing say less per
// answer, so the sd comes down more slowly. These values were chosen by
// simulation and are pinned in test/profile-irt.test.js: a person guessing at
// random reaches "learned" within 20 answers in under 2% of runs (about 1.5% on
// 2-option items, 1.6% on 3-option), while someone who knows the concept
// (θ = 1.5, items at b = 0) gets there within 8 answers about 82% of the time on
// 3- and 4-option items. On 2-option items the same person needs more answers
// (about half get there within 8): a right answer says less when half of the
// guesses are right too. Once learned, a concept stays learned until the
// estimate falls below SLIPPED_BELOW, so a single slip doesn't take it away;
// with no answers at all there is nothing to keep.
export const LEARNED_AT = 0.5;
export const LEARNED_SD_CAP = 0.89;
export const SLIPPED_BELOW = -0.25;
export const MIN_RESPONSES = 4;
export const MIN_ITEMS = 2;
const K0 = 0.1;
const K_SLOPE = 0.2;
const B_RANGE = 1;

const round = (v, d = 3) => Math.round(v * 10 ** d) / 10 ** d;
const sigmoid = (z) => 1 / (1 + Math.exp(-z));

export function guessFloor(k) {
  return Number.isInteger(k) && k >= 2 ? Math.min(0.5, 1 / k) : 0;
}

export function levelB(level) {
  return Object.prototype.hasOwnProperty.call(LEVEL_B, level) ? LEVEL_B[level] : LEVEL_B.medium;
}

export function pCorrect(theta, b, c) {
  return c + (1 - c) * sigmoid(theta - b);
}

// Fisher information of one item at θ, for choosing the next item.
export function information(theta, b, c) {
  const s = sigmoid(theta - b);
  const p = c + (1 - c) * s;
  const dp = (1 - c) * s * (1 - s);
  const v = (dp * dp) / (p * (1 - p));
  return Number.isFinite(v) ? v : 0;
}

// `responses`: oldest first, each { key, x: 1|0, b, c }. Returns the
// posterior mean and sd (3 decimals), how many answers counted, and how many
// different items they were on.
export function estimate(responses, prior = PRIOR, decay = DECAY, floor = WEIGHT_FLOOR) {
  const pr = prior && Number.isFinite(prior.mean) && Number.isFinite(prior.sd) && prior.sd > 0 ? prior : PRIOR;
  const dc = Number.isFinite(decay) && decay > 0 && decay <= 1 ? decay : DECAY;
  const fl = Number.isFinite(floor) && floor >= 0 && floor <= 1 ? floor : WEIGHT_FLOOR;
  const rs = (Array.isArray(responses) ? responses : [])
    .filter((r) => r && (r.x === 0 || r.x === 1) && Number.isFinite(r.b) && Number.isFinite(r.c) && r.c >= 0 && r.c < 1);
  const n = rs.length;
  const logPost = GRID.map((t) => -((t - pr.mean) ** 2) / (2 * pr.sd * pr.sd));
  rs.forEach((r, k) => {
    const w = Math.max(fl, dc ** (n - 1 - k));
    for (let j = 0; j < GRID.length; j += 1) {
      const p = pCorrect(GRID[j], r.b, r.c);
      logPost[j] += w * (r.x === 1 ? Math.log(p) : Math.log(1 - p));
    }
  });
  const top = Math.max(...logPost);
  const post = logPost.map((v) => Math.exp(v - top));
  const total = post.reduce((a, v) => a + v, 0);
  const mean = post.reduce((a, v, j) => a + v * GRID[j], 0) / total;
  const variance = post.reduce((a, v, j) => a + v * (GRID[j] - mean) ** 2, 0) / total;
  return { mean: round(mean), sd: round(Math.sqrt(variance)), n, items: new Set(rs.map((r) => r.key)).size };
}

export function enoughEvidence(est) {
  return !!est && est.n >= MIN_RESPONSES && est.items >= MIN_ITEMS;
}

// `wasLearned`: the concept has been learned before (or finished under the
// old rule). Then only a fall below SLIPPED_BELOW takes "learned" away, but
// there must be at least one answer behind the estimate.
export function isLearned(est, wasLearned = false) {
  if (wasLearned) return !!est && est.n > 0 && est.mean >= SLIPPED_BELOW;
  return enoughEvidence(est) && est.mean >= LEARNED_AT && est.sd <= LEARNED_SD_CAP;
}

// One Elo-style step for an item's difficulty after an answer `x` given by
// someone whose estimate was `theta` just before. `n`: answers this item has
// had before this one. Returns the new { b, n }.
export function updateDifficulty(rec = {}, x, theta, c, level = 'medium') {
  if (!rec) rec = {};
  if (!Number.isFinite(theta) || !Number.isFinite(c)) return rec;
  const { b, n } = rec;
  const base = levelB(level);
  const start = Number.isFinite(b) ? b : base;
  const seen = Number.isInteger(n) && n >= 0 ? n : 0;
  const k = K0 / (1 + K_SLOPE * seen);
  const next = start + k * (pCorrect(theta, start, c) - (x === 1 ? 1 : 0));
  return { b: round(Math.min(base + B_RANGE, Math.max(base - B_RANGE, next)), 4), n: seen + 1 };
}
