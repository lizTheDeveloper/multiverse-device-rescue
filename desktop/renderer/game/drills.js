// The drill bank: invented findings for practice, kept as data files beside
// the lessons. Pure, except loadDrills, which takes the import function it
// should use. A drill is always stamped DRILL, never counted in integrity,
// sorted, confirmed or reported, and never about monitoring software.
export const DRILL_FILES = ['./drills/gatehouse.js', './drills/wires.js', './drills/engine-room.js', './drills/junkyard.js'];
export const MAX_DRILLS = 3;
export const DRILL_ANSWERS = ['mine', 'threat', 'closer'];
// Words no drill may use (desktop/test/game-drills.test.js).
export const MONITORING_WORDS = /stalker|monitor|spy|keylog|watching|being watched|track(?:s|ing)? (?:you|someone)/i;

// One file at a time: a broken file is left out, never the whole bank.
export async function loadDrills(importModule) {
  const results = await Promise.allSettled(DRILL_FILES.map((f) => Promise.resolve().then(() => importModule(f)).then((m) => m && m.default)));
  const out = [];
  const ids = new Set();
  for (const r of results) {
    if (r.status !== 'fulfilled' || !Array.isArray(r.value)) continue;
    for (const d of r.value) {
      if (d && typeof d.id === 'string' && !ids.has(d.id) && DRILL_ANSWERS.includes(d.answer) && d.clues && typeof d.clues === 'object' && typeof d.clues.what === 'string') { ids.add(d.id); out.push(d); }
    }
  }
  return out;
}

// About one per four real signals, at most three.
export function drillCount(realCount) {
  return Math.min(MAX_DRILLS, Math.ceil(Math.max(0, Number(realCount) || 0) / 4));
}

// Drills for these districts. The ones already answered right come last; the
// seed rotates which one comes first, so a new sweep offers a different one.
export function pickDrills(bank, districtIds, deck, seed = 0) {
  const want = new Set(districtIds || []);
  const pool = (bank || []).filter((d) => d && want.has(d.district));
  const right = (d) => !!(deck && deck.once && deck.once[`drill:${d.id}`]);
  const rotate = (xs) => {
    if (xs.length < 2) return xs;
    const k = ((Math.floor(Number(seed) || 0) % xs.length) + xs.length) % xs.length;
    return [...xs.slice(k), ...xs.slice(0, k)];
  };
  return [...rotate(pool.filter((d) => !right(d))), ...rotate(pool.filter(right))];
}

// This sweep's drills, drawn from the districts the real queue is in, taking
// turns across those districts in the queue's order.
export function chooseDrills(bank, realSignals, deck, seed = 0) {
  const real = (realSignals || []).filter((x) => x && x.kind === 'real');
  const n = drillCount(real.length);
  if (!n) return [];
  const districts = [...new Set(real.map((x) => x.districtId))];
  const lists = districts.map((id) => pickDrills(bank, [id], deck, seed));
  const out = [];
  for (let round = 0; out.length < n && lists.some((l) => l.length > round); round += 1) {
    for (const l of lists) if (out.length < n && l[round]) out.push(l[round]);
  }
  return out;
}

export function drillSignal(d) {
  return { id: `drill:${d.id}`, kind: 'drill', severity: d.severity, title: d.title,
    description: (d.clues && d.clues.what) || '', districtId: d.district, module: null, finding: null,
    missionId: null, fixable: false, marked: false, stale: false, fp: 'drill', count: 1, tag: null, changed: false, drill: d };
}

// A drill after every fourth real signal; any left over go at the end.
export function mixDrills(real, drills = []) {
  drills = Array.isArray(drills) ? drills : [];
  const out = [];
  let k = 0;
  (real || []).forEach((x, i) => {
    out.push(x);
    if ((i + 1) % 4 === 0 && k < drills.length) { out.push(drillSignal(drills[k])); k += 1; }
  });
  while (k < drills.length) { out.push(drillSignal(drills[k])); k += 1; }
  return out;
}
