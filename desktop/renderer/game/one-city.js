// The one-city view's numbers. Two kinds of progress, never mixed:
// confirmed (the computer proved it) and reported (the person said so).
// Nothing here changes the game state; it only reads it.
import { countReclaimed } from './progress.js';
import { VERIFIED_MISSIONS, verifyMission, disagreement, DONE } from './verified-missions.js';

// The same starting points as the Reclaim City links in LEARN_MORE.
const FOCUS = { hacked: 'master-keys', identity: 'reclamation' };

export function focusFor(situation) {
  return (situation && FOCUS[situation.id]) || 'computer';
}

// verifyMission needs the game mission's step count, or it never confirms.
function stepCountOf(rc, id) {
  const m = rc && Array.isArray(rc.MISSIONS) ? rc.MISSIONS.find((x) => x.id === id) : null;
  return m && Array.isArray(m.steps) ? m.steps.length : undefined;
}

// Confirmed: Plan A's reclaimed missions, plus game missions the person
// finished from the scan that the current scan still confirms. Reported:
// every other game mission the person filed as done. `yours` is never counted.
export function countConfirmedAndReported({ rc, progress, rcState, scanConfirmed, doc }) {
  let confirmed = countReclaimed(progress);
  let reported = 0;
  const records = (rcState && rcState.missions) || {};
  const fromScan = (scanConfirmed && scanConfirmed.missions) || {};
  for (const [id, record] of Object.entries(records)) {
    if (!record || !DONE.has(record.status)) continue;
    const v = fromScan[id] ? verifyMission(id, doc, stepCountOf(rc, id)) : null;
    if (v && v.allConfirmed) confirmed += 1;
    else reported += 1;
  }
  return { confirmed, reported };
}

// One card per game district, in chapter order. checkAgain marks a district
// with a mission the person filed as done that the scan now disagrees with.
export function accountDistrictCards({ rc, rcState, doc }) {
  const missions = (rcState && rcState.missions) || {};
  const checkAgain = new Set();
  for (const id of Object.keys(VERIFIED_MISSIONS)) {
    if (disagreement(missions[id], verifyMission(id, doc, stepCountOf(rc, id)))) {
      const m = rc.MISSIONS.find((x) => x.id === id);
      if (m) checkAgain.add(rc.missionDistrict(m));
    }
  }
  return [...rc.DISTRICTS].sort((a, b) => a.chapter - b.chapter).map((d) => {
    const p = rc.calcDistrictProgress(rcState, d.id);
    return { id: d.id, name: d.name, description: d.description, chapter: d.chapter,
      percent: p.percent, total: p.total, completed: p.completed, checkAgain: checkAgain.has(d.id) };
  });
}

// The device mission (from this scan) that looks at any of these modules.
export function deviceMissionFor(city, modules) {
  for (const d of (city && city.districts) || []) {
    for (const m of d.missions || []) if (modules.includes(m.module)) return m;
  }
  return null;
}
