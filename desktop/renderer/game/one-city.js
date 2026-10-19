// The one-city view's numbers. Two kinds of progress, never mixed:
// confirmed (the computer proved it) and reported (the person said so).
// Nothing here changes the game state; it only reads it.
import { countReclaimed } from './progress.js';
import { VERIFIED_MISSIONS, verifyMission, disagreement, DONE } from './verified-missions.js';

// The same starting points as the Reclaim City links in LEARN_MORE.
const FOCUS = { hacked: 'master-keys', identity: 'reclamation' };

// Several worries: the first one (in the worry list's order) that has a district.
export function focusFor(situation) {
  if (!situation) return 'computer';
  const ids = Array.isArray(situation.ids) ? situation.ids : [situation.id];
  for (const id of ids) if (FOCUS[id]) return FOCUS[id];
  return 'computer';
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
  // No game state yet (or it failed to load): count from an empty one.
  const state = rcState || rc.createInitialState();
  return [...rc.DISTRICTS].sort((a, b) => a.chapter - b.chapter).map((d) => {
    const p = rc.calcDistrictProgress(state, d.id);
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

// The deck's bars (and every HUD): CONFIRMED is device fixes a re-check
// proved (deck.confirmed) plus game missions finished from the checkup that it
// still confirms. A finding that's simply gone after a re-sweep isn't counted.
// YOU REPORTED is everything else the person filed as done. Never summed.
export function countDeckBars({ rc, deck, rcState, scanConfirmed, doc }) {
  const fixes = Object.keys((deck && deck.confirmed) || {}).length + ((deck && Number.isInteger(deck.confirmedEarlier)) ? deck.confirmedEarlier : 0);
  if (!rc) return { confirmed: fixes, reported: 0 };
  const accounts = countConfirmedAndReported({ rc, progress: { missions: {} }, rcState, scanConfirmed, doc });
  return { confirmed: fixes + accounts.confirmed, reported: accounts.reported };
}
