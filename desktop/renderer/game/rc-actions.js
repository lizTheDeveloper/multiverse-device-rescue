// Reclaim City's click actions, re-done for Device Rescue. The game's own app.js
// (which also sends analytics, asks for notifications and talks to its server)
// is never loaded, so this is the part of it game mode needs, as pure functions:
// they take the game state and return the next one, plus where to go and what
// link to open. Nothing here is tracked or sent anywhere.
export const SUPPORTED_RC_SCREENS = new Set(['district', 'briefing', 'debrief', 'milestone']);
const MAP = { screen: 'map', params: {} };
const PM_KIND = { 'pm-cat-flag': 'flag', 'pm-cat-changed': 'changed', 'pm-cat-none': 'clear', 'pm-cat-clear': 'clear', 'pm-cat-reopen': 'reopen' };
const httpsOnly = (u) => (typeof u === 'string' && u.startsWith('https://') ? u : undefined);

export function routeFor(hash, parseRoute) {
  if (typeof hash !== 'string' || !hash.startsWith('#/')) return MAP;
  const r = parseRoute(hash);
  return SUPPORTED_RC_SCREENS.has(r.screen) ? r : MAP;
}

export function afterRecorded(rc, state, mission) {
  const districtId = rc.missionDistrict(mission);
  const wasComplete = Boolean(state.seenProgress?.[districtId]?.includes(100));
  const reaction = rc.debriefReaction(state, mission);
  const progress = rc.calcDistrictProgress(state, districtId);
  let next = state;
  if (districtId && rc.isMissionDone(state.missions[mission.id])) {
    const seen = new Set(state.seenProgress?.[districtId] || []);
    for (const m of [25, 50, 75, 100]) if (progress.percent >= m) seen.add(m);
    next = { ...state, seenProgress: { ...state.seenProgress, [districtId]: [...seen].sort((a, b) => a - b) } };
  }
  if (progress.total > 0 && progress.percent === 100 && !wasComplete) {
    return { state: next, route: `#/milestone/${districtId}` };
  }
  return {
    state: next,
    route: `#/district/${districtId}${mission.phase ? `?tab=${mission.phase}` : ''}`,
    reaction: reaction ? { districtId, reaction } : null,
  };
}

export function fileRc(rc, state, missionId, answers) {
  const mission = rc.MISSIONS.find((m) => m.id === missionId);
  if (!mission) return { state, route: '#/city' };
  const filed = rc.fileDebrief(state, mission, answers);
  if (!filed) return { state, incomplete: true };
  const next = rc.ensureBurst(rc.streakAfterFiling(
    rc.noteFirstTwoFactor(filed.state, mission, filed.state.missions[missionId]), filed.event));
  return afterRecorded(rc, next, mission);
}

export function applyRcAction(rc, state, action, data = {}) {
  const id = data.mission;
  switch (action) {
    case 'go-do-it':
      return { state: rc.markMissionStarted(state, id), open: httpsOnly(data.url), route: `#/mission/${id}/debrief` };
    case 'i-did-it':
      return { state, route: `#/mission/${id}/debrief` };
    case 'mission-step':
      return { state: rc.markMissionStarted(state, id), open: httpsOnly(data.href) };
    case 'password-not-needed': {
      const mission = rc.MISSIONS.find((m) => m.id === id);
      const next = mission ? rc.recordNotNeeded(state, id) : state;
      if (next === state) return { state };
      return afterRecorded(rc, rc.ensureBurst(rc.updateStreak(next)), mission);
    }
    case 'reset-anyway':
      return { state, ui: { resetAnyway: id } };
    case 'line-up-burst':
      return { state: rc.startBurst(state) };
    case 'set-password-manager':
      // Only the game's own choices; anything else would change which steps show.
      if (!(rc.PASSWORD_MANAGERS || []).some((p) => p.value === data.pm)) return { state };
      return { state: { ...state, passwordManager: data.pm } };
    case 'toggle-account': {
      const acct = state.accounts && state.accounts[data.account];
      if (!acct) return { state };
      return { state: rc.toggleAccount(state, data.account, !acct.enabled) };
    }
    case 'add-custom-account': {
      const name = typeof data.name === 'string' ? data.name.trim() : '';
      if (!name) return { state };
      const list = [...(state.customAccounts?.[data.district] || []), name];
      return { state: { ...state, customAccounts: { ...state.customAccounts, [data.district]: list } } };
    }
    case 'remove-custom-account': {
      const list = state.customAccounts?.[data.district];
      const i = Number(data.index);
      if (!list || !Number.isInteger(i) || i < 0 || i >= list.length) return { state };
      return { state: { ...state, customAccounts: { ...state.customAccounts, [data.district]: list.filter((_, j) => j !== i) } } };
    }
    case 'dismiss-intro':
      return { state: { ...state, seenIntros: { ...state.seenIntros, [data.district]: true } } };
    default:
      if (PM_KIND[action]) {
        const next = rc.applyCategoryAction(state, data.district, PM_KIND[action], data.raw);
        return { state: next };
      }
      return { state }; // share-card and every action game mode doesn't include
  }
}
