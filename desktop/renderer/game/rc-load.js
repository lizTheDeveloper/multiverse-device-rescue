// Loads the parts of Reclaim City that game mode uses, as one object, so the
// rest of game mode can take it as a plain argument (and tests can load the
// same files from disk). In the app the files come from app://rescue/rc/.
const FILES = {
  district: 'screens/district.js', briefing: 'screens/briefing.js', debrief: 'screens/debrief.js',
  milestone: 'screens/milestone.js', state: 'state.js', missions: 'data/missions.js',
  accounts: 'data/accounts.js', districts: 'data/districts.js', debriefUtil: 'utils/debrief.js',
  bursts: 'utils/bursts.js', pmCategories: 'utils/pm-categories.js', feelings: 'utils/scout-feelings.js',
  status: 'utils/mission-status.js', calc: 'utils/calc.js', router: 'router.js',
  keyboard: 'utils/keyboard.js', scout: 'components/scout.js',
};
export const RC_ENTRY_FILES = Object.values(FILES);

export async function loadRc(importFile = (rel) => import(`../rc/${rel}`)) {
  const entries = await Promise.all(Object.entries(FILES).map(async ([k, rel]) => [k, await importFile(rel)]));
  const m = Object.fromEntries(entries);
  return {
    renderDistrict: m.district.renderDistrict,
    renderBriefing: m.briefing.renderBriefing,
    renderDebrief: m.debrief.renderDebrief,
    debriefReaction: m.debrief.debriefReaction,
    renderMilestone: m.milestone.renderMilestone,
    loadState: m.state.loadState,
    saveState: m.state.saveState,
    createInitialState: m.state.createInitialState,
    markMissionStarted: m.state.markMissionStarted,
    toggleAccount: m.state.toggleAccount,
    updateStreak: m.state.updateStreak,
    streakAfterFiling: m.state.streakAfterFiling,
    MISSIONS: m.missions.MISSIONS,
    missionDistrict: m.missions.missionDistrict,
    ACCOUNTS: m.accounts.ACCOUNTS,
    DISTRICTS: m.districts.DISTRICTS,
    fileDebrief: m.debriefUtil.fileDebrief,
    recordNotNeeded: m.debriefUtil.recordNotNeeded,
    visibleQuestions: m.debriefUtil.visibleQuestions,
    ensureBurst: m.bursts.ensureBurst,
    startBurst: m.bursts.startBurst,
    applyCategoryAction: m.pmCategories.applyCategoryAction,
    noteFirstTwoFactor: m.feelings.noteFirstTwoFactor,
    markTwoFactorHugSeen: m.feelings.markTwoFactorHugSeen,
    isMissionDone: m.status.isMissionDone,
    DONE_STATUSES: m.status.DONE_STATUSES,
    calcDistrictProgress: m.calc.calcDistrictProgress,
    parseRoute: m.router.parseRoute,
    keyActivationTarget: m.keyboard.keyActivationTarget,
    newScreenVisit: m.scout.newScreenVisit,
  };
}
