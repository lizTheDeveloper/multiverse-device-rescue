// Reclaim City's own "turn sharing off" switch. Game mode never loads the
// game's analytics or error-reporting scripts, but the switch is set anyway,
// first, so no game code ever starts with sharing on.
export const OPT_OUT = { 'reclaim-city.analytics-off': '1', 'umami.disabled': '1' };

export function applyOptOut(storage) {
  try {
    for (const [k, v] of Object.entries(OPT_OUT)) storage.setItem(k, v);
    return true;
  } catch (_) {
    return false;
  }
}
