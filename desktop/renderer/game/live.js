// What the sweep has found so far. `rescue scan --live` puts each finished
// check on its progress line (`result`, the module as in the final JSON), so
// signals can be shown, and sorted, while the rest of the scan runs. Pure.
//
// Memory only, and only for this sweep: the finished scan replaces it. A
// monitoring check that finds something (held.js) stops it at once: nothing
// more arrives this sweep, so the safety flow after the scan is the only one.
import { HELD_MODULES, isDetection } from './held.js';

export function liveInit() {
  return { modules: [], held: false };
}

const plain = (x) => !!x && typeof x === 'object' && !Array.isArray(x);

// A progress event (app.js forwards the engine's). Only a finished check
// with a well-formed result adds anything; the same check twice is kept once.
export function liveApply(live, ev) {
  const l = live || liveInit();
  const r = ev && ev.phase === 'done' ? ev.result : null;
  if (l.held || !plain(r) || typeof r.name !== 'string' || !Array.isArray(r.findings)) return l;
  if (r.name !== ev.module) return l;
  if (HELD_MODULES.has(r.name) && r.findings.some((f) => f && isDetection(f))) return { modules: [], held: true };
  if (l.modules.some((m) => m.name === r.name)) return l;
  return { ...l, modules: [...l.modules, r] };
}

// A scan document of the checks finished so far, or null while there are none
// (or once something is held).
export function liveDoc(live, platform) {
  if (!live || live.held || !live.modules.length) return null;
  return { schema_version: 1, platform: typeof platform === 'string' ? platform : null, modules: live.modules };
}

// The signals to show while sweeping: critical and warning ones only (the
// low-priority pile waits for the deck), marked `live`. A live signal has no
// mission yet: its steps and any fix open on the deck once the scan is done.
export function liveSignals(signals) {
  return (signals || []).filter((x) => x && x.kind === 'real' && (x.severity === 'critical' || x.severity === 'warning') && !x.marked)
    .map((x) => ({ ...x, live: true, missionId: null, fixable: false }));
}
