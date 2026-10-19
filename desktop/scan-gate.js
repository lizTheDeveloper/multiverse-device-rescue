// Changes to the computer (a fix, an undo, "It's mine") never race a scan.
// While a scan runs, they are refused with a plain answer: the person sees
// results as checks finish, but acts on them once the checkup is done, when
// the main process has the whole scan to check each request against. A scan
// asked for while a change is still running starts once that change is done,
// so it never reads a half-made change.
//
// Pure apart from the promises it is handed; tested from Node.

const SCAN_RUNNING_FIX = 'The checkup is still running. You can fix this once it’s done. Nothing was changed.';
const SCAN_RUNNING_MARK = 'The checkup is still running. You can do this once it’s done. Nothing was changed.';

function createScanGate() {
  let scans = 0;
  const changes = new Set();
  return {
    scanning: () => scans > 0,
    // Runs `scan()` once no change is running; the gate is closed until it settles.
    async runScan(scan) {
      scans += 1;
      try {
        while (changes.size) await Promise.allSettled([...changes]);
        return await scan();
      } finally {
        scans -= 1;
      }
    },
    // Runs `change()` unless a scan is running; then resolves with `refused` instead.
    async runChange(change, refused) {
      if (scans > 0) return refused;
      const p = Promise.resolve().then(change);
      changes.add(p);
      try {
        return await p;
      } finally {
        changes.delete(p);
      }
    },
  };
}

function fixRefusal(module) {
  return {
    module: typeof module === 'string' ? module : null,
    applied: false, verified: false, changes: [], how_to_undo: [],
    status: 'refused', error: 'scan_running', message: SCAN_RUNNING_FIX,
  };
}

function markRefusal() {
  return { status: 'refused', error: 'scan_running', message: SCAN_RUNNING_MARK, id: null, label: null, how_to_undo: [] };
}

module.exports = { createScanGate, fixRefusal, markRefusal, SCAN_RUNNING_FIX, SCAN_RUNNING_MARK };
