// Gatekeeping for the 'run-fix' IPC channel ("Fix it for me").
//
// The engine decides which modules may be fixed from the app (rescue/app_fixes.json)
// and says so in its own scan output, as a `fixable` block on each finding. The
// main process remembers only the modules the engine marked that way in scans it
// ran itself, and refuses anything else BEFORE starting the engine. The engine
// then checks the same list again on its own, so neither side trusts the other.
//
// Nothing the renderer sends is trusted: the module name arrives over IPC.

const FIX_MODULE_NAME = /^[a-z0-9_]+$/;

function isValidFixModuleName(name) {
  return typeof name === 'string' && FIX_MODULE_NAME.test(name);
}

function hasWellFormedFixable(finding) {
  const f = finding && finding.fixable;
  return !!f
    && typeof f === 'object'
    && typeof f.will_change === 'string' && f.will_change.trim() !== ''
    && Array.isArray(f.how_to_undo) && f.how_to_undo.length > 0
    && f.how_to_undo.every((s) => typeof s === 'string' && s.trim() !== '');
}

function createFixPolicy() {
  let allowed = new Set();
  return {
    // Replace (not merge) the allowance with whatever the latest scan offered.
    remember(doc) {
      const next = new Set();
      const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
      for (const mod of modules) {
        if (!mod || !isValidFixModuleName(mod.name) || !Array.isArray(mod.findings)) continue;
        if (mod.findings.some(hasWellFormedFixable)) next.add(mod.name);
      }
      allowed = next;
    },
    isAllowed(name) {
      return isValidFixModuleName(name) && allowed.has(name);
    },
  };
}

function refusal(module, error, message) {
  return {
    module: typeof module === 'string' ? module : null,
    applied: false,
    verified: false,
    changes: [],
    how_to_undo: [],
    status: 'refused',
    error,
    message,
  };
}

// Pure handler behind ipcMain.handle('run-fix'). Never throws.
async function handleRunFix(name, { policy, runFix }) {
  if (!isValidFixModuleName(name) || !policy.isAllowed(name)) {
    return refusal(name, 'not_allowed', 'This fix is not available in the app. Use the written steps instead.');
  }
  try {
    return await runFix(name);
  } catch (err) {
    return refusal(name, 'engine_error', `We could not start the fix: ${err && err.message ? err.message : err}`);
  }
}

module.exports = { createFixPolicy, handleRunFix, isValidFixModuleName, hasWellFormedFixable };
