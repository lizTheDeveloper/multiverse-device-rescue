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

// Engine-level actions (e.g. disable_launch_agent) are offered per finding as
// {action, target, will_change, how_to_undo}. The main process allows only the
// exact action+target pairs the engine itself offered in a scan it ran.
const FIX_ACTION_NAME = /^[a-z0-9_]+$/;
const QUARANTINE_ID = /^[0-9]{8}T[0-9]{6}Z-[A-Za-z0-9][A-Za-z0-9._-]{0,200}$/;

function isValidAction(action) {
  return typeof action === 'string' && FIX_ACTION_NAME.test(action);
}

function isValidTarget(target) {
  return typeof target === 'string' && target.startsWith('/') && target.length < 1024 && !target.includes('\0');
}

function isValidQuarantineId(id) {
  return typeof id === 'string' && QUARANTINE_ID.test(id);
}

function isActionFixable(finding) {
  return hasWellFormedFixable(finding) && finding.fixable.action !== undefined;
}

function createFixPolicy() {
  let allowed = new Set();
  let actions = new Set();
  const undoable = new Set();
  return {
    // Replace (not merge) the allowance with whatever the latest scan offered.
    remember(doc) {
      const next = new Set();
      const nextActions = new Set();
      const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
      for (const mod of modules) {
        if (!mod || !isValidFixModuleName(mod.name) || !Array.isArray(mod.findings)) continue;
        // An action fixable never makes its whole module fixable.
        if (mod.findings.some((f) => hasWellFormedFixable(f) && f.fixable.action === undefined)) next.add(mod.name);
        for (const f of mod.findings) {
          if (isActionFixable(f) && isValidAction(f.fixable.action) && isValidTarget(f.fixable.target)) {
            nextActions.add(JSON.stringify([f.fixable.action, f.fixable.target]));
          }
        }
      }
      allowed = next;
      actions = nextActions;
    },
    isActionAllowed(action, target) {
      return isValidAction(action) && isValidTarget(target) && actions.has(JSON.stringify([action, target]));
    },
    // Undo is allowed only for ids the engine returned from an action this process ran.
    noteUndo(id) { if (isValidQuarantineId(id)) undoable.add(id); },
    isUndoAllowed(id) { return isValidQuarantineId(id) && undoable.has(id); },
    forgetUndo(id) { undoable.delete(id); },
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

// Pure handler behind ipcMain.handle('run-fix-action'). Never throws.
async function handleRunAction(action, target, { policy, runAction }) {
  if (!policy.isActionAllowed(action, target)) {
    return refusal(action, 'not_allowed', 'This fix is not available in the app. Use the written steps instead.');
  }
  try {
    const result = await runAction(action, target);
    if (result && result.status === 'fixed' && isValidQuarantineId(result.quarantine_id)) {
      policy.noteUndo(result.quarantine_id);
    }
    return result;
  } catch (err) {
    return refusal(action, 'engine_error', `We could not start the fix: ${err && err.message ? err.message : err}`);
  }
}

// Pure handler behind ipcMain.handle('undo-fix'). Never throws.
async function handleRunUndo(quarantineId, { policy, runUndo }) {
  if (!policy.isUndoAllowed(quarantineId)) {
    return refusal('undo', 'not_allowed', 'We can only undo something Device Rescue turned off in this session. Use the written steps instead.');
  }
  try {
    const result = await runUndo(quarantineId);
    if (result && result.status === 'restored') policy.forgetUndo(quarantineId);
    return result;
  } catch (err) {
    return refusal('undo', 'engine_error', `We could not start the undo: ${err && err.message ? err.message : err}`);
  }
}

module.exports = {
  createFixPolicy, handleRunFix, handleRunAction, handleRunUndo,
  isValidFixModuleName, hasWellFormedFixable, isValidAction, isValidTarget, isValidQuarantineId,
};
