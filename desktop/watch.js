// The connection watch (run-watch / stop-watch IPC channels).
//
// The engine watches which programs connect where for the chosen minutes and
// prints one scan-shaped document with a single `connection_watch` module. Its
// result replaces any earlier watch in the last checkup (merged by module
// name, like a re-check), so it lasts until the next checkup and is never
// stored anywhere else. A watch needs a checkup to merge into, runs one at a
// time (and never alongside a checkup), and is off while the checkup has found
// possible monitoring software.
const { mergeModuleResult } = require('./recheck');
const { MONITORING_MODULES } = require('./mark-policy');

const WATCH_MINUTES = [1, 2, 5, 10, 15, 30];
const WATCH_MODULE = 'connection_watch';
// How long a watch gets to exit after "stop" before it is killed.
const STOP_GRACE_MS = 15000;
const SCAN_BUSY_MESSAGE = 'A connection watch is running. Stop it, or let it finish, then run the checkup.';

function fail(reason, message) {
  return { ok: false, reason, message };
}

// The same test the renderer's game gate uses (app.js mayBeWatched): a warning
// or critical finding from a monitoring check. Their info notes ("No device
// backups found", "Keyboard access: 3 apps") are on almost every computer.
function foundMonitoring(doc) {
  return doc.modules.some((m) => m && MONITORING_MODULES.has(m.name) && Array.isArray(m.findings)
    && m.findings.some((f) => f && (f.severity === 'critical' || f.severity === 'warning')));
}

// Pure handler behind ipcMain.handle('run-watch'). Never throws. `runWatch`
// resolves with the engine's document; `isBusy` covers checkups and watches.
// `logError` gets the engine's own error (exit code, last stderr lines) when a
// watch fails; the person sees only the plain message.
async function handleWatch(minutes, { getLastDoc, setLastDoc, runWatch, policies, isBusy, onEvent, logError = console.error }) {
  if (!WATCH_MINUTES.includes(minutes)) return fail('bad_minutes', 'Pick how long to watch from the list.');
  if (isBusy()) return fail('busy', 'Something is already running. Try again when it finishes.');
  const last = getLastDoc();
  if (!last || !Array.isArray(last.modules)) return fail('no_scan', 'Run the checkup first.');
  if (foundMonitoring(last)) {
    return fail('monitoring', 'The connection watch is off while this checkup has found possible monitoring software.');
  }
  let result;
  try {
    result = await runWatch(minutes, onEvent);
  } catch (err) {
    logError('The connection watch failed:', err);
    result = null;
  }
  // Merge into the checkup as it is now: a re-check may have landed meanwhile.
  // (A new checkup can't: it is refused while a watch runs.)
  const { doc, module } = mergeModuleResult(getLastDoc(), result, WATCH_MODULE);
  if (!module) return fail('failed', 'The connection watch couldn’t finish. Your checkup results are unchanged.');
  setLastDoc(doc);
  for (const p of policies) p.remember(doc);
  return { ok: true, doc };
}

// Ask a running watch to stop; kill it if it hasn't exited within graceMs.
// Resolves once it exited or was killed. Used by the Stop button, on quit and
// when the window goes away, so the engine never outlives the app.
function stopActiveWatch(handle, { graceMs = STOP_GRACE_MS } = {}) {
  if (!handle) return Promise.resolve();
  handle.stop();
  return new Promise((resolve) => {
    const timer = setTimeout(() => { handle.kill(); resolve(); }, graceMs);
    const done = () => { clearTimeout(timer); resolve(); };
    handle.promise.then(done, done);
  });
}

module.exports = { WATCH_MINUTES, WATCH_MODULE, SCAN_BUSY_MESSAGE, handleWatch, stopActiveWatch };
