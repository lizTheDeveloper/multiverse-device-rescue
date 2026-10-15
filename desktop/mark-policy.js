// Gatekeeping for "This is mine" (mark-mine / unmark-mine IPC channels).
//
// The engine says which findings may be marked, as a `markable` block on each
// one ({kind, id, code, label, program, plist, arguments_sha256}). The id is
// the engine's hash over everything the mark pins.
//
// The renderer sends ONLY that id. The main process looks up the target it
// stored from the scan it ran itself and passes that to the engine, so the
// renderer can never confirm one thing and have another written. The engine
// then re-reads the task from disk and refuses unless it still hashes to the
// same id (--expect-id), so a task that changed after the checkup is never
// marked. Everything goes to the engine as argv, never through a shell.

const MARK_ID = /^[0-9a-f]{12}$/;
const CODE = /^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const KINDS = new Set(['background_task']);

function isCleanString(s, max = 1024) {
  return typeof s === 'string' && s.length > 0 && s.length < max && !s.includes('\0');
}

// The validated {kind, id, code, label, program, plist} from a markable block, or null.
function markTarget(markable) {
  const m = markable;
  if (!m || typeof m !== 'object') return null;
  if (!KINDS.has(m.kind)) return null;
  if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) return null;
  if (typeof m.code !== 'string' || !CODE.test(m.code)) return null;
  if (typeof m.arguments_sha256 !== 'string' || !SHA256.test(m.arguments_sha256)) return null;
  if (!isCleanString(m.label, 256) || m.label.startsWith('-')) return null;
  if (!isCleanString(m.program) || !(m.program.startsWith('/') || m.program.startsWith('~'))) return null;
  if (!isCleanString(m.plist) || !m.plist.startsWith('/')) return null;
  return { kind: m.kind, id: m.id, code: m.code, label: m.label, program: m.program, plist: m.plist };
}

function isValidMarkId(id) {
  return typeof id === 'string' && MARK_ID.test(id);
}

function createMarkPolicy() {
  let markable = new Map(); // id -> target, from the last scan only
  let marked = new Set();
  return {
    // Replace (not merge) with what the latest scan offered.
    remember(doc) {
      const nextMarkable = new Map();
      const nextMarked = new Set();
      const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
      for (const mod of modules) {
        if (!mod || !Array.isArray(mod.findings)) continue;
        for (const f of mod.findings) {
          const t = f && markTarget(f.markable);
          if (t) nextMarkable.set(t.id, t);
          const data = f && f.data;
          if (data && data.marked_by_user === true && isValidMarkId(data.known_item_id)) {
            nextMarked.add(data.known_item_id);
          }
        }
      }
      markable = nextMarkable;
      marked = nextMarked;
    },
    // The stored target for an id the last scan offered, or null.
    targetFor(id) {
      return isValidMarkId(id) && markable.has(id) ? markable.get(id) : null;
    },
    isUnmarkAllowed(id) {
      return isValidMarkId(id) && marked.has(id);
    },
  };
}

function refusal(error, message) {
  return { status: 'refused', error, message, id: null, label: null, how_to_undo: [] };
}

// Pure handler behind ipcMain.handle('mark-mine'). Takes only an id. Never throws.
async function handleMark(id, { policy, runMark }) {
  const target = policy.targetFor(id);
  if (!target) {
    return refusal('not_allowed', 'This item can’t be marked from the app. Nothing was changed.');
  }
  try {
    return await runMark(target);
  } catch (err) {
    return refusal('engine_error', `We could not save that: ${err && err.message ? err.message : err}`);
  }
}

// Pure handler behind ipcMain.handle('unmark-mine'). Never throws.
async function handleUnmark(id, { policy, runUnmark }) {
  if (!policy.isUnmarkAllowed(id)) {
    return refusal('not_allowed', 'That item isn’t marked as yours in this checkup. Nothing was changed.');
  }
  try {
    return await runUnmark(id);
  } catch (err) {
    return refusal('engine_error', `We could not save that: ${err && err.message ? err.message : err}`);
  }
}

module.exports = { createMarkPolicy, handleMark, handleUnmark, markTarget, isValidMarkId };
