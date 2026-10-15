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
//
// One task reported by several checks is marked as one: the stored target
// carries every {code, id} the scan offered for that same task, the engine
// re-checks each id and saves all of them or none. "Stop treating this as
// mine" likewise removes every mark the scan showed for that task.

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

// What makes two findings "the same task". Two offers group only if every
// one of these matches; the engine's `ids` list is never trusted on its own.
function taskKey(m) {
  return JSON.stringify([m.kind, m.label, m.plist, m.program, m.arguments_sha256,
    typeof m.content_sha256 === 'string' ? m.content_sha256 : '']);
}

function markedKey(data) {
  return JSON.stringify([data.label, data.plist, data.program, data.arguments_sha256]);
}

function idList(value) {
  return Array.isArray(value) ? value.filter(isValidMarkId) : [];
}

function createMarkPolicy() {
  let markable = new Map(); // id -> target, from the last scan only
  let marked = new Map(); // id -> every marked id for the same task, from the last scan only
  return {
    // Replace (not merge) with what the latest scan offered.
    //
    // One background task is often reported by more than one check, each with
    // its own mark id. The engine lists them together (markable.ids); a
    // sibling is kept only if this same scan offered it as markable for the
    // same task, so one confirmation can never reach a different task.
    remember(doc) {
      const offered = new Map(); // id -> { target, key, ids }
      const markedSeen = new Map(); // id -> { key, ids }
      const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
      for (const mod of modules) {
        if (!mod || !Array.isArray(mod.findings)) continue;
        for (const f of mod.findings) {
          const t = f && markTarget(f.markable);
          if (t && !offered.has(t.id)) offered.set(t.id, { target: t, key: taskKey(f.markable), ids: idList(f.markable.ids) });
          const data = f && f.data;
          if (data && data.marked_by_user === true && isValidMarkId(data.known_item_id) && !markedSeen.has(data.known_item_id)) {
            markedSeen.set(data.known_item_id, { key: markedKey(data), ids: idList(f.marked_ids) });
          }
        }
      }
      const nextMarkable = new Map();
      for (const [id, o] of offered) {
        const group = [id, ...o.ids.filter((other) => other !== id
          && offered.has(other) && offered.get(other).key === o.key)];
        const marks = [...new Set(group)]
          .map((gid) => ({ code: offered.get(gid).target.code, id: gid }))
          .sort((a, b) => (a.code < b.code ? -1 : a.code > b.code ? 1 : 0));
        // Two ids for one code would mean two different tasks: keep only this one.
        const codes = new Set(marks.map((m) => m.code));
        nextMarkable.set(id, { ...o.target, marks: codes.size === marks.length ? marks : [{ code: o.target.code, id }] });
      }
      const nextMarked = new Map();
      for (const [id, m] of markedSeen) {
        const group = [id, ...m.ids.filter((other) => other !== id
          && markedSeen.has(other) && markedSeen.get(other).key === m.key)];
        nextMarked.set(id, [...new Set(group)].sort());
      }
      markable = nextMarkable;
      marked = nextMarked;
    },
    // The stored target for an id the last scan offered, or null. Its `marks`
    // are every {code, id} the same task was offered under in that scan.
    targetFor(id) {
      return isValidMarkId(id) && markable.has(id) ? markable.get(id) : null;
    },
    isUnmarkAllowed(id) {
      return isValidMarkId(id) && marked.has(id);
    },
    // Every marked id for the same task as `id` in the last scan ([] if none).
    unmarkIdsFor(id) {
      return isValidMarkId(id) && marked.has(id) ? [...marked.get(id)] : [];
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
    // Every mark the scan showed for the same task, so the task's warnings all come back.
    const ids = typeof policy.unmarkIdsFor === 'function' ? policy.unmarkIdsFor(id) : [id];
    return await runUnmark(ids.length ? ids : [id]);
  } catch (err) {
    return refusal('engine_error', `We could not save that: ${err && err.message ? err.message : err}`);
  }
}

module.exports = { createMarkPolicy, handleMark, handleUnmark, markTarget, isValidMarkId };
