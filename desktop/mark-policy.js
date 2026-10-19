// Gatekeeping for "It's mine" (mark-mine / unmark-mine IPC channels).
//
// The engine says which findings may be marked, as a `markable` block on each
// one. For a background task that is {kind, id, code, label, program, plist,
// arguments_sha256}; for a setting or installed item (a sharing service, a
// proxy, an extension...) it is {kind, id, code, group}. The id is the
// engine's hash over everything the mark pins.
//
// The renderer sends ONLY that id. The main process looks up the target it
// stored from the scan it ran itself and passes that to the engine, so the
// renderer can never confirm one thing and have another written. The engine
// then re-reads the item from disk (or runs the check again) and refuses
// unless it still hashes to the same id (--expect-id), so something that
// changed after the checkup is never marked. Everything goes to the engine
// as argv, never through a shell.
//
// One item reported by several checks is marked as one: the stored target
// carries every {code, id} the scan offered for that same item, the engine
// re-checks each id and saves all of them or none. "Stop treating this as
// mine" likewise removes every mark the scan showed for that item, or that
// this app saved since.

const MARK_ID = /^[0-9a-f]{12}$/;
const CODE = /^[a-z0-9_]+\.[a-z0-9_]+\.[a-z0-9_]+$/;
const SHA256 = /^[0-9a-f]{64}$/;
const BACKGROUND_TASK = 'background_task';
// Settings and installed items (rescue/known_items.py ITEM_KINDS).
const ITEM_KINDS = new Set([
  'sharing_service', 'network_proxy', 'system_extension', 'browser_extension',
  'app_permissions', 'ssh_authorized_keys', 'ai_tooling',
]);
// Checks for monitoring software: never markable, whatever the engine says.
const NEVER_MARKABLE_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);

function isCleanString(s, max = 1024) {
  return typeof s === 'string' && s.length > 0 && s.length < max && !s.includes('\0');
}

function moduleOfCode(code) {
  return String(code).split('.')[1];
}

// The validated target from a markable block, or null.
function markTarget(markable) {
  const m = markable;
  if (!m || typeof m !== 'object') return null;
  if (typeof m.id !== 'string' || !MARK_ID.test(m.id)) return null;
  if (typeof m.code !== 'string' || !CODE.test(m.code)) return null;
  if (NEVER_MARKABLE_MODULES.has(moduleOfCode(m.code))) return null;
  if (ITEM_KINDS.has(m.kind)) {
    if (typeof m.group !== 'string' || !MARK_ID.test(m.group)) return null;
    return { kind: m.kind, id: m.id, code: m.code, group: m.group };
  }
  if (m.kind !== BACKGROUND_TASK) return null;
  if (typeof m.arguments_sha256 !== 'string' || !SHA256.test(m.arguments_sha256)) return null;
  if (!isCleanString(m.label, 256) || m.label.startsWith('-')) return null;
  if (!isCleanString(m.program) || !(m.program.startsWith('/') || m.program.startsWith('~'))) return null;
  if (!isCleanString(m.plist) || !m.plist.startsWith('/')) return null;
  return { kind: m.kind, id: m.id, code: m.code, label: m.label, program: m.program, plist: m.plist };
}

function isValidMarkId(id) {
  return typeof id === 'string' && MARK_ID.test(id);
}

// What makes two findings "the same item". Two offers group only if every
// one of these matches; the engine's `ids` list is never trusted on its own.
function itemKey(m) {
  if (ITEM_KINDS.has(m.kind)) return JSON.stringify([m.kind, m.group]);
  return JSON.stringify([m.kind, m.label, m.plist, m.program, m.arguments_sha256,
    typeof m.content_sha256 === 'string' ? m.content_sha256 : '']);
}

function markedKey(data) {
  if (ITEM_KINDS.has(data.marked_kind) && isValidMarkId(data.marked_key)) {
    return JSON.stringify([data.marked_kind, data.marked_key]);
  }
  return JSON.stringify([data.label, data.plist, data.program, data.arguments_sha256]);
}

function idList(value) {
  return Array.isArray(value) ? value.filter(isValidMarkId) : [];
}

function createMarkPolicy() {
  let markable = new Map(); // id -> target, from the last scan only
  let marked = new Map(); // id -> every marked id for the same item, from the last scan (or saved since)
  return {
    // Replace (not merge) with what the latest scan offered.
    //
    // One item is often reported by more than one check, each with its own
    // mark id. The engine lists them together (markable.ids); a sibling is
    // kept only if this same scan offered it as markable for the same item,
    // so one confirmation can never reach a different item.
    remember(doc) {
      const offered = new Map(); // id -> { target, key, ids }
      const markedSeen = new Map(); // id -> { key, ids }
      const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];
      for (const mod of modules) {
        if (!mod || !Array.isArray(mod.findings)) continue;
        if (NEVER_MARKABLE_MODULES.has(mod.name)) continue;
        for (const f of mod.findings) {
          const t = f && markTarget(f.markable);
          if (t && !offered.has(t.id)) offered.set(t.id, { target: t, key: itemKey(f.markable), ids: idList(f.markable.ids) });
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
        // Two ids for one code would mean two different items: keep only this one.
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
    // are every {code, id} the same item was offered under in that scan.
    targetFor(id) {
      return isValidMarkId(id) && markable.has(id) ? markable.get(id) : null;
    },
    // After the engine saved marks for `target`: those ids may be unmarked
    // ("Undo") in this session. Only ids this target asked for count.
    rememberMarked(target, result) {
      if (!target || !result || (result.status !== 'marked' && result.status !== 'already_marked')) return;
      const asked = new Set((target.marks || [{ id: target.id }]).map((m) => m.id));
      const saved = Array.isArray(result.ids) ? result.ids.filter((x) => isValidMarkId(x) && asked.has(x)) : [];
      const ids = saved.length ? saved : (isValidMarkId(result.id) && asked.has(result.id) ? [result.id] : []);
      const group = [...new Set(ids)].sort();
      for (const id of group) marked.set(id, group);
    },
    isUnmarkAllowed(id) {
      return isValidMarkId(id) && marked.has(id);
    },
    // Every marked id for the same item as `id` ([] if none).
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
    const result = await runMark(target);
    if (typeof policy.rememberMarked === 'function') policy.rememberMarked(target, result);
    return result;
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
    // Every mark for the same item, so all of its warnings come back.
    const ids = typeof policy.unmarkIdsFor === 'function' ? policy.unmarkIdsFor(id) : [id];
    return await runUnmark(ids.length ? ids : [id]);
  } catch (err) {
    return refusal('engine_error', `We could not save that: ${err && err.message ? err.message : err}`);
  }
}

module.exports = {
  createMarkPolicy, handleMark, handleUnmark, markTarget, isValidMarkId, ITEM_KINDS, NEVER_MARKABLE_MODULES,
  // The same list gates the connection watch (watch.js); the game's ledger.js keeps a copy, and a test keeps them equal.
  MONITORING_MODULES: NEVER_MARKABLE_MODULES,
};
