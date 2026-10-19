'use strict';

/*
 * Filling a walkthrough's placeholders with what the scan found, for the list
 * and the game alike. The engine's steps say `<path-to-plist>` or `<label>`
 * where the scan already knows the value. The person may copy these steps into
 * Terminal, and scan data (paths, labels, program names) can be chosen by
 * whoever put the thing there, so a value is filled in only when it can't run
 * as code or change the step's markup:
 *
 *   - pid, port: digits only, left unquoted;
 *   - label, bundle id, name, process, username: letters, digits, dot,
 *     underscore, hyphen, not starting with "-"; single-quoted;
 *   - path, plist, program: an absolute path of letters (any script), digits,
 *     spaces and / . _ + , : @ % = - only: no quote, $, backtick, backslash,
 *     ; | & < > ( ) * ? [ ] { } ~ ! #, newline or control character, and no
 *     space at either end. Always single-quoted.
 *
 * The first data field that holds a value decides: an unsafe value leaves the
 * placeholder as written (never another field's value instead). Quotes the
 * template put on both sides of a placeholder are replaced by ours, never
 * doubled; a quote on one side only leaves it unfilled. Only POSIX shells are
 * filled: `platform` 'darwin' or 'linux'. Windows (PowerShell quotes
 * differently) and an unknown platform fill nothing. The step is escaped
 * afterwards by whoever draws it.
 *
 *   StepFill.fillPlaceholders(text, data, platform | { platform }) -> string
 *   StepFill.safeValue(kind, value) -> the text to put in, or null
 *   StepFill.shellSafe(value) -> true for a value safe single-quoted in a shell
 *   StepFill.PLACEHOLDERS -> { name: { keys, kind } }
 *
 * Loaded as a plain script (global `StepFill`, also on window/globalThis);
 * the game's ES modules `import '../step-fill.js'` (or '../../step-fill.js')
 * and read globalThis.StepFill; tested from Node.
 */
const StepFill = (function () {
  const PLACEHOLDERS = {
    'path-to-plist': { keys: ['plist', 'plist_path'], kind: 'path' },
    plist: { keys: ['plist', 'plist_path'], kind: 'path' },
    path: { keys: ['path', 'program', 'plist', 'location'], kind: 'path' },
    'app path': { keys: ['path', 'location', 'program'], kind: 'path' },
    'path-to-binary': { keys: ['program', 'path'], kind: 'path' },
    program: { keys: ['program'], kind: 'path' },
    label: { keys: ['label'], kind: 'name' },
    'bundle-id': { keys: ['bundle_id'], kind: 'name' },
    name: { keys: ['name', 'label', 'process'], kind: 'name' },
    process: { keys: ['process', 'name'], kind: 'name' },
    username: { keys: ['username', 'user'], kind: 'name' },
    pid: { keys: ['pid'], kind: 'digits' },
    port: { keys: ['port', 'ports'], kind: 'digits' },
  };
  const SHELLS = new Set(['darwin', 'linux']);
  const SAFE_NAME = /^[A-Za-z0-9._-]{1,256}$/;
  const SAFE_VALUE = /^[\p{L}\p{N} /._+,:@%=-]+$/u;
  const QUOTES = '"\'‘’“”';
  const PLACEHOLDER = new RegExp(`([${QUOTES}]?)<([a-zA-Z][a-zA-Z0-9_ -]*)>([${QUOTES}]?)`, 'g');

  const shellSafe = (v) => typeof v === 'string' && v !== '' && v.length <= 1024 && SAFE_VALUE.test(v)
    && !v.startsWith('-') && v.trim() === v;

  function safeValue(kind, value) {
    if (kind === 'digits') {
      const v = typeof value === 'number' ? (Number.isInteger(value) && value >= 0 ? String(value) : '') : value;
      return typeof v === 'string' && /^\d{1,10}$/.test(v) ? v : null;
    }
    if (typeof value !== 'string') return null;
    if (kind === 'name') return SAFE_NAME.test(value) && !value.startsWith('-') ? `'${value}'` : null;
    if (kind === 'path') return value.startsWith('/') && shellSafe(value) ? `'${value}'` : null;
    return null;
  }

  // The first field with something in it (an array gives its first item).
  function present(data, keys) {
    for (const k of keys) {
      let v = data[k];
      if (Array.isArray(v)) v = v.length ? v[0] : undefined;
      if (typeof v === 'string' && v !== '') return v;
      if (typeof v === 'number') return v;
    }
    return undefined;
  }

  function fillPlaceholders(text, data, platform) {
    const t = String(text == null ? '' : text);
    const p = platform && typeof platform === 'object' ? platform.platform : platform;
    if (!SHELLS.has(p)) return t;
    const d = data && typeof data === 'object' ? data : {};
    return t.replace(PLACEHOLDER, (all, q1, name, q2) => {
      const spec = PLACEHOLDERS[name.toLowerCase()];
      if (!spec || (!q1 !== !q2)) return all;
      const safe = safeValue(spec.kind, present(d, spec.keys));
      return safe === null ? all : safe;
    });
  }

  return { PLACEHOLDERS, safeValue, shellSafe, fillPlaceholders };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = StepFill;
}
// A top-level const isn't a window property. The game's ES modules import this
// file for its side effect and read it from globalThis (window in the app).
if (typeof globalThis !== 'undefined') {
  globalThis.StepFill = StepFill;
}
