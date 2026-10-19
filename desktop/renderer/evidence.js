'use strict';

/*
 * The Evidence block: what a finding actually saw, as short label/value rows
 * (path, program, settings file, label, bundle id, maker and whether that was
 * verified, which check and which commands, counts, versions, dates, hashes),
 * built from the engine's `data` and `made_by`. One pure helper for the list
 * and the game, so both show the same facts.
 *
 *   Evidence.evidenceRows(finding, { mode, held, checkName, commands, seen })
 *     -> [{ label, value, mono, copy }], with array flags `held` and
 *        `replacesDescription` (non-enumerable)
 *   Evidence.renderEvidence(rows, { title, copy, held }) -> HTML string (escaped)
 *   Evidence.replacesDescription(finding) -> true when the finding's prose
 *     must not show (keyboard access, every maker verified): show the rows
 *   Evidence.evidenceText(rows) -> "Label: value" lines, what "Copy all" copies
 *   Evidence.wireCopy(root, write) -> click handling for the copy buttons
 *   Evidence.noClipboard(mode, modules) -> true in city mode for a monitoring
 *     check's finding: render it with { copy: false }
 *
 * `value` is what shows; `copy` is the full value (a whole hash, a whole path).
 * Home folders read "~" in both, so a pasted block doesn't carry the account
 * name. Nothing here ever prints raw JSON: a value the adapters don't know is
 * shown as a short list, or left out.
 *
 * City mode, held monitoring finding: only what the help district asks the
 * person to write down (name, where found, how detected, maker + verified,
 * date). Nothing about fixing, marking or rewards, and no clipboard: drawn
 * large, with "Write this on paper or on another device."
 *
 * Loaded as a plain script (global `Evidence`, also on window for the game);
 * tested from Node.
 */
const Evidence = (function () {
  // The same three checks as app.js's ALWAYS_SAFETY_MODULES and game/held.js.
  const MONITORING_MODULES = new Set(['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']);
  const VT = typeof VisibleText !== 'undefined' ? VisibleText : require('./visible-text.js');
  const MAX_LIST = 8;         // items shown in one list value before "and N more"
  const MAX_ROWS = 24;        // rows in one block, whatever the finding carries
  const MAX_VALUE = 300;      // characters of one value shown (copy keeps up to MAX_COPY)
  const MAX_COPY = 4000;
  const MAX_PATH_SHOWN = 64;  // longer paths keep their start and end
  const MAX_COMMANDS = 3;     // commands named on the "Checked with" row

  const MONTHS = ['Jan', 'Feb', 'Mar', 'Apr', 'May', 'Jun', 'Jul', 'Aug', 'Sep', 'Oct', 'Nov', 'Dec'];

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  const isObj = (v) => v != null && typeof v === 'object' && !Array.isArray(v);
  const isScalar = (v) => v == null || ['string', 'number', 'boolean'].includes(typeof v);
  const clip = (s, n) => (s.length > n ? `${s.slice(0, n - 1)}\u2026` : s);

  /** "/Users/ann/x" -> "~/x"; also /home/<name>, /var/root and C:\Users\<name>. */
  function homeRelative(text) {
    return String(text == null ? '' : text)
      .replace(/(^|[\s'"=:(])\/(?:Users|home)\/(?!Shared(?:\/|$))[^/\s'"]+(?=\/|$|[\s'"])/g, '$1~')
      .replace(/(^|[\s'"=:(])[A-Za-z]:\\Users\\[^\\\s'"]+(?=\\|$|[\s'"])/g, '$1~');
  }

  const looksLikePath = (s) => typeof s === 'string' && (/^(~|\/|[A-Za-z]:\\)/.test(s));

  /**
   * A long path keeps whole folder names: its first two and last three
   * ("/tmp/claude-501/…/scratchpad/plan/gen4.py"), or last two, never a cut
   * in the middle of a name. Only a path whose names are themselves too long
   * falls back to its start and end.
   */
  function shortPath(p, max = MAX_PATH_SHOWN) {
    const s = homeRelative(p);
    if (s.length <= max) return s;
    const sep = s.includes('\\') && !s.includes('/') ? '\\' : '/';
    const parts = s.split(sep);
    // ["", "tmp", ...] for "/tmp/..." keeps the root with the first name.
    const lead = parts[0] === '' ? 3 : 2;
    if (parts.length > lead + 3) {
      const out = [...parts.slice(0, lead), '\u2026', ...parts.slice(-3)].join(sep);
      if (out.length <= max) return out;
      const tail = [...parts.slice(0, lead), '\u2026', ...parts.slice(-2)].join(sep);
      if (tail.length <= max) return tail;
    }
    const keepEnd = Math.ceil(max * 0.6);
    const keepStart = max - keepEnd - 1;
    return `${s.slice(0, keepStart)}\u2026${s.slice(-keepEnd)}`;
  }

  /** "78eb25a0…ca7f0" (first 8, last 5); the full hash goes in `copy`. */
  function shortHash(h) {
    const s = String(h || '');
    return s.length > 16 ? `${s.slice(0, 8)}\u2026${s.slice(-5)}` : s;
  }

  /**
   * An ISO date or date-time as a plain day, as written (no time-zone shift):
   * "2026-10-10T18:44:55+00:00" -> "10 Oct 2026". Anything else unchanged.
   */
  function plainDay(value) {
    if (value instanceof Date && !Number.isNaN(value.getTime())) {
      return `${value.getDate()} ${MONTHS[value.getMonth()]} ${value.getFullYear()}`;
    }
    const m = /^(\d{4})-(\d{2})-(\d{2})(?:[T ][\d:.]+(?:Z|[+-]\d{2}:?\d{2})?)?$/.exec(String(value == null ? '' : value).trim());
    if (!m) return value == null ? '' : String(value);
    const month = Number(m[2]);
    if (month < 1 || month > 12) return String(value);
    return `${Number(m[3])} ${MONTHS[month - 1]} ${m[1]}`;
  }

  /** Bytes as people read them: "2.4 GB". */
  function bytes(n) {
    const v = Number(n);
    if (!Number.isFinite(v) || v < 0) return String(n);
    const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let x = v;
    while (x >= 1000 && i < units.length - 1) { x /= 1000; i += 1; }
    return i === 0 ? `${v} bytes` : `${x >= 100 ? Math.round(x) : x.toFixed(1)} ${units[i]}`;
  }

  function humanize(key) {
    const words = String(key || '').replace(/_/g, ' ').trim();
    return words ? words.charAt(0).toUpperCase() + words.slice(1) : '';
  }

  /** A check's name for people: the engine's `check_name`, else its id in words. */
  function checkLabel(module, doc) {
    const mods = doc && Array.isArray(doc.modules) ? doc.modules : [];
    const hit = mods.find((m) => m && m.name === module);
    if (hit && typeof hit.check_name === 'string' && hit.check_name) return hit.check_name;
    return humanize(module);
  }

  /**
   * One row. `value` is clipped for show; `copy` keeps the whole of it.
   * Control and format characters (a newline, U+2028, a bidi override) are a
   * visible [U+XXXX] in the label, the value and the copy, so scan data can't
   * start a line that reads like another row in "Copy all" or "Ask about this".
   * `copy` as an array: one line each (the commands a check ran), each made
   * visible on its own, so only this file's own line breaks remain.
   */
  function row(label, value, { mono = false, copy } = {}) {
    const shown = clip(VT.visible(value == null ? '' : value), MAX_VALUE);
    const whole = Array.isArray(copy) ? copy.map(VT.visible).join('\n') : VT.visible(copy == null ? (value == null ? '' : value) : copy);
    const full = clip(whole, MAX_COPY);
    return { label: VT.visible(label), value: shown, mono, copy: full };
  }

  const pathRow = (label, p) => row(label, shortPath(p), { mono: true, copy: homeRelative(p) });
  const hashRow = (label, h) => row(label, shortHash(h), { mono: true, copy: String(h) });

  /** A list value: the first MAX_LIST items, then "and N more"; copy has all. */
  function listRow(label, items, { mono = true, fmt = (x) => x } = {}) {
    const all = items.map((x) => (looksLikePath(x) ? homeRelative(x) : String(fmtScalar(fmt(x)))));
    const shown = all.slice(0, MAX_LIST).map((x) => (looksLikePath(x) ? shortPath(x, all.length > 1 ? 48 : MAX_PATH_SHOWN) : x));
    const more = all.length > MAX_LIST ? `, and ${all.length - MAX_LIST} more` : '';
    return row(label, shown.join(', ') + more, { mono, copy: all.join(', ') });
  }

  function fmtScalar(v) {
    if (v === true) return 'yes';
    if (v === false) return 'no';
    if (v == null) return '';
    return String(v);
  }

  // ---- who made it -------------------------------------------------------

  /** "Microsoft Corporation · verified (Developer ID signature)". */
  function makerText(entry) {
    const e = entry || {};
    const name = e.name || 'Unknown maker';
    // "claims to be made by X; couldn't verify" only repeats the name and "not verified".
    const how = e.how && !/^claims to be made by/i.test(e.how) ? ` (${e.how})` : '';
    return `${name} \u00b7 ${e.verified ? 'verified' : 'not verified'}${how}`;
  }

  const baseName = (s) => String(s || '').split(/[\\/]/).filter(Boolean).pop() || String(s || '');

  /**
   * True when every program the finding names has a maker the engine
   * verified: each made_by entry is verified, and when the finding lists apps,
   * each app has one. (The engine says the same as `makers_verified`.)
   */
  function makersVerified(finding) {
    const f = finding || {};
    if (typeof f.makers_verified === 'boolean') return f.makers_verified;
    const entries = Array.isArray(f.made_by) ? f.made_by.filter(isObj) : [];
    if (!entries.length || !entries.every((e) => e.verified === true)) return false;
    const apps = isObj(f.data) && Array.isArray(f.data.apps) ? f.data.apps : null;
    if (!apps) return true;
    const subjects = new Set(entries.map((e) => e.subject));
    // An app is matched only by what the engine looked up: the name itself
    // for a string, the path for a {path, name} entry (never its own name).
    return apps.every((a) => { const k = verifiedSubject(a); return k != null && subjects.has(k); });
  }

  // What a maker can be verified for: a full path (the file attribution
  // checked). A bundle id never is: it is what the app says it is, and a TCC
  // row's id can belong to any program (rescue/serialize.py _app_subject).
  const isPath = (a) => typeof a === 'string' && (/^[/~]/.test(a) || /^[A-Za-z]:[\\/]/.test(a));
  const verifiedSubject = (a) => (typeof a === 'string' ? (isPath(a) ? a : null) : appSubject(a));

  /** The subject an "apps" entry was looked up by: itself, or its path. */
  function appSubject(a) {
    if (typeof a === 'string') return a;
    if (isObj(a)) for (const k of ['plist', 'path', 'program', 'exe', 'executable', 'binary']) if (typeof a[k] === 'string' && a[k]) return a[k];
    return null;
  }

  /**
   * "Made by" rows. One program: its maker. Several: the label stays "Made
   * by" and the program goes in the value ("python \u2014 Unknown maker \u00b7 not
   * verified"), so the label column stays short.
   */
  function makerRows(madeBy, { skip = new Set() } = {}) {
    const entries = (Array.isArray(madeBy) ? madeBy : []).filter((e) => isObj(e) && !skip.has(e.subject));
    if (entries.length === 1) return [row('Made by', makerText(entries[0]))];
    return entries.slice(0, MAX_LIST).map((e) => row('Made by', `${clip(baseName(e.subject), 40)} \u2014 ${makerText(e)}`,
      { copy: `${homeRelative(e.subject)} \u2014 ${makerText(e)}` }))
      .concat(entries.length > MAX_LIST ? [row('Made by', `and ${entries.length - MAX_LIST} more`)] : []);
  }

  const MAX_APPS = 16; // apps listed one per row (a permission list is marked app by app)

  /**
   * One row per app, names first and in the order the "It's mine" panel
   * lists them (markable.items), each with its maker:
   * "Visual Studio Code (com.microsoft.VSCode) \u2014 Microsoft Corporation \u00b7 verified".
   */
  function appRows(label, apps, madeBy, items) {
    const bySubject = new Map((Array.isArray(madeBy) ? madeBy : []).filter(isObj).map((e) => [e.subject, e]));
    const rows0 = (Array.isArray(items) ? items : []).filter((i) => isObj(i) && typeof i.key === 'string');
    const byKey = new Map(rows0.map((i) => [i.key, i]));
    const keys = apps.map(appSubject).filter((k) => k != null);
    // The panel's order first, then anything the panel doesn't list.
    const order = [...rows0.map((i) => i.key).filter((k) => keys.includes(k)), ...keys.filter((k) => !byKey.has(k))];
    const rows = order.slice(0, MAX_APPS).map((key) => {
      const item = byKey.get(key);
      const e = (item && isObj(item.made_by) ? item.made_by : null) || bySubject.get(key);
      const id = looksLikePath(key) ? shortPath(key, 48) : String(key);
      const name = item && typeof item.label === 'string' && item.label && item.label !== key ? item.label : '';
      const what = name ? `${name} (${id})` : id;
      const full = name ? `${name} (${homeRelative(key)})` : homeRelative(key);
      return row(label, e ? `${what} \u2014 ${makerText(e)}` : what, { mono: !name, copy: e ? `${full} \u2014 ${makerText(e)}` : full });
    });
    if (order.length > MAX_APPS) rows.push(row(label, `and ${order.length - MAX_APPS} more`, { copy: order.slice(MAX_APPS).map(homeRelative).join(', ') }));
    return rows;
  }

  // ---- how it was checked -------------------------------------------------

  /** A traced command as a short shell line ("codesign --verify …"). */
  function commandLine(cmd) {
    const argv = Array.isArray(cmd) ? cmd : (isObj(cmd) && Array.isArray(cmd.argv) ? cmd.argv : (typeof cmd === 'string' ? [cmd] : []));
    return homeRelative(argv.map((a) => (/^[\w@%+=:,./~-]+$/.test(String(a)) ? String(a) : `'${String(a).replace(/'/g, "'\\''")}'`)).join(' '));
  }

  /**
   * "codesign --verify … ~/…/Baba Is You.app": the program, its first flag,
   * and the last path it was given (the thing it looked at), so "…" never
   * hides what makes the line concrete.
   */
  function shortCommand(cmd) {
    const argv = Array.isArray(cmd) ? cmd : (isObj(cmd) && Array.isArray(cmd.argv) ? cmd.argv : (typeof cmd === 'string' ? cmd.split(/\s+/) : []));
    if (!argv.length) return '';
    const prog = baseName(argv[0]);
    const rest = argv.slice(1).map(String);
    const flag = rest.find((a) => /^-{1,2}[A-Za-z]/.test(a));
    let lastPath = null;
    for (let i = rest.length - 1; i >= 0; i -= 1) if (looksLikePath(rest[i])) { lastPath = i; break; }
    const shown = [prog];
    if (flag) shown.push(flag);
    const used = (flag ? 1 : 0) + (lastPath != null ? 1 : 0);
    if (rest.length > used) shown.push('\u2026');
    if (lastPath != null && rest[lastPath] !== flag) shown.push(shortPath(rest[lastPath], 40));
    return shown.join(' ');
  }

  function commandRow(commands) {
    const list = (Array.isArray(commands) ? commands : []).filter(Boolean);
    if (!list.length) return null;
    const shorts = [...new Set(list.map(shortCommand).filter(Boolean))];
    const shown = shorts.slice(0, MAX_COMMANDS).join(', ') + (shorts.length > MAX_COMMANDS ? `, and ${shorts.length - MAX_COMMANDS} more` : '');
    return row('Checked with', shown, { mono: true, copy: list.map(commandLine) });
  }

  // ---- per-module adapters -------------------------------------------------
  // Each returns { rows, used }: its rows first, then the generic rows for any
  // `data` key it didn't use. They only read; they never throw on odd data.

  const BACKGROUND_TASK_MODULES = ['launch_agent_audit', 'launchd_persistence_audit', 'scheduled_tasks_audit',
    'ai_worm_persistence', 'startup_optimizer', 'crypto_miner_persistence', 'linux_persistence_audit'];

  function backgroundTask(f) {
    const d = f.data;
    const rows = [];
    if (d.label) rows.push(row('Background task', d.label, { mono: true }));
    if (d.program) rows.push(pathRow('Runs', d.program));
    if (Array.isArray(d.arguments) && d.arguments.length) rows.push(listRow('With', d.arguments));
    if (d.plist) rows.push(pathRow('Settings file', d.plist));
    if (d.arguments_sha256) rows.push(hashRow('Arguments hash', d.arguments_sha256));
    if (d.content_sha256) rows.push(hashRow('Script hash', d.content_sha256));
    return { rows, used: ['label', 'program', 'arguments', 'plist', 'arguments_sha256', 'content_sha256'] };
  }

  const ADAPTERS = {
    code_signature_audit(f) {
      const d = f.data;
      const rows = [];
      if (d.name) rows.push(row('App', d.name));
      if (d.path) rows.push(pathRow('Where', d.path));
      if (d.detail) {
        // "codesign --verify failed on a signed object: /Applications/X.app: a sealed resource is missing or invalid"
        const reason = String(d.detail).split(': ').pop();
        rows.push(row('Signature check said', reason, { mono: true, copy: homeRelative(d.detail) }));
      }
      // The list may be partial: say how much of it was checked, here.
      if (Number.isInteger(d.apps_checked) && Number.isInteger(d.apps_total) && d.apps_total > 0) {
        rows.push(row('Checked', `${d.apps_checked} of ${d.apps_total} apps`));
      }
      return { rows, used: ['name', 'path', 'detail', 'apps_checked', 'apps_total'] };
    },
    session_revocation_scan(f) {
      const d = f.data;
      if (d.check !== 'ssh_authorized_keys') return { rows: [], used: [] };
      const rows = [pathRow('File', d.file || '~/.ssh/authorized_keys')];
      if (d.key_count != null) rows.push(row('Keys in it', d.key_count));
      if (d.list_sha256) rows.push(hashRow('List hash', d.list_sha256));
      return { rows, used: ['file', 'key_count', 'list_sha256'] };
    },
    hosts_file_check(f) {
      const d = f.data;
      const entries = Array.isArray(d.entries) ? d.entries.filter(isObj) : [];
      const rows = [pathRow('File', d.file || '/etc/hosts')];
      for (const e of entries.slice(0, MAX_LIST)) rows.push(row('Sends', `${e.hostname || '?'} \u2192 ${e.ip || '?'}`, { mono: true }));
      if (entries.length > MAX_LIST) rows.push(row('Sends', `and ${entries.length - MAX_LIST} more`, { copy: entries.slice(MAX_LIST).map((e) => `${e.hostname} -> ${e.ip}`).join(', ') }));
      if (d.count != null && d.count !== entries.length) rows.push(row('Entries', d.count));
      return { rows, used: ['file', 'entries', 'count'] };
    },
    suspicious_connections(f) {
      const d = f.data;
      const rows = [];
      if (d.process) rows.push(row('Program', d.process, { mono: true }));
      if (d.pid != null) rows.push(row('Process id', d.pid, { mono: true }));
      const ports = Array.isArray(d.ports) && d.ports.length ? d.ports : (d.port != null ? [d.port] : []);
      if (ports.length) rows.push(listRow(ports.length === 1 ? 'Port' : 'Ports', ports));
      if (d.remote || d.dest) rows.push(row('Other end', d.remote || d.dest, { mono: true }));
      return { rows, used: ['process', 'pid', 'port', 'ports', 'remote', 'dest'] };
    },
    resource_hog_identifier(f) {
      const d = f.data;
      const rows = [];
      if (d.name) rows.push(row('Program', d.name, { mono: true }));
      if (d.pid != null) rows.push(row('Process id', d.pid, { mono: true }));
      if (d.cpu_percent != null) rows.push(row('Processor use', `${d.cpu_percent}%`));
      if (d.memory_bytes != null) rows.push(row('Memory', bytes(d.memory_bytes)));
      if (d.command && d.command !== d.name) rows.push(row('Command line', shortPath(d.command, 120), { mono: true, copy: homeRelative(d.command) }));
      return { rows, used: ['name', 'pid', 'cpu_percent', 'memory_bytes', 'command'] };
    },
    security_baseline_diff(f) {
      const d = f.data;
      const since = d.baseline_captured_at ? plainDay(d.baseline_captured_at) : '';
      const rows = [];
      const added = Array.isArray(d.added) ? d.added : [];
      const removed = Array.isArray(d.disabled) ? d.disabled : (Array.isArray(d.removed) ? d.removed : []);
      if (added.length) rows.push(listRow(since ? `New since ${since}` : 'New', added));
      if (removed.length) rows.push(listRow(since ? `Turned off since ${since}` : 'Turned off', removed));
      if (since) rows.push(row('Last snapshot', since));
      return { rows, used: ['added', 'disabled', 'removed', 'baseline_captured_at'] };
    },
    keylogger_indicators(f) {
      const d = f.data;
      const apps = Array.isArray(d.apps) ? d.apps : [];
      const rows = apps.length ? appRows('Keyboard access', apps, f.made_by) : [];
      return { rows, used: ['apps'], makersDone: true };
    },
    stalkerware_scan(f) {
      const d = f.data;
      const rows = [];
      if (d.stalkerware_name) rows.push(row('Name', d.stalkerware_name));
      if (d.location) rows.push(looksLikePath(d.location) ? pathRow('Where found', d.location) : row('Where found', d.location, { mono: true }));
      if (d.detected_as) rows.push(row('Found as', d.detected_as));
      if (d.stalkerware_category) rows.push(row('Kind', d.stalkerware_category));
      if (d.confidence) rows.push(row('Confidence', d.confidence));
      return { rows, used: ['stalkerware_name', 'location', 'detected_as', 'stalkerware_category', 'confidence'] };
    },
  };
  for (const name of BACKGROUND_TASK_MODULES) ADAPTERS[name] = backgroundTask;
  // Lists of apps with a permission: one row per app, with its maker.
  for (const name of ['app_permissions', 'privacy_permissions_audit', 'accessibility_permissions']) {
    ADAPTERS[name] = (f) => {
      const apps = Array.isArray(f.data.apps) ? f.data.apps : [];
      return { rows: apps.length ? appRows('App', apps, f.made_by, isObj(f.markable) ? f.markable.items : null) : [],
        used: ['apps', 'service', 'display_name'], makersDone: apps.length > 0 };
    };
  }

  // ---- generic ---------------------------------------------------------------

  // Keys that are the engine's own bookkeeping, not evidence ("Check type:
  // suspicious_dns", "Source: filesystem").
  const SKIP = new Set(['check', 'severity_level', 'marked_by_user', 'mark_stale', 'mark_id', 'original_title',
    'used_pct', 'is_system_app', 'source', 'known_item_id', 'original_severity']);
  const skipKey = (key) => SKIP.has(key) || /_type$/.test(key) || /^check_/.test(key);
  // An empty value says nothing: never a row.
  const isEmpty = (v) => v == null || (typeof v === 'string' && v.trim() === '')
    || (Array.isArray(v) && !v.some((x) => !isEmpty(x))) || (isObj(v) && !Object.values(v).some((x) => !isEmpty(x)));
  // A key written for code ("font_smoothing", "mouseTrackingSpeed") in words.
  const keyLabel = (k) => (/^[a-z][a-z0-9]*(?:[_A-Z][a-z0-9]*)+$/.test(k) ? humanize(k.replace(/([a-z0-9])([A-Z])/g, '$1_$2').toLowerCase()) : k);
  const LABELS = {
    path: 'Where', location: 'Where', file: 'File', plist: 'Settings file', program: 'Runs', binary: 'Program file',
    label: 'Name', name: 'Name', app_name: 'App', item_name: 'Item', process: 'Program', pid: 'Process id',
    port: 'Port', ports: 'Ports', dest: 'Other end', remote: 'Other end', ip: 'Address', hostname: 'Website name',
    command: 'Command line', detail: 'Reported', value: 'Set to', version: 'Version', mount_point: 'Disk',
    device: 'Device', used_pct_str: 'Used', free_bytes: 'Free', total_bytes: 'Size', memory_bytes: 'Memory',
    cpu_percent: 'Processor use', count: 'How many', key_count: 'Keys', crash_count: 'Crashes', panic_count: 'Crashes',
    total_crashes: 'Crashes', profile_count: 'Profiles', most_recent_date: 'Most recent', last_seen: 'Last seen',
    baseline_captured_at: 'Last snapshot', apps: 'Apps', keys: 'Keys', confidence: 'Confidence',
    interval_seconds: 'Every (seconds)', bundle_id: 'Bundle id', team_id: 'Team id', signer: 'Signed by',
    servers: 'DNS servers', dns_servers: 'DNS servers', providers: 'Provider', provider: 'Provider',
    profile_ids: 'Profile id',
  };
  const MONO_KEYS = new Set(['pid', 'port', 'ports', 'ip', 'hostname', 'dest', 'remote', 'label', 'process',
    'bundle_id', 'team_id', 'command', 'device', 'value', 'keys', 'apps', 'detail', 'servers', 'dns_servers', 'profile_ids']);

  function genericRows(data, used) {
    const rows = [];
    for (const [key, v] of Object.entries(data)) {
      if (used.has(key) || skipKey(key) || isEmpty(v)) continue;
      const label = LABELS[key] || humanize(key);
      if (/_sha256$|^sha256$|_hash$|^hash$/.test(key) && typeof v === 'string') rows.push(hashRow(label, v));
      else if (/_bytes$/.test(key) && typeof v === 'number') rows.push(row(label, bytes(v)));
      else if (/(^|_)(date|at|time|since)$/.test(key) && typeof v === 'string') rows.push(row(label, plainDay(v)));
      else if (key === 'cpu_percent') rows.push(row(label, `${v}%`));
      else if (typeof v === 'string' && looksLikePath(v)) rows.push(pathRow(label, v));
      else if (isScalar(v)) rows.push(row(label, fmtScalar(v), { mono: MONO_KEYS.has(key) }));
      else if (Array.isArray(v)) {
        if (!v.length) continue;
        if (v.every(isScalar)) rows.push(listRow(label, v, { mono: MONO_KEYS.has(key) || v.some(looksLikePath) }));
        else if (v.every(isObj)) rows.push(listRow(label, v.map(flatObject), { mono: false }));
      } else if (isObj(v)) {
        // A small map ({"Arial.ttf": ["/Library/Fonts", …]}, {"chrome": 50}): one row per key.
        const entries = Object.entries(v).filter(([, x]) => !isEmpty(x) && (isScalar(x) || (Array.isArray(x) && x.every(isScalar))));
        for (const [k, x] of entries.slice(0, MAX_LIST)) {
          rows.push(Array.isArray(x) ? listRow(clip(keyLabel(k), 48), x) : row(clip(keyLabel(k), 48), fmtScalar(x), { mono: true }));
        }
        if (entries.length > MAX_LIST) rows.push(row(label, `and ${entries.length - MAX_LIST} more`));
      }
    }
    return rows;
  }

  /** {browser: "Brave", profiles: 7} -> "Brave, profiles 7". Scalars only. */
  function flatObject(o) {
    const parts = [];
    for (const [k, x] of Object.entries(o)) {
      if (!isScalar(x) || isEmpty(x) || skipKey(k)) continue;
      parts.push(typeof x === 'string' && parts.length === 0 ? (looksLikePath(x) ? shortPath(x, 48) : x) : `${humanize(k).toLowerCase()} ${fmtScalar(x)}`);
    }
    return parts.slice(0, 4).join(', ');
  }

  // ---- held (city) -----------------------------------------------------------

  /** The rows the help district asks the person to write down. */
  function heldRows(f, opts) {
    const d = isObj(f.data) ? f.data : {};
    const rows = [];
    const apps = Array.isArray(d.apps) ? d.apps : [];
    const name = d.stalkerware_name || d.name || d.app_name || (apps.length ? null : f.title);
    if (name) rows.push(row('Name', name));
    const where = d.location || d.path || d.program || d.plist;
    if (where) rows.push(looksLikePath(where) ? pathRow('Where found', where) : row('Where found', where, { mono: true }));
    if (apps.length) rows.push(listRow('Where found', apps));
    const how = d.detected_as ? `Found as ${d.detected_as}` : (f.module === 'keylogger_indicators' ? 'Has keyboard access (Input Monitoring)' : '');
    if (how) rows.push(row('How detected', how));
    const entries = (Array.isArray(f.made_by) ? f.made_by : []).filter(isObj);
    if (entries.length) rows.push(...makerRows(entries));
    else rows.push(row('Made by', 'Not known'));
    rows.push(row('Date', plainDay(opts.seen instanceof Date || typeof opts.seen === 'string' ? opts.seen : new Date())));
    return rows;
  }

  // ---- the finding's own words ---------------------------------------------

  // The keyboard-access check's "familiar names" finding says the tool "has
  // not verified who actually made them". When every maker was verified,
  // that sentence is wrong: show the rows (each app with its verified maker)
  // in place of the description.
  const KEYBOARD_FAMILIAR = 'security.keylogger_indicators.suspicious_input_monitoring';
  function replacesDescription(finding) {
    const f = isObj(finding) ? finding : {};
    const keyboard = f.code === KEYBOARD_FAMILIAR
      || (f.module === 'keylogger_indicators' && isObj(f.data) && f.data.check === 'claimed_vendor_input_monitoring');
    return keyboard && makersVerified(f);
  }

  // ---- the rows ----------------------------------------------------------------

  /**
   * opts.mode: 'city' | 'standard'. opts.held: true for a held monitoring
   * finding (default in city: any finding of a monitoring check). opts.checkName:
   * the check's name for people (else finding.check_name, else its id in
   * words). opts.commands: the commands that check ran (argv arrays, {argv}
   * events or strings). opts.seen: when (Date or ISO), else the finding's
   * collected_at; with neither there is no When row.
   *
   * The array also says how to show it: `held: true` (city, held: no
   * clipboard anywhere, renderEvidence draws it to write down) and
   * `replacesDescription: true` (the finding's own prose is wrong here: show
   * these rows instead of it; see replacesDescription).
   */
  function evidenceRows(finding, opts = {}) {
    const f = isObj(finding) ? finding : {};
    const o = isObj(opts) ? opts : {};
    const held = o.mode === 'city' && (typeof o.held === 'boolean' ? o.held : MONITORING_MODULES.has(f.module));
    if (held) return mark(heldRows(f, o), { held: true });

    const data = isObj(f.data) ? f.data : {};
    const adapter = ADAPTERS[f.module];
    let out = { rows: [], used: [] };
    try {
      if (adapter) out = adapter({ ...f, data }) || out;
    } catch (_) {
      out = { rows: [], used: [] };
    }
    const used = new Set(out.used || []);
    const rows = [...(out.rows || []), ...genericRows(data, used)];

    if (!out.makersDone) {
      // A maker for a path already shown is still worth its own row; skip none.
      rows.push(...makerRows(f.made_by));
    }
    const check = o.checkName || f.check_name || (f.module ? humanize(f.module) : '');
    if (check) rows.push(row('Check', check));
    const cmd = commandRow(o.commands);
    if (cmd) rows.push(cmd);
    if (f.repeats > 1) rows.push(row('Seen', `${f.repeats} times in this check`));
    const when = o.seen || f.collected_at;
    if (when) rows.push(row('When', plainDay(when)));
    return mark(rows.slice(0, MAX_ROWS), replacesDescription(f) ? { replacesDescription: true } : {});
  }

  // Flags on the rows array itself, not on any row (rows stay {label, value, mono, copy}).
  function mark(rows, flags) {
    for (const [k, v] of Object.entries(flags)) Object.defineProperty(rows, k, { value: v, enumerable: false });
    return rows;
  }

  /** The text "Copy all" puts on the clipboard: one "Label: value" line per row. */
  function evidenceText(rows) {
    // Rows from row() are already visible (their only line breaks are a
    // command list's own); the rest is made so here too, line by line.
    const text = (v) => String(v == null ? '' : v).split('\n').map(VT.visible).join('\n');
    return (Array.isArray(rows) ? rows : []).map((r) => `${VT.visible(r.label)}: ${text(r.copy != null ? r.copy : r.value)}`).join('\n');
  }

  const PAPER_LINE = 'Write this on paper or on another device.';

  /**
   * City mode: nothing from a monitoring check goes to the clipboard, held or
   * not (monitoring apps can read it). `modules`: the check's name, or the
   * names of every check that saw the finding. The one rule for the list,
   * the game and Copy for any AI.
   */
  function noClipboard(mode, modules) {
    const names = Array.isArray(modules) ? modules : [modules];
    return mode === 'city' && names.some((m) => MONITORING_MODULES.has(m));
  }

  /**
   * An escaped value with a line-break chance after each "/", "\\" and "." of
   * a path or id, so a long value wraps between its names, not mid-name
   * (the CSS's overflow-wrap:anywhere is only the last resort).
   */
  function breakable(value) {
    return esc(value).replace(/([/\\.])(?=[^\s/\\.])/g, '$1<wbr>');
  }

  /**
   * A compact key/value grid. Values in monospace only for paths, ids,
   * ports, hashes and commands, and only those get their own Copy; "Copy all"
   * copies every row. opts.copy false leaves the copy buttons out.
   *
   * Held (opts.held, or rows from evidenceRows' held branch): no clipboard at
   * all, since monitoring software can read it. The rows are drawn large,
   * with the one line PAPER_LINE.
   */
  function renderEvidence(rows, opts = {}) {
    const list = Array.isArray(rows) ? rows.filter((r) => r && r.label) : [];
    if (!list.length) return '';
    const held = opts.held === true || (Array.isArray(rows) && rows.held === true);
    const title = opts.title == null ? (held ? 'Write this down' : 'Evidence') : opts.title;
    const copy = opts.copy !== false && !held;
    const btn = (text, label, aria) => (copy
      ? `<button type="button" class="evidence-copy" data-evidence-copy="${esc(text)}" aria-label="${esc(aria)}">${esc(label)}</button>`
      : '');
    const body = list.map((r) => {
      const full = r.copy != null ? r.copy : r.value;
      const val = r.mono
        ? `<code class="evidence-mono"${full !== r.value ? ` title="${esc(full)}"` : ''}>${breakable(r.value)}</code>`
        : `<span${full !== r.value ? ` title="${esc(full)}"` : ''}>${breakable(r.value)}</span>`;
      return `<dt>${esc(r.label)}</dt><dd>${val}${r.mono ? btn(full, 'Copy', `Copy ${r.label}`) : ''}</dd>`;
    }).join('');
    return `<section class="evidence${held ? ' evidence--held' : ''}" data-evidence>`
      + `<div class="evidence-head"><span class="evidence-title">${esc(title)}</span>`
      + `${btn(evidenceText(list), opts.copyAllLabel || 'Copy all', 'Copy all of this')}</div>`
      + (held ? `<p class="evidence-paper">${esc(PAPER_LINE)}</p>` : '')
      + `<dl class="evidence-grid">${body}</dl></section>`;
  }

  /**
   * Copy buttons: one click handler on `root` (a document, element or shadow
   * root). `write(text)` puts text on the clipboard (navigator.clipboard.writeText).
   * Returns a function that removes the handler.
   */
  function wireCopy(root, write) {
    if (!root || typeof root.addEventListener !== 'function') return () => {};
    const onClick = (ev) => {
      const t = ev.target && typeof ev.target.closest === 'function' ? ev.target.closest('[data-evidence-copy]') : null;
      if (!t) return;
      const text = t.getAttribute('data-evidence-copy') || '';
      Promise.resolve().then(() => write(text)).then(() => {
        const was = t.textContent;
        t.textContent = 'Copied';
        setTimeout(() => { t.textContent = was; }, 1500);
      }).catch(() => {});
    };
    root.addEventListener('click', onClick);
    return () => root.removeEventListener('click', onClick);
  }

  // Styles for the block, for a <style> in the page or a shadow root (the CSP
  // allows inline styles). Colours inherit; set --evidence-* to theme it.
  const CSS = `
.evidence{margin:.5rem 0;padding:.5rem .75rem;border:1px solid var(--evidence-border,rgba(127,127,127,.35));border-radius:6px;container-type:inline-size}
.evidence-head{display:flex;justify-content:space-between;align-items:center;gap:.5rem;margin-bottom:.25rem}
.evidence-title{font-weight:600;font-size:.85em;letter-spacing:.04em;text-transform:uppercase}
.evidence-grid{display:grid;grid-template-columns:fit-content(11em) minmax(0,1fr);gap:.2rem .75rem;margin:0}
.evidence-grid dt{opacity:.8;overflow-wrap:break-word;min-width:0}
.evidence-grid dd{margin:0;display:flex;gap:.5rem;align-items:baseline;min-width:0}
.evidence-grid dd>code,.evidence-grid dd>span{overflow-wrap:anywhere;min-width:0}
.evidence-mono{font-family:ui-monospace,SFMono-Regular,Menlo,Consolas,monospace;font-size:.9em;background:var(--evidence-mono-bg,rgba(127,127,127,.12));padding:0 .25em;border-radius:3px}
.evidence-copy{font:inherit;font-size:.8em;padding:0 .4em;margin-left:auto;cursor:pointer;flex:none}
.evidence--held{font-size:1.2em;line-height:1.5}
.evidence--held .evidence-grid{gap:.5rem 1rem}
.evidence-paper{margin:.25rem 0 .5rem;font-weight:600}
@container (max-width:28rem){.evidence-grid{grid-template-columns:1fr;gap:0}.evidence-grid dd{margin-bottom:.35rem}}
@media (max-width:800px){.evidence-grid{grid-template-columns:1fr;gap:0}.evidence-grid dd{margin-bottom:.35rem}}
`;

  return {
    MONITORING_MODULES, ADAPTERS, CSS, PAPER_LINE,
    evidenceRows, renderEvidence, evidenceText, wireCopy, replacesDescription, noClipboard,
    plainDay, shortHash, shortPath, homeRelative, bytes, makersVerified, makerText, checkLabel, commandLine, shortCommand,
    appSubject, breakable,
  };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = Evidence;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.Evidence = Evidence;
}
