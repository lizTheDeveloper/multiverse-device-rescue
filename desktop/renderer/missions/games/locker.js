// The Evidence Locker: suspicious files (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md,
// "locker"). Each item is a file tag: where it is, its size and when it changed (when the engine recorded them), what
// matched (the indicator), and who made it. Decisions: Mine / Quarantine / Look closer.
// render() draws only the tag card; the runner draws the buttons, the removal-warning line, evidence rows and links.
//
// Not every finding in these checks is a file. The game reads each item's kind from its finding code (or, for
// code-less findings, its `data.check`) and offers the matching move:
//   file      Mine / Quarantine / Look closer      Quarantine = the engine's fix when it offers one, else steps to
//                                                  move the file aside (never delete)
//   process   Mine / Stop it / Look closer         steps for Activity Monitor or Task Manager
//   extension Mine / Turn it off / Look closer     steps for the browser's extensions page
//   setting   Mine, I know why / Look closer / Later
//   system    Look closer / Mine, I know why / Later   core parts of the computer: never moved by hand
// A critical or warning item puts Look closer first, so the default never waves through a known-bad match.
//
// Pure module (missions/contract.js): no DOM, storage, globals or network. Step and checklist texts in effects are
// PLAIN TEXT (scan values passed through ctx.visible); whoever shows them must escape them.
import { makerFor, isAlertingItem } from '../contract.js';

const MODULES = [
  'ai_worm_filesystem', 'ai_worm_git_ssh', 'ai_worm_lateral', 'ai_worm_network', 'ai_threat_indicators',
  'malware_scan_indicators', 'crypto_miner_detect', 'rootkit_check',
  'win_malware_indicators', 'win_crypto_miner_detect', 'win_rootkit_check', 'suspicious_processes', 'win_suspicious_processes',
];

// Shared modules, narrowed by finding code: win_rootkit_check's unsigned_drivers belongs to the seal game and
// its Secure Boot switch to Lock Run. (Lock Run also claims rootkit_check's SIP switch and
// win_malware_indicators' Safe Mode option by code; a code claim wins over this game's whole claim.
// ClamAV's tool status is Lock Run's whole.)
const CODES_BY_MODULE = {
  // Running programs that look wrong; its unsigned apps are the seal game's.
  suspicious_processes: ['known_malware', 'suspicious_paths', 'suspicious_names', 'high_cpu'].map((c) => `security.suspicious_processes.${c}`),
  win_rootkit_check: ['alternate_data_streams', 'hidden_services', 'boot_tampering', 'all_passed']
    .map((c) => `security.win_rootkit_check.${c}`),
  // Windows running programs that look harmful; one running from an odd folder or with no file is the seal game's.
  win_suspicious_processes: ['known_malware', 'encoded_powershell', 'mining_software'].map((c) => `security.win_suspicious_processes.${c}`),
};

const KIND_BY_CHECK = {
  // files
  obfuscated_script: 'file', known_payload_path: 'file', known_hash_match: 'file', npmrc_git_override: 'file',
  rogue_mcp_server: 'file', repo_hook_file: 'file', ssh_authorized_keys_recent: 'file', credential_harvesting: 'file',
  supply_chain_artifact: 'file', stepsecurity_bypass: 'file', launchagent_ai: 'file', ai_config_file: 'file',
  malware_launchdaemon: 'file', suspicious_bundle_id: 'file', adware_indicator: 'file', malware_folder: 'file',
  suspicious_service: 'file', malware_registry: 'file',
  // running programs
  imds_access: 'process', known_malicious_connection: 'process', beaconing_detected: 'process',
  token_harvesting_subprocess: 'process', ai_api_connection: 'process', python_node_ai_process: 'process',
  known_miner: 'process', high_cpu_process: 'process', mining_pool_connection: 'process',
  known_malware: 'process', suspicious_paths: 'process', suspicious_names: 'process', high_cpu: 'process',
  mining_software: 'process', encoded_powershell: 'process',
  // browser add-ons
  browser_extension: 'extension',
  // settings and tools
  git_hookspath_hijack: 'setting', git_templatedir_hijack: 'setting', ai_api_key_found: 'setting',
  cron_ai_call: 'setting', npm_publish_credentials: 'setting', clamav_not_installed: 'setting',
  clamav_version: 'setting', freshclam_not_installed: 'setting', clamav_definitions: 'setting',
  clamav_outdated_definitions: 'setting', clamd_not_running: 'setting', clamd_running: 'setting',
  safe_mode_disabled: 'setting', clean_scan: 'setting', clean_system: 'setting', all_clean: 'setting', all_passed: 'setting',
  // the computer's own core parts
  sip_disabled: 'system', binary_integrity: 'system', kernel_extensions: 'system', hidden_processes: 'system',
  hidden_files: 'system', unsigned_drivers: 'system', alternate_data_streams: 'system',
  secure_boot_disabled: 'system', hidden_services: 'system', boot_tampering: 'system',
};

const MINER_CHECKS = new Set(['known_miner', 'high_cpu_process', 'mining_pool_connection', 'mining_software']);

// What matched, in a few words, by check. [standard, city]
const WHY = {
  known_hash_match: ['An exact copy of a known harmful file', 'Fingerprint matches a known bad file'],
  known_payload_path: ['Sits where a known harmful program leaves files', 'Found at a known drop spot'],
  obfuscated_script: ['Code that hides what it does, or downloads and runs more code', 'Scrambled or fetch-and-run code'],
  npmrc_git_override: ['npm is told to use a different git tool', 'A tool swapped for a look-alike'],
  rogue_mcp_server: ['An AI tool setting points to a known bad server', 'Points at a known bad hideout'],
  repo_hook_file: ['A file in a project that runs on its own', 'A tripwire file in a project'],
  ssh_authorized_keys_recent: ['The list of keys that can log in remotely changed', 'The spare-key list changed'],
  credential_harvesting: ['Looks like a store of collected passwords', 'Looks like a stash of keys'],
  supply_chain_artifact: ['Looks like harmful code inside a package', 'A bad part hidden in a package'],
  stepsecurity_bypass: ['The hosts file switches off a security service', 'The address book silences a guard'],
  launchagent_ai: ['A background item that talks to an AI service', 'A night-shift item calling an AI service'],
  ai_config_file: ['A settings file for an AI tool', 'A settings file for an AI tool'],
  malware_launchdaemon: ['A background task known to be harmful', 'A known bad night-shift task'],
  suspicious_bundle_id: ['An app ID that unwanted software often uses', 'An ID badge used by known pests'],
  adware_indicator: ['A folder that unwanted software leaves', 'A pest nest'],
  malware_folder: ['A folder unwanted software uses', 'A pest nest'],
  suspicious_service: ['A service running from a hidden folder', 'A night-shift worker in a hidden room'],
  malware_registry: ['A startup entry nobody expects', 'An odd name on the start-up roster'],
  imds_access: ["Asked for this machine's cloud keys", 'Asked for the cloud keys'],
  known_malicious_connection: ['Talking to a known harmful address', 'Calling a known bad hideout'],
  beaconing_detected: ['Keeps checking in with an unknown server', 'Keeps phoning an unknown base'],
  token_harvesting_subprocess: ['Read your saved GitHub sign-in', 'Read your saved sign-in'],
  ai_api_connection: ['Connecting to an AI service', 'Calling an AI service'],
  python_node_ai_process: ['A running program that uses AI', 'A running program that uses AI'],
  known_miner: ['Matches a known crypto miner', 'Matches a known miner'],
  high_cpu_process: ['Using a lot of power', 'Running the generators hot'],
  mining_pool_connection: ['Connecting to a crypto mining server', 'Calling a mining base'],
  browser_extension: ['An add-on known as unwanted software', 'A gadget known as a pest'],
  mining_software: ['Matches crypto mining software', 'Matches a known miner'],
  encoded_powershell: ['PowerShell running a hidden, scrambled command', 'A scrambled order running in the shell'],
};
const WHY_DEFAULT = ['Matched a warning sign the checkup looks for', 'Matched a known sign'];

// The data field that holds the matched value, first present wins.
const MATCH_FIELDS = ['pattern', 'match_value', 'server_name', 'endpoint', 'key_name', 'cron_entry', 'line', 'command',
  'indicator', 'bundle_id', 'matched', 'entry_value', 'extension_name', 'dest', 'address', 'remote', 'value'];
const PATH_FIELDS = ['path', 'config_path', 'plist_path', 'binary_path', 'binary'];
const LIST_FIELDS = ['files', 'drivers', 'services', 'issues', 'paths', 'processes'];
const MAX_TEXT = 160;
const MAX_LIST = 6;

const pick = (ctx, pair) => (ctx && ctx.mode === 'city' ? pair[1] : pair[0]);
const str = (v) => (v == null ? '' : String(v));
const clip = (s, n = MAX_TEXT) => (s.length > n ? `${s.slice(0, n - 1)}…` : s);
const isWin = (ctx, f) => (ctx && ctx.platform === 'win32') || /^win_/.test(str(f && f.module));

function checkOf(f) {
  const code = str(f && f.code);
  if (code) return code.split('.').pop();
  return str(f && f.data && f.data.check);
}

export function kindOf(item) {
  const f = (item && item.finding) || {};
  const d = f.data || {};
  const k = KIND_BY_CHECK[checkOf(f)];
  if (k) return k;
  if (d.process || d.pid) return 'process';
  if (pathOf(f)) return 'file';
  if (LIST_FIELDS.some((x) => Array.isArray(d[x]))) return 'system';
  return 'setting';
}

// ---- paths ----------------------------------------------------------------

const winPath = (p) => /^[A-Za-z]:\\/.test(p) || (p.includes('\\') && !p.includes('/'));
const sepOf = (p) => (winPath(p) ? '\\' : '/');

export function pathOf(f) {
  const d = (f && f.data) || {};
  for (const k of PATH_FIELDS) {
    if (typeof d[k] === 'string' && d[k]) return k === 'binary_path' ? exePath(d[k]) : d[k];
  }
  if (typeof d.location === 'string' && d.location) {
    return d.name ? `${d.location.replace(/[\\/]+$/, '')}${sepOf(d.location)}${d.name}` : d.location;
  }
  if (checkOf(f).endsWith('hijack') && typeof d.value === 'string') return d.value;
  return '';
}

// A command line's program path, the way Windows reads a service ImagePath: the quoted first token, or the first
// token ending .exe. Anything else is returned as given (and must still pass safeFolder before it is pasted).
export function exePath(cmd) {
  const t = str(cmd).trim();
  if (t.startsWith('"')) {
    const end = t.indexOf('"', 1);
    return end > 1 ? t.slice(1, end) : '';
  }
  const m = t.match(/^(.+?\.exe)(?=\s|$)/i);
  return m ? m[1] : t;
}

// Only a plain absolute folder path is ever offered to paste into an address bar or Go to Folder. Scan data a
// harmful program controls must not become something that runs: no shell or cmd metacharacters, quotes, variables,
// control characters, arguments or program names.
const CLEAN_WIN_DIR = /^[A-Za-z]:\\[^<>"|?*\r\n%&^;]*$/;
const CLEAN_POSIX_DIR = /^(~|\/)[^\r\n$`"'\\;|&<>(){}*?!\[\]#]*$/;
export function safeFolder(dir, win) {
  const d = str(dir);
  if (!d || d.length > 400 || /[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/u.test(d)) return '';
  if (/\s[-/]\S/.test(d) || /\.(exe|com|bat|cmd|ps1|vbs|js|sh|scr|lnk|msi)$/i.test(d)) return '';
  if (win) return CLEAN_WIN_DIR.test(d) ? d : '';
  return CLEAN_POSIX_DIR.test(d) && !d.split('/').includes('..') ? d : '';
}

function dirOf(p) {
  const s = sepOf(p);
  const t = p.replace(/[\\/]+$/, '');
  const i = t.lastIndexOf(s);
  return i > 0 ? t.slice(0, i) : t;
}

function baseOf(p) {
  const t = p.replace(/[\\/]+$/, '');
  return t.slice(t.lastIndexOf(sepOf(t)) + 1) || t;
}

// /Users/<name>/… reads as ~/… (Windows paths are left as Windows shows them).
const shortHome = (p) => p.replace(/^\/(?:Users|home)\/[^/]+(?=\/|$)/, '~');

const HIDDEN_SEG = (p) => p.split(/[\\/]/).some((seg) => seg.length > 1 && seg.startsWith('.') && seg !== '..');
const TEMP_RE = /(^|[\\/])(tmp|temp)([\\/]|$)|[\\/]var[\\/]folders[\\/]/i;
const CACHE_RE = /[\\/](Caches?|\.cache|Code Cache|Cache_Data)([\\/]|$)/i;
const ADMIN_RE = /^\/(Library|System|usr|bin|sbin|private\/etc|etc|Applications)\//;

export function placeFlags(p) {
  const s = str(p);
  return {
    hidden: HIDDEN_SEG(s) || /[\\/]AppData([\\/]|$)/i.test(s),
    temp: TEMP_RE.test(s),
    cache: CACHE_RE.test(s),
  };
}

// ---- the tag ----------------------------------------------------------------

function entryText(e) {
  if (e == null) return '';
  if (typeof e !== 'object') return str(e);
  return str(e.name || e.path || e.display_name || e.service || e.driver || e.file || '');
}

function fmtBytes(n) {
  const v = Number(n);
  if (!Number.isFinite(v) || v < 0) return '';
  const u = ['bytes', 'KB', 'MB', 'GB', 'TB'];
  let i = 0; let x = v;
  while (x >= 1000 && i < u.length - 1) { x /= 1000; i += 1; }
  return i === 0 ? `${Math.round(x)} bytes` : `${x.toFixed(x < 10 ? 1 : 0)} ${u[i]}`;
}

// The maker of the file the item is about; another file's entry shows its
// claimed name only, never as verified (contract.js makerFor).
function makerOf(f, path, v) {
  const list = Array.isArray(f.made_by) ? f.made_by.filter((m) => m && typeof m === 'object') : [];
  const own = path ? makerFor(f, path) : makerFor(f);
  const first = list.find((x) => typeof x.name === 'string' && x.name);
  const m = own || (first ? { name: first.name, verified: false, what: '' } : null);
  if (!m || !m.name) return null;
  // Scan data like every other field: control and bidi characters made visible, length capped.
  return { name: v(clip(str(m.name), 120)), verified: m.verified === true, what: m.verified === true ? v(clip(str(m.what), 300)) : '' };
}

// Everything the tag shows, as plain (unescaped) text. The render escapes it.
export function tagOf(item, ctx) {
  const f = (item && item.finding) || {};
  const d = f.data || {};
  const kind = kindOf(item);
  const check = checkOf(f);
  const path = pathOf(f);
  const v = (ctx && ctx.visible) || ((s) => s);
  const matchField = MATCH_FIELDS.find((k) => d[k] != null && d[k] !== '' && typeof d[k] !== 'object');
  const list = LIST_FIELDS.map((k) => d[k]).find(Array.isArray) || [];
  const entries = list.map(entryText).filter(Boolean);
  const size = d.size_bytes != null ? fmtBytes(d.size_bytes) : (d.size != null ? fmtBytes(d.size) : '');
  const days = Number.isFinite(Number(d.modified_days_ago)) && d.modified_days_ago !== null && d.modified_days_ago !== '' ? Number(d.modified_days_ago) : null;
  let where = path;
  if (!where && d.registry_path) where = `${d.registry_path}${d.entry_name ? `\\${d.entry_name}` : ''}`;
  if (!where && d.folder_name) where = str(d.folder_name);
  return {
    kind,
    check,
    title: v(clip(str(f.title))),
    path: v(clip(shortHome(str(where)), 400)),
    rawPath: str(path),
    name: v(clip(str(path ? baseOf(path) : (d.process || d.extension_name || d.display_name || d.entry_name || d.key_name || '')), 120)),
    process: v(clip(str(d.process || ''), 120)),
    pid: Number.isInteger(d.pid) && d.pid > 0 ? d.pid : null,
    browser: v(str(d.browser || '')),
    flags: placeFlags(path),
    size,
    days,
    cpu: Number.isFinite(Number(d.cpu_percent)) && d.cpu_percent != null ? Math.round(Number(d.cpu_percent)) : null,
    why: pick(ctx, WHY[check] || WHY_DEFAULT),
    matched: matchField ? v(clip(str(d[matchField]))) : '',
    threat: d.threat ? v(clip(str(d.threat), 80)) : '',
    entries: entries.slice(0, MAX_LIST).map((e) => v(clip(e, 120))),
    moreEntries: Math.max(0, entries.length - MAX_LIST),
    count: Number.isFinite(Number(d.count)) && d.count != null ? Number(d.count) : null,
    maker: makerOf(f, path, v),
    miner: MINER_CHECKS.has(check) || /miner/.test(str(f.module)),
    worm: /^ai_worm_/.test(str(f.module)),
    win: isWin(ctx, f),
    markable: !!(f.markable && typeof f.markable === 'object'),
    fixable: hasEngineFix(f),
    alerting: isAlertingItem(item),
    unfinished: !!((item && item.unfinished) || d.incomplete),
    stale: d.mark_stale === true,
  };
}

// Items that look the same (one package pattern copied into ten folders): same check, same match, same folder shape.
export function groupKey(item) {
  const f = (item && item.finding) || {};
  const d = f.data || {};
  const path = pathOf(f);
  const shape = path ? dirOf(path).split(/[\\/]/).slice(0, 5).join('/') : '';
  const matchField = MATCH_FIELDS.find((k) => d[k] != null && typeof d[k] !== 'object');
  return [str(f.module), checkOf(f), matchField ? str(d[matchField]) : '', d.threat ? str(d.threat) : '', shape].join('|');
}

// ---- effects ----------------------------------------------------------------

function hasEngineFix(f) {
  const x = f && f.fixable;
  return !!x && typeof x === 'object' && typeof x.will_change === 'string' && x.will_change.trim() !== ''
    && Array.isArray(x.how_to_undo) && x.how_to_undo.length > 0;
}

const AGAIN = ['Run the checkup again to see that it is gone from your list.', 'Run the sweep again to see that it is gone from the board.'];
const NO_RUN = ["Don't open it or run it.", "Don't open it or run it."];
const READ_NOTE = ['Read the note above before you move anything.', 'Read the note above before you move anything.'];

export function moveAsideSteps(item, ctx) {
  const t = tagOf(item, ctx);
  const folder = pick(ctx, ['Quarantine', 'Set aside']);
  const dir = t.rawPath ? safeFolder(dirOf(t.win ? t.rawPath : shortHome(t.rawPath)), t.win) : '';
  const name = t.name || pick(ctx, ['the file', 'the file']);
  const s = [pick(ctx, NO_RUN)];
  if (t.alerting) s.push(pick(ctx, READ_NOTE));
  if (t.win) {
    if (dir) s.push(`Open File Explorer, click the address bar, paste ${dir} and press Enter.`);
    else s.push('To find its folder, open Task Manager (Ctrl+Shift+Esc) > Details, right-click the program and choose Open file location. If it is not running, use the Where line on the tag.');
    if (t.flags.hidden) s.push("If you can't see it, turn on Hidden items in File Explorer's View menu.");
    s.push(`Make a folder named ${folder} in your user folder and drag ${name} into it. Nothing is deleted, and you can drag it back.`);
    s.push('If Windows says the file is in use, end the program in Task Manager (Ctrl+Shift+Esc) first, then try again.');
  } else if (ctx && ctx.platform === 'linux') {
    if (dir) s.push(`Open your file manager and go to ${dir}.`);
    else s.push('Open your file manager and find the folder on the Where line of the tag.');
    s.push(`Make a folder named ${folder} in your home folder and move ${name} into it. Nothing is deleted, and you can move it back.`);
  } else {
    if (dir) s.push(`In Finder, press Command-Shift-G and paste ${dir}`);
    else s.push('In Finder, find the folder on the Where line of the tag.');
    if (t.flags.hidden) s.push("If you can't see it, press Command-Shift-. (period) to show hidden files.");
    s.push(`Make a folder named ${folder} in your home folder and drag ${name} into it. Nothing is deleted, and you can drag it back.`);
    if (ADMIN_RE.test(t.rawPath)) s.push('Your Mac may ask for your Mac password to move it. That is your Mac asking, not this app.');
  }
  s.push(pick(ctx, AGAIN));
  return s;
}

export function stopSteps(item, ctx) {
  const t = tagOf(item, ctx);
  const who = `${t.process || t.name || pick(ctx, ['the program', 'the program'])}${t.pid ? ` (ID ${t.pid})` : ''}`;
  const s = [];
  if (t.alerting) s.push(pick(ctx, READ_NOTE));
  if (t.win) {
    s.push('Open Task Manager (Ctrl+Shift+Esc) and choose Details.');
    s.push(`Find ${who}, right-click it and choose Open file location, so you know where it lives.`);
    s.push('Right-click it again and choose End task.');
    s.push(pick(ctx, ['If it comes back, look for it in Settings > Apps > Startup.', 'If it comes back, check The Door too: Settings > Apps > Startup.']));
  } else {
    s.push('Open Activity Monitor (in Applications > Utilities).');
    s.push(`Find ${who}. Double-click it and look under Open Files and Ports to see where it lives.`);
    s.push('Close that window, select it, click the Stop button (the X at the top) and choose Quit.');
    s.push(pick(ctx, ['If it comes back, it starts on its own: look for it under Things that start on their own.', 'If it comes back, it starts on its own: look for it at The Door.']));
  }
  s.push(pick(ctx, AGAIN));
  return s;
}

export function turnOffSteps(item, ctx) {
  const t = tagOf(item, ctx);
  const name = t.name || 'the add-on';
  const b = t.browser.toLowerCase();
  const s = [];
  if (t.alerting) s.push(pick(ctx, READ_NOTE));
  if (b.includes('safari')) s.push(`Open Safari, choose Safari > Settings > Extensions, and untick ${name}.`);
  else if (b.includes('chrome')) s.push(`Open Chrome, type chrome://extensions in the address bar, find ${name} and switch it off.`);
  else s.push(`Open your browser's extensions page, find ${name} and switch it off.`);
  s.push('Switching it off keeps it, so you can switch it back on.');
  s.push(pick(ctx, AGAIN));
  return s;
}

export function checklistFor(item, ctx) {
  const t = tagOf(item, ctx);
  const lookUp = pick(ctx, ['Look up the name with the search link.', 'Look up the name on another device.']);
  const c = [];
  if (t.kind === 'file') {
    c.push(pick(ctx, ['Do you know this folder? Is it one of your projects, or an app you use?', 'Do you know this spot? Is it one of your projects, or an app you use?']));
    if (t.flags.cache) c.push(pick(ctx, ["It's in an app's cache, a folder apps fill on their own. Which app owns the folder?", "It's in an app's cache, a folder apps fill on their own. Which app owns the folder?"]));
    c.push(t.flags.hidden || t.flags.temp
      ? pick(ctx, ['Who made it? A file with no maker in a hidden or temporary folder is a bad sign.', "Who made it? No maker's mark in a hidden or temporary spot is a bad sign."])
      : pick(ctx, ['Who made it? An unknown maker is worth checking.', "Who made it? No maker's mark is worth checking."]));
    if (t.worm) c.push(pick(ctx, ['Did you install a package (npm, pip) in this folder? Some worms arrive inside packages.', 'Did you install a package (npm, pip) in this folder? Some bad code arrives inside packages.']));
    c.push(lookUp);
    c.push(pick(ctx, NO_RUN));
  } else if (t.kind === 'process') {
    c.push(pick(ctx, ['Do you know this program? Did you start it?', 'Do you know this program? Did you start it?']));
    if (t.miner) c.push(pick(ctx, ['Is your computer hot, loud or slow?', 'Is your computer hot, loud or slow?']));
    c.push(t.win
      ? 'Where does its file live? Task Manager > Details > Open file location shows it.'
      : 'Where does its file live? Activity Monitor shows it under Open Files and Ports.');
    c.push(lookUp);
  } else if (t.kind === 'extension') {
    c.push(pick(ctx, ['Did you add this add-on yourself?', 'Did you add this gadget yourself?']));
    c.push(pick(ctx, ['Do you use it?', 'Do you use it?']));
    c.push(lookUp);
  } else if (t.kind === 'system') {
    c.push(pick(ctx, ["This is about your computer's own core parts. Changing them by hand can do harm.", "This is about the city's foundations. Changing them by hand can do harm."]));
    c.push(pick(ctx, ['Did you change this on purpose, for example for a developer tool?', 'Did you change this on purpose, for example for a developer tool?']));
    c.push(pick(ctx, ["If you didn't, ask someone you trust who knows computers to help.", "If you didn't, ask someone you trust who knows computers to help."]));
    c.push(lookUp);
  } else {
    c.push(pick(ctx, ['Did you, or someone helping you, set this up on purpose?', 'Did you, or someone helping you, set this up on purpose?']));
    c.push(lookUp);
  }
  return c;
}

const LABEL = {
  mine: { standard: 'Mine', city: 'Mine' },
  know: { standard: 'Mine, I know why', city: 'Mine, I know why' },
  quarantine: { standard: 'Quarantine', city: 'Bag it' },
  stop: { standard: 'Stop it', city: 'Shut it down' },
  off: { standard: 'Turn it off', city: 'Switch it off' },
  closer: { standard: 'Look closer', city: 'Look closer' },
  later: { standard: 'Later', city: 'Later' },
};

function mineEffect(f) {
  if (f.markable && typeof f.markable === 'object') return { kind: 'mark', id: str(f.markable.id) || null };
  return { kind: 'keep', as: 'mine' };
}

function quarantineEffect(item, t, ctx) {
  const f = item.finding;
  if (t.fixable) return { kind: 'fix', module: str(f.module), action: f.fixable.action ? str(f.fixable.action) : null };
  if (t.check === 'malware_registry' && t.win) {
    return { kind: 'settings', pane: 'startup-apps', steps: [pick(ctx, NO_RUN), `In Settings > Apps > Startup, switch off ${t.name || 'the entry'}.`, pick(ctx, AGAIN)] };
  }
  return { kind: 'closer', focus: 'move-aside', steps: moveAsideSteps(item, ctx) };
}

export function decisions(item, ctx) {
  const f = (item && item.finding) || {};
  const t = tagOf(item, ctx);
  // The first decision is the default: "Mine" leads only on a note (info), never on a critical or warning item.
  const sev = (item && item.severity) || f.severity;
  const wary = sev === 'critical' || sev === 'warning' || !!t.alerting;
  const closer = { id: 'closer', label: LABEL.closer, effect: { kind: 'closer', focus: 'check', checklist: checklistFor(item, ctx) },
    hint: pick(ctx, ['See the evidence and what to check. It stays on your list until you decide.', 'See the evidence and what to check. It stays on the board until you decide.']) };
  const later = { id: 'later', label: LABEL.later, effect: { kind: 'later' } };
  if (t.kind === 'system') {
    return [closer, { id: 'mine', label: LABEL.know, effect: mineEffect(f), hint: pick(ctx, ['You changed this on purpose.', 'You changed this on purpose.']) }, later];
  }
  if (t.kind === 'setting') {
    const mine = { id: 'mine', label: LABEL.know, effect: mineEffect(f), hint: pick(ctx, ['You set this up on purpose.', 'You set this up on purpose.']) };
    return wary ? [closer, mine, later] : [mine, closer, later];
  }
  const mine = { id: 'mine', label: LABEL.mine, effect: mineEffect(f),
    hint: pick(ctx, ['You know it and want it.', 'You know it and want it.']) };
  let act;
  if (t.kind === 'process') {
    act = { id: 'stop', label: LABEL.stop, effect: { kind: 'closer', focus: 'stop', steps: stopSteps(item, ctx) },
      hint: pick(ctx, ['Steps to stop it and find where it lives.', 'Steps to shut it down and find where it lives.']) };
  } else if (t.kind === 'extension') {
    act = { id: 'turn-off', label: LABEL.off, effect: { kind: 'closer', focus: 'turn-off', steps: turnOffSteps(item, ctx) },
      hint: pick(ctx, ['Switch it off in the browser. It stays, so you can switch it back on.', 'Switch it off. It stays, so you can switch it back on.']) };
  } else {
    act = { id: 'quarantine', label: LABEL.quarantine, effect: quarantineEffect(item, t, ctx),
      hint: pick(ctx, ['Moves it to a Quarantine folder. Nothing is deleted.', 'Moves it to a Set aside folder. Nothing is deleted.']) };
  }
  // R6: the runner shows the removal warning before carrying out an acting effect on an alerting item.
  if (t.alerting) act.effect = { ...act.effect, warning: true };
  return wary ? [closer, act, mine] : [mine, act, closer];
}

// ---- research ---------------------------------------------------------------

function lessonConcept(t) {
  if (t.miner) return 'wifi-and-mining';
  if (t.worm) return 'poisoned-packages';
  if (t.kind === 'process' || t.kind === 'extension') return 'who-made-it';
  return 'where-it-lives';
}

export function research(item, ctx) {
  const f = (item && item.finding) || {};
  const t = tagOf(item, ctx);
  let rows = [];
  try { rows = (ctx && typeof ctx.evidenceRows === 'function' && ctx.evidenceRows(f, { mode: ctx.mode })) || []; } catch (_) { rows = []; }
  const what = t.maker && t.maker.verified && t.maker.what ? t.maker.what : pick(ctx, ['Unknown maker', "No maker's mark on file"]);
  const links = [{ kind: 'lesson', concept: lessonConcept(t) }];
  const q = t.threat || t.process || t.name;
  if (q) links.push({ kind: 'lookup', source: 'web', query: `"${q}"` });
  if (t.maker && t.maker.verified) links.push({ kind: 'lookup', source: 'maker-site', query: t.maker.name });
  if (t.check === 'launchagent_ai' || t.check === 'malware_launchdaemon') links.push({ kind: 'settings', pane: 'login-items' });
  if (t.kind === 'extension') links.push({ kind: 'settings', pane: 'extensions-browser' });
  if (t.win && t.check === 'malware_registry') links.push({ kind: 'settings', pane: 'startup-apps' });
  else if (t.win && (t.kind === 'system' || t.kind === 'file' || t.kind === 'process')) links.push({ kind: 'settings', pane: 'windows-security' });
  return { rows: Array.isArray(rows) ? rows : [], what, links, tag: t };
}

// ---- render -----------------------------------------------------------------

const KIND_WORD = {
  file: ['File', 'Exhibit'], process: ['Running program', 'Running program'], extension: ['Browser add-on', 'Gadget'],
  setting: ['Setting', 'Setting'], system: ['Core part', 'Foundations'],
};

function field(cls, label, valueHtml) {
  return `<div class="lk-f lk-f-${cls}"><dt>${label}</dt><dd>${valueHtml}</dd></div>`;
}

const breakable = (html) => html.replace(/([/\\])/g, '$1<wbr>');

export function render(view, ctx) {
  const esc = ctx.esc;
  const item = view.item;
  const r = view.research && view.research.tag ? view.research : research(item, ctx);
  const t = r.tag;
  const city = ctx.mode === 'city';
  const P = (pair) => esc(pick(ctx, pair));
  const total = Number(view.total) || 1;
  const n = (Number(view.index) || 0) + 1;
  const out = [];
  out.push(`<article class="lk-tag lk-kind-${esc(t.kind)} lk-sev-${esc(item.severity === 'critical' ? 'critical' : item.severity === 'info' ? 'info' : 'warning')}">`);
  out.push('<span class="lk-hole" aria-hidden="true"></span>');
  out.push(`<header class="lk-head"><span class="lk-no">${P(KIND_WORD[t.kind] || KIND_WORD.file)} ${n} ${P(['of', 'of'])} ${total}</span><h3 class="lk-title">${esc(t.title)}</h3></header>`);
  if (view.practice && view.step && view.step.say) {
    out.push(`<p class="lk-coach">${esc(city ? view.step.say.city : view.step.say.standard)}</p>`);
  }
  out.push('<dl class="lk-fields">');
  if (t.path) {
    const flags = [];
    if (t.flags.hidden) flags.push(`<span class="lk-flag lk-flag-hidden">${P(['hidden folder', 'hidden spot'])}</span>`);
    if (t.flags.temp) flags.push(`<span class="lk-flag lk-flag-temp">${P(['temporary folder', 'temporary spot'])}</span>`);
    if (t.flags.cache) flags.push(`<span class="lk-flag lk-flag-cache">${P(["an app's cache", "an app's cache"])}</span>`);
    out.push(field('path', P(t.kind === 'process' ? ['Runs from', 'Runs from'] : ['Where', 'Where']), `<code class="lk-path">${breakable(esc(t.path))}</code>${flags.join('')}`));
  }
  if (t.process) out.push(field('process', P(['Program', 'Program']), `<code>${esc(t.process)}</code>${t.pid ? ` <span class="lk-dim">${P(['ID', 'ID'])} ${esc(t.pid)}</span>` : ''}`));
  if (t.entries.length) {
    const more = t.moreEntries ? `<li class="lk-dim">${P(['and', 'and'])} ${esc(t.moreEntries)} ${P(['more', 'more'])}</li>` : '';
    out.push(field('list', P(['Names', 'Names']), `<ul class="lk-list">${t.entries.map((e) => `<li><code>${breakable(esc(e))}</code></li>`).join('')}${more}</ul>`));
  }
  if (t.size) out.push(field('size', P(['Size', 'Size']), esc(t.size)));
  if (t.days != null) {
    out.push(field('when', P(['Changed', 'Last touched']), `${esc(t.days)} ${esc(t.days === 1 ? 'day' : 'days')} ${P(['before this checkup', 'before this sweep'])}`));
  }
  if (t.cpu != null) out.push(field('cpu', P(['Power use', 'Power draw']), `${esc(t.cpu)}% ${P(['of the processor', 'of the generators'])}`));
  const matched = t.matched ? `<code class="lk-match">${breakable(esc(t.matched))}</code>` : '';
  out.push(field('matched', P(['What matched', 'What matched']), `<span class="lk-why">${esc(t.why)}</span>${matched}`));
  if (t.threat) out.push(field('threat', P(['Known as', 'Known as']), esc(t.threat)));
  const maker = t.maker
    ? `${esc(t.maker.name)} <span class="lk-seal lk-seal-${t.maker.verified ? 'ok' : 'no'}">${P(t.maker.verified ? ['verified', 'seal checked'] : ['not verified', 'seal not checked'])}</span>`
    : `<span class="lk-seal lk-seal-no">${P(['Unknown maker', "No maker's mark"])}</span>`;
  out.push(field('maker', P(['Made by', 'Made by']), maker));
  out.push('</dl>');
  if (t.maker && t.maker.verified && t.maker.what) out.push(`<p class="lk-what">${esc(t.maker.what)}</p>`);
  if (t.stale) out.push(`<p class="lk-note">${P(['You marked this as yours before, but it has changed since.', 'You tagged this as yours before, but it has changed since.'])}</p>`);
  if (t.unfinished) out.push(`<p class="lk-note lk-unfinished">${P(["This check didn't finish, so there may be more than this.", "This sweep didn't finish, so there may be more than this."])}</p>`);
  const sibs = Array.isArray(view.siblings) ? view.siblings : [];
  if (sibs.length > 1) {
    const g = groupKey(item);
    const same = sibs.filter((s) => s !== item && s && s.key !== item.key && groupKey(s) === g).length;
    if (same > 0) {
      out.push(`<p class="lk-same">${esc(same)} ${P(same === 1 ? ['more in this set looks the same.', 'more in this set looks the same.'] : ['more in this set look the same.', 'more in this set look the same.'])} ${P(['Decide each one on its own.', 'Tag each one on its own.'])}</p>`);
    }
  }
  const prior = (Array.isArray(view.results) ? view.results : []).filter((x) => x && x.item && groupKey(x.item) === groupKey(item) && x.item !== item);
  if (prior.length) {
    const last = prior[prior.length - 1];
    const id = decisionId(last);
    const lab = labelFor(id, ctx);
    if (lab) out.push(`<p class="lk-same">${P(['For the last one like this, you chose', 'For the last one like this, you chose'])} <strong>${esc(lab)}</strong>.</p>`);
  }
  out.push('</article>');
  return out.join('');
}

// ---- summary ----------------------------------------------------------------

function decisionId(r) {
  if (!r) return '';
  const d = r.decision != null ? r.decision : (r.choice != null ? r.choice : r.id);
  return typeof d === 'string' ? d : (d && typeof d.id === 'string' ? d.id : '');
}

function labelFor(id, ctx) {
  const map = { mine: LABEL.mine, quarantine: LABEL.quarantine, stop: LABEL.stop, 'turn-off': LABEL.off, closer: LABEL.closer, later: LABEL.later };
  const l = map[id];
  return l ? (ctx.mode === 'city' ? l.city : l.standard) : '';
}

export function summary(results, ctx) {
  const esc = ctx.esc;
  const P = (pair) => esc(pick(ctx, pair));
  const rs = (Array.isArray(results) ? results : []).filter((r) => r && r.item);
  if (!rs.length) return `<div class="lk-summary"><p>${P(['No files tagged in this set yet.', 'No exhibits tagged in this set yet.'])}</p></div>`;
  const count = { mine: 0, aside: 0, closer: 0, later: 0 };
  for (const r of rs) {
    const id = decisionId(r);
    if (id === 'mine') count.mine += 1;
    else if (id === 'quarantine' || id === 'stop' || id === 'turn-off') count.aside += 1;
    else if (id === 'closer') count.closer += 1;
    else count.later += 1;
  }
  const lines = [];
  if (count.mine) lines.push([['Yours', 'Tagged yours'], count.mine]);
  if (count.aside) lines.push([['Set aside or stopped', 'Bagged or shut down'], count.aside]);
  if (count.closer) lines.push([['To look closer at', 'Under the lamp'], count.closer]);
  if (count.later) lines.push([['Later', 'Later'], count.later]);
  const out = [`<div class="lk-summary"><h3>${P(['Files tagged', 'Locker tagged'])}: ${esc(rs.length)}</h3><ul class="lk-counts">`];
  for (const [pair, n] of lines) out.push(`<li><span>${P(pair)}</span> <strong>${esc(n)}</strong></li>`);
  out.push('</ul>');
  const groups = new Map();
  for (const r of rs) {
    const g = groupKey(r.item);
    groups.set(g, (groups.get(g) || 0) + 1);
  }
  const repeats = [...groups.values()].filter((x) => x > 1);
  if (repeats.length) {
    const biggest = Math.max(...repeats);
    out.push(`<p class="lk-dim">${esc(biggest)} ${P(['of these matched the same sign. You decided each one on its own.', 'of these matched the same sign. You tagged each one on its own.'])}</p>`);
  }
  if (count.aside) out.push(`<p>${P(['Nothing was deleted. Files you moved stay in your Quarantine folder.', 'Nothing was deleted. Exhibits you bagged stay in your Set aside folder.'])}</p>`);
  if (count.closer || count.later) out.push(`<p>${P(['Anything you are still looking at stays on your list.', 'Anything still under the lamp stays on the board.'])}</p>`);
  out.push('</div>');
  return out.join('');
}

// ---- practice ---------------------------------------------------------------

function practiceItem(key, finding) {
  const f = { category: 'security', ...finding };
  return { key, severity: f.severity, finding: f, findings: [f], seen_in: [f.module], marked: false, held: false, removal_alert: false, practice: true };
}

const PRACTICE_ITEMS = [
  practiceItem('practice:locker:own-script', {
    module: 'ai_worm_filesystem', severity: 'warning', code: 'security.ai_worm_filesystem.obfuscated_script',
    title: 'Script downloads and runs code: setup.sh',
    description: 'A script downloads code and runs it.',
    data: { check: 'obfuscated_script', kind: 'pipe_to_shell', path: '~/Projects/my-site/scripts/setup.sh', pattern: 'curl -fsSL https://example.com/install | sh' },
  }),
  practiceItem('practice:locker:temp-dropper', {
    module: 'ai_worm_filesystem', severity: 'warning', code: 'security.ai_worm_filesystem.obfuscated_script',
    title: 'Hard-to-read script found: run.js',
    description: 'A script uses scrambled code that hides what it does.',
    data: { check: 'obfuscated_script', kind: 'atob_eval', path: '/private/var/tmp/.x9/run.js', pattern: 'eval(atob(' },
  }),
  practiceItem('practice:locker:cache-file', {
    module: 'ai_worm_filesystem', severity: 'warning', code: 'security.ai_worm_filesystem.obfuscated_script',
    title: 'Hard-to-read script found: 7f3a.js',
    description: 'A script uses scrambled code that hides what it does.',
    data: { check: 'obfuscated_script', kind: 'atob_eval', path: '~/Library/Caches/com.example.browser/Code Cache/js/7f3a.js', pattern: 'eval(atob(' },
  }),
];

const PRACTICE_SCRIPT = [
  { item: 0, expect: 'mine', concept: 'where-it-lives', say: {
    standard: "This script is in your own project folder. It matched \"downloads and runs code\", which installers do. If you wrote it or added it, it's yours: choose Mine.",
    city: "This exhibit is in your own project folder. It matched \"fetch-and-run code\", which installers do. If you wrote it or added it, it's yours: choose Mine.",
  } },
  { item: 1, expect: 'quarantine', concept: 'where-it-lives', say: {
    standard: 'A hidden folder inside a temporary folder, no maker, and code that hides what it does. Nobody installs things there. Quarantine moves it aside; nothing is deleted.',
    city: 'A hidden spot inside a temporary folder, no maker\'s mark, and scrambled code. Nobody keeps things there. Bag it: it moves aside, nothing is deleted.',
  } },
  { item: 2, expect: 'closer', concept: 'who-made-it', say: {
    standard: "Same match, but this one is in an app's cache, a folder apps fill on their own. It is usually the app's own code. Look closer before you decide.",
    city: "Same match, but this one is in an app's cache, a folder apps fill on their own. It is usually the app's own code. Look closer before you tag it.",
  } },
];

export default {
  type: 'locker',
  title: { standard: 'Suspicious files', city: 'The Evidence Locker' },
  concepts: ['where-it-lives', 'who-made-it', 'poisoned-packages', 'wifi-and-mining'],
  covers: MODULES.map((module) => (CODES_BY_MODULE[module] ? { module, codes: CODES_BY_MODULE[module] } : { module })),
  decisions,
  research,
  practice: { items: PRACTICE_ITEMS, script: PRACTICE_SCRIPT },
  render,
  summary,
  groupKey,
};
