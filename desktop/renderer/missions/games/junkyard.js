// The Junkyard: storage and clutter (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md).
//
// Size-first cards ("4.2 GB of caches in your Library folder"), one decision per item:
//   space items    Keep / Clear it / Later    Clear = the engine's fix when it offers one, else the steps
//   crash items    Keep / Update it / Later   Update = a maker look-up intent (nothing to clear)
//   setting items  Keep / Change it / Later   Change = the settings pane and steps
//   hog items      Keep / Quit it | Remove it / Later
// (that order on a note; on a critical or warning item Keep goes last, see decisions()).
// The summary adds up the space the Clear choices would free (an estimate from the scan).
//
// Pure module: no DOM, no storage, no globals. Everything shown goes through ctx.esc.

const KIND_BY_MODULE = {
  // Storage and caches (macOS).
  storage_cleanup: 'space', large_files_finder: 'space', library_cache_cleanup: 'space',
  browser_cache_cleanup: 'space', trash_cleanup: 'space', docker_cleanup: 'space',
  xcode_cleanup: 'space', mail_attachment_cleanup: 'space', temp_file_scanner: 'space',
  // Storage and caches (Windows).
  win_disk_cleanup: 'space', win_temp_cleanup: 'space', win_temp_files: 'space',
  win_temp_files_cleanup: 'space', win_disk_space: 'space',
  // Crashes and error logs.
  crash_log_analyzer: 'crash', app_crash_analyzer: 'crash', application_crash_report: 'crash',
  system_log_errors: 'crash', win_event_errors: 'crash', win_bsod_analysis: 'crash',
  // Performance settings (sleep, screen-off, Power Nap and wake are Lock Run's).
  win_power_plan: 'setting', win_power_plan_check: 'setting', win_pagefile: 'setting',
  win_pagefile_check: 'setting', win_visual_effects: 'setting',
  // Programs using a lot, and pre-installed extras.
  resource_hog_identifier: 'hog', process_scanner: 'hog', win_bloatware: 'hog',
};

export const COVERS = Object.keys(KIND_BY_MODULE).map((module) => ({ module }));

const isObj = (x) => !!x && typeof x === 'object' && !Array.isArray(x);
const str = (x) => (typeof x === 'string' ? x : typeof x === 'number' && Number.isFinite(x) ? String(x) : '');
const num = (x) => (typeof x === 'number' && Number.isFinite(x) && x >= 0 ? x : null);
const pick = (mode, t) => (t && typeof t === 'object' ? (mode === 'city' ? t.city : t.standard) : str(t));

export function fmtBytes(n) {
  let v = num(n);
  if (v === null) return '';
  for (const unit of ['B', 'KB', 'MB', 'GB', 'TB']) {
    if (v < 1024) return `${unit === 'B' ? v : v.toFixed(1)} ${unit}`;
    v /= 1024;
  }
  return `${v.toFixed(1)} PB`;
}

const findingOf = (item) => (item && isObj(item.finding) ? item.finding : {});
const dataOf = (f) => (isObj(f.data) ? f.data : {});
const subtype = (d) => str(d.type) || str(d.check) || str(d.issue);

export function kindOf(item) {
  return KIND_BY_MODULE[findingOf(item).module] || 'other';
}

function platformOf(item, ctx) {
  const m = str(findingOf(item).module);
  if (m.startsWith('win_')) return 'win32';
  return ctx && ctx.platform === 'win32' ? 'win32' : 'darwin';
}

// Bytes the item is about (what Clear would free). Free space on a full drive is not "freed".
export function bytesOf(item) {
  const f = findingOf(item);
  if (kindOf(item) !== 'space' || f.module === 'win_disk_space') return null;
  const d = dataOf(f);
  for (const k of ['size_bytes', 'total_bytes', 'total_size_bytes', 'total_size', 'cache_size', 'recycle_bin_size', 'total_reclaimable']) {
    const v = num(d[k]);
    if (v !== null) return v;
  }
  return null;
}

// An aggregate overlaps the other items of its check; the summary never adds the two.
const TOTAL_TYPES = new Set(['total_reclaimable', 'total_cache_size', 'total_browser_cache', 'total_xcode', 'high_docker_usage', 'critical_large_files', 'top_large_files', 'temp_files', 'total_waste']);
const isTotal = (item) => TOTAL_TYPES.has(subtype(dataOf(findingOf(item))));

// ---------------------------------------------------------------- what each pile is

const SAFE = 'safe'; const CHECK = 'check'; const LOOK = 'look'; const TOOL = 'tool'; const FULL = 'full'; const SUM = 'sum';

const VERDICTS = {
  [SAFE]: { standard: 'Safe to clear. Apps rebuild it when they need it.', city: 'Scrap. It grows back on its own.' },
  [CHECK]: { standard: 'Look inside first. Once it is emptied, it is gone.', city: 'Check the pile first. Once hauled, it is gone.' },
  [LOOK]: { standard: 'Yours to judge. These are your files, so look before clearing.', city: 'Your stuff. Look it over before hauling.' },
  [TOOL]: { standard: 'Let Windows clear this with its own tool. Never delete it by hand.', city: 'Only the yard crane moves this pile.' },
  // A total of other piles: it isn't one pile to clear, and those piles hold your own files too.
  [SUM]: { standard: 'A total of the other piles. Decide each pile on its own card before you clear any of it.', city: 'A tally of the other piles. Sort each pile on its own before hauling any of it.' },
  [FULL]: { standard: 'The drive is nearly full. Clearing other piles makes room.', city: 'The yard is nearly full. Hauling other piles makes room.' },
};

const MAC_CACHE_STEPS = [
  'Quit the app the cache belongs to.',
  'In Finder, choose Go > Go to Folder, type ~/Library/Caches and press Return.',
  "Move that app's folder to the Trash, then empty the Trash. The app rebuilds it.",
];
const MAC_DOWNLOAD_STEPS = [
  'Open your Downloads folder in Finder and sort by Size.',
  'Move what you no longer need to the Trash.',
  'Copy anything precious to a backup first.',
];
const MAC_FILES_STEPS = [
  'Open the folder named on the card in Finder and sort by Size.',
  'Move what you no longer need to the Trash, or copy it to an external drive first.',
];
const MAC_XCODE_BUILD_STEPS = [
  'Quit Xcode.',
  'In Finder, choose Go > Go to Folder and type ~/Library/Developer/Xcode/DerivedData.',
  'Move its contents to the Trash. Xcode rebuilds them.',
];
const WIN_TEMP_STEPS = [
  'Open Storage settings (button above) and choose Temporary files.',
  'Tick the kinds to remove. Leave Downloads unticked unless you have looked through it.',
  'Choose Remove files.',
];
const WIN_RECYCLE_STEPS = ['Open the Recycle Bin on the desktop.', 'Restore anything you still need.', 'Choose Empty Recycle Bin.'];
const WIN_SYSTEM_STEPS = [
  'Open the Start menu, type Disk Cleanup and open it.',
  'Choose Clean up system files.',
  'Tick Windows Update Cleanup and choose OK.',
];

// type -> { what: {standard, city}, verdict, steps, pane? }   (the {app}/{browser} slot is filled from data)
const SPACE = {
  total_reclaimable: { what: { standard: 'in old downloads, caches, the Trash and old installers', city: 'in old deliveries, scrap, the haul-out bin and old crates' }, verdict: SUM,
    darwin: { pane: 'storage', steps: ['Open Storage settings (button above).', 'Go through the Recommendations and the list of categories.', 'Look at each one before you remove anything.'] },
    win32: { pane: 'windows-storage', steps: WIN_TEMP_STEPS } },
  // temp_file_scanner's own total of its piles (caches, logs, temps, Xcode, Homebrew).
  total_waste: { what: { standard: 'of caches, logs and temporary files', city: 'of scrap across the yard' }, verdict: SAFE,
    darwin: { pane: 'storage', steps: ['Open Storage settings (button above).', 'Go through the Recommendations and the list of categories.', 'Look at each one before you remove anything.'] } },
  old_downloads: { what: { standard: 'of old downloads', city: 'of old deliveries' }, verdict: LOOK, darwin: { steps: MAC_DOWNLOAD_STEPS } },
  large_caches: { what: { standard: 'of caches in your Library folder', city: 'of scrap in the Library shed' }, verdict: SAFE, darwin: { steps: MAC_CACHE_STEPS } },
  total_cache_size: { what: { standard: 'of caches in your Library folder', city: 'of scrap in the Library shed' }, verdict: SAFE, darwin: { steps: MAC_CACHE_STEPS } },
  caches: { what: { standard: 'of caches', city: 'of scrap' }, verdict: SAFE, darwin: { steps: MAC_CACHE_STEPS } },
  large_single_cache: { what: { standard: 'of caches for {app}', city: 'of scrap from {app}' }, verdict: SAFE, darwin: { steps: MAC_CACHE_STEPS } },
  browser_cache: { what: { standard: 'of {browser} cache', city: 'of {browser} scrap' }, verdict: SAFE, browser: true },
  large_browser_cache: { what: { standard: 'of {browser} cache', city: 'of {browser} scrap' }, verdict: SAFE, browser: true },
  total_browser_cache: { what: { standard: 'of browser caches', city: 'of browser scrap' }, verdict: SAFE, browser: true },
  trash: { what: { standard: 'in the Trash', city: 'in the haul-out bin' }, verdict: CHECK, darwin: { steps: ['Open the Trash from the Dock.', 'Drag back anything you still need.', 'Choose Empty.'] } },
  trash_status: { what: { standard: 'in the Trash', city: 'in the haul-out bin' }, verdict: CHECK, darwin: { steps: ['Open the Trash from the Dock.', 'Drag back anything you still need.', 'Choose Empty.'] } },
  large_trash: { what: { standard: 'in the Trash', city: 'in the haul-out bin' }, verdict: CHECK, darwin: { steps: ['Open the Trash from the Dock.', 'Drag back anything you still need.', 'Choose Empty.'] } },
  too_many_trash_items: { what: { standard: 'items in the Trash', city: 'pieces in the haul-out bin' }, verdict: CHECK, count: 'item_count', darwin: { steps: ['Open the Trash from the Dock.', 'Drag back anything you still need.', 'Choose Empty.'] } },
  dmg_files: { what: { standard: 'of old installer files', city: 'of old crates' }, verdict: CHECK, darwin: { steps: ['Open your Downloads folder in Finder.', 'Installer files end in .dmg or .pkg. Once an app is installed, you can move its installer to the Trash.'] } },
  app_support: { what: { standard: 'left by apps you removed', city: 'left by hauled-off machines' }, verdict: LOOK,
    darwin: { steps: ['In Finder, choose Go > Go to Folder and type ~/Library/Application Support.', 'Move a folder to the Trash only when you are sure its app is gone from Applications.'] } },
  top_large_files: { what: { standard: 'in your biggest files', city: 'in your biggest pieces' }, verdict: LOOK, darwin: { steps: MAC_FILES_STEPS } },
  critical_large_files: { what: { standard: 'in large files', city: 'in big pieces' }, verdict: LOOK, darwin: { steps: MAC_FILES_STEPS } },
  desktop_files: { what: { standard: 'of big files on your Desktop', city: 'of big pieces on the front lot' }, verdict: LOOK, darwin: { steps: MAC_FILES_STEPS } },
  high_docker_usage: { what: { standard: 'used by Docker', city: 'in the Docker containers' }, verdict: LOOK, docker: true },
  docker_disk_usage: { what: { standard: 'used by Docker', city: 'in the Docker containers' }, verdict: LOOK, docker: true },
  docker_vm_disk_size: { what: { standard: "in Docker's disk", city: "in Docker's lot" }, verdict: LOOK, docker: true },
  dangling_images: { what: { standard: 'unused Docker images', city: 'unused Docker crates' }, verdict: SAFE, count: 'count', docker: true },
  stopped_containers: { what: { standard: 'stopped Docker containers', city: 'parked Docker containers' }, verdict: CHECK, count: 'count', docker: true },
  derived_data: { what: { standard: 'of Xcode build files', city: 'of Xcode offcuts' }, verdict: SAFE, darwin: { steps: MAC_XCODE_BUILD_STEPS } },
  xcode_caches: { what: { standard: 'of Xcode caches', city: 'of Xcode scrap' }, verdict: SAFE, darwin: { steps: MAC_XCODE_BUILD_STEPS } },
  xcode_derived: { what: { standard: 'of Xcode build files', city: 'of Xcode offcuts' }, verdict: SAFE, darwin: { steps: MAC_XCODE_BUILD_STEPS } },
  total_xcode: { what: { standard: 'used by Xcode', city: 'in the Xcode workshop' }, verdict: LOOK, darwin: { steps: MAC_XCODE_BUILD_STEPS } },
  archives: { what: { standard: 'of Xcode archives', city: 'of Xcode archives' }, verdict: LOOK,
    darwin: { steps: ['In Xcode, choose Window > Organizer and open Archives.', 'Delete archives of builds you no longer need.'] } },
  device_support: { what: { standard: 'of Xcode device files', city: 'of Xcode device parts' }, verdict: SAFE,
    darwin: { steps: ['In Finder, choose Go > Go to Folder and type ~/Library/Developer/Xcode/iOS DeviceSupport.', 'Move folders for system versions you no longer test on to the Trash. Xcode adds them back when a device needs them.'] } },
  core_simulator: { what: { standard: 'of iPhone simulators', city: 'of practice phones' }, verdict: LOOK,
    darwin: { steps: ['To remove simulators Xcode no longer supports, run: xcrun simctl delete unavailable', 'Or in Xcode open Window > Devices and Simulators and delete the ones you do not use.'] } },
  mail_data: { what: { standard: 'of Mail data', city: 'of mail sacks' }, verdict: LOOK,
    darwin: { steps: ['Mail keeps copies of your messages here. Delete old messages in Mail, then empty its Trash mailbox.'] } },
  mail_attachments: { what: { standard: 'of Mail attachments', city: 'of mail parcels' }, verdict: LOOK,
    darwin: { steps: ['In Mail, select a message with a large attachment.', 'Save the attachment to a folder first if you need it.', 'Choose Message > Remove Attachments.'] } },
  homebrew_cache: { what: { standard: 'of Homebrew downloads', city: 'of Homebrew crates' }, verdict: SAFE,
    darwin: { steps: ['Run: brew cleanup', 'Homebrew downloads them again if it needs them.'] } },
  logs: { what: { standard: 'of old log files', city: 'of old logbooks' }, verdict: SAFE, darwin: { pane: 'storage', steps: ['Open Storage settings (button above) and look through the Recommendations.'] } },
  temps: { what: { standard: 'of temporary files', city: 'of loose scrap' }, verdict: SAFE, darwin: { pane: 'storage', steps: ['Restart your Mac. It clears most temporary files on its own.'] } },
  // Windows piles.
  winsxs: { what: { standard: 'in the Windows component store', city: 'in the yard machinery store' }, verdict: TOOL, win32: { steps: WIN_SYSTEM_STEPS } },
  windows_update: { what: { standard: 'of Windows Update downloads', city: 'of old update crates' }, verdict: SAFE, win32: { steps: WIN_SYSTEM_STEPS } },
  update_cache: { what: { standard: 'of Windows Update downloads', city: 'of old update crates' }, verdict: SAFE, win32: { steps: WIN_SYSTEM_STEPS } },
  windows_old: { what: { standard: 'of your previous Windows', city: 'of the old yard office' }, verdict: CHECK,
    win32: { pane: 'windows-storage', steps: ['Open Storage settings (button above) and choose Temporary files.', 'Tick Previous Windows installation(s) only if you will not go back to it.', 'Choose Remove files.'] } },
  recycle_bin: { what: { standard: 'in the Recycle Bin', city: 'in the haul-out bin' }, verdict: CHECK, win32: { steps: WIN_RECYCLE_STEPS } },
  system_temp: { what: { standard: 'of Windows temporary files', city: 'of loose scrap' }, verdict: SAFE, win32: { pane: 'windows-storage', steps: WIN_TEMP_STEPS } },
  windows_temp: { what: { standard: 'of Windows temporary files', city: 'of loose scrap' }, verdict: SAFE, win32: { pane: 'windows-storage', steps: WIN_TEMP_STEPS } },
  user_temp: { what: { standard: 'of temporary files', city: 'of loose scrap' }, verdict: SAFE, win32: { pane: 'windows-storage', steps: WIN_TEMP_STEPS } },
  temp_files: { what: { standard: 'of temporary files', city: 'of loose scrap' }, verdict: SAFE, win32: { pane: 'windows-storage', steps: WIN_TEMP_STEPS } },
  prefetch: { what: { standard: 'of Windows start-up helper files', city: 'of start-up offcuts' }, verdict: SAFE, win32: { pane: 'windows-storage', steps: WIN_TEMP_STEPS } },
  installer_cache: { what: { standard: 'of installer cache', city: 'of installer crates' }, verdict: TOOL, win32: { steps: WIN_SYSTEM_STEPS } },
};

const BROWSER_STEPS = {
  chrome: ['In Chrome, open Settings > Privacy and security > Delete browsing data.', 'Tick only Cached images and files, then choose Delete data.'],
  brave: ['In Brave, open Settings > Privacy and security > Delete browsing data.', 'Tick only Cached images and files, then choose Delete data.'],
  edge: ['In Edge, open Settings > Privacy, search, and services > Clear browsing data.', 'Choose what to clear, tick only Cached images and files, then Clear now.'],
  firefox: ['In Firefox, open Settings > Privacy & Security.', 'Under Cookies and Site Data, choose Clear Data, tick only the cached web content, then Clear.'],
  safari: ['In Safari, open Settings > Advanced and turn on Show features for web developers.', 'Choose Develop > Empty Caches.'],
};
const BROWSER_GENERIC = ["In the browser's settings, find the option to clear browsing data.", 'Choose only cached images and files, so your sign-ins stay.'];

const DOCKER_STEPS = [
  'Open Docker Desktop to see images, containers and volumes.',
  'To clear stopped containers and unused images, run: docker system prune',
  'Volumes hold data. Remove one only when you know what is in it.',
];

function spaceInfo(item) {
  const d = dataOf(findingOf(item));
  const t = subtype(d);
  if (findingOf(item).module === 'win_disk_space') return { full: true, verdict: FULL, win32: { pane: 'windows-storage', steps: ['Open Storage settings (button above).', 'Turn on Storage Sense, or review Temporary files.', 'Look at large folders before removing anything.'] } };
  return SPACE[t] || null;
}

function spaceSteps(item, ctx) {
  const info = spaceInfo(item);
  const plat = platformOf(item, ctx);
  if (!info) return { pane: plat === 'win32' ? 'windows-storage' : 'storage', steps: ['Open Storage settings (button above).', 'Look at each pile before you remove anything.'] };
  if (info.browser) {
    const b = str(dataOf(findingOf(item)).browser).toLowerCase();
    const key = Object.keys(BROWSER_STEPS).find((k) => b.includes(k));
    return { steps: key ? BROWSER_STEPS[key] : BROWSER_GENERIC };
  }
  if (info.docker) return { steps: DOCKER_STEPS };
  const p = info[plat] || info.darwin || info.win32;
  return p ? { pane: p.pane, steps: p.steps } : { steps: [] };
}

// ---------------------------------------------------------------- crashes

function crashSubject(item) {
  const f = findingOf(item);
  const d = dataOf(f);
  if (str(d.app_name)) return str(d.app_name);
  if (Array.isArray(d.system_apps) && str(d.system_apps[0])) return str(d.system_apps[0]);
  if (Array.isArray(d.affected_apps) && d.affected_apps[0]) {
    const a = d.affected_apps[0];
    return Array.isArray(a) ? str(a[0]) : str(a);
  }
  if (isObj(d.top_sources)) return Object.keys(d.top_sources)[0] || '';
  if (f.module === 'win_bsod_analysis') return str(d.stop_code) || (Array.isArray(d.stop_codes) ? str(d.stop_codes[0]) : '');
  return '';
}

function crashCount(item) {
  const d = dataOf(findingOf(item));
  for (const k of ['crash_count', 'event_count', 'error_count', 'known_bad_count', 'total_recent']) {
    const v = num(d[k]);
    if (v !== null) return v;
  }
  if (Array.isArray(d.affected_apps) && Array.isArray(d.affected_apps[0]) && num(d.affected_apps[0][1]) !== null) return d.affected_apps[0][1];
  if (num(d.system_error_count) !== null || num(d.app_error_count) !== null) return (num(d.system_error_count) || 0) + (num(d.app_error_count) || 0);
  return null;
}

const isSystemCrash = (item) => {
  const f = findingOf(item); const d = dataOf(f);
  return d.is_system_app === true || subtype(d) === 'system_crashes' || f.module === 'system_log_errors';
};

function verifiedMaker(item, subject) {
  const list = Array.isArray(findingOf(item).made_by) ? findingOf(item).made_by : [];
  return list.find((e) => isObj(e) && e.verified === true && (!subject || e.subject === subject || !e.subject)) || null;
}

function crashLookup(item) {
  const f = findingOf(item);
  const subject = crashSubject(item);
  if (f.module === 'win_bsod_analysis') return { kind: 'lookup', source: 'microsoft-support', query: subject ? `stop code ${subject}` : 'blue screen stop code' };
  if (f.module === 'win_event_errors') return { kind: 'lookup', source: 'microsoft-support', query: subject ? `${subject} error` : 'event log errors' };
  if (isSystemCrash(item)) return { kind: 'lookup', source: 'apple-support', query: subject ? `${subject} keeps crashing` : 'Mac keeps crashing' };
  const maker = verifiedMaker(item, subject);
  if (maker) return { kind: 'lookup', source: 'maker-site', query: subject || str(maker.name), maker: str(maker.name) };
  return { kind: 'lookup', source: 'web', query: subject ? `"${subject}" update` : 'app keeps crashing update' };
}

// ---------------------------------------------------------------- settings and hogs

function settingSteps(item, ctx) {
  const f = findingOf(item); const d = dataOf(f);
  const t = subtype(d);
  if (f.module === 'win_power_plan' || f.module === 'win_power_plan_check') {
    if (t === 'disk_timeout_short' || t === 'disk_timeout') return { steps: ['Open the Start menu, type Edit power plan and open it.', 'Choose Change advanced power settings.', 'Under Hard disk, set Turn off hard disk after to a longer time.'] };
    return { steps: ['Open the Start menu, type Choose a power plan and open it.', 'Pick Balanced. It speeds up when you need it and saves power when you do not.'] };
  }
  if (f.module === 'win_pagefile' || f.module === 'win_pagefile_check') {
    return { steps: ['Open the Start menu, type Advanced system settings and open it.', 'Under Performance, choose Settings, then Advanced, then Virtual memory: Change.', 'Tick Automatically manage paging file size for all drives, choose OK and restart.'] };
  }
  if (f.module === 'win_visual_effects') {
    if (t === 'transparency_low_ram') return { steps: ['Open Settings > Personalization > Colors.', 'Turn off Transparency effects.'] };
    return { steps: ['Open the Start menu, type Adjust the appearance and performance of Windows.', 'Choose Adjust for best performance, or untick the effects you do not need, then OK.'] };
  }
  return { steps: ['Look for the setting named on the card.'] };
}

const isBloat = (item) => ['process_scanner', 'win_bloatware'].includes(findingOf(item).module);

function hogName(item) {
  const d = dataOf(findingOf(item));
  return str(d.bloatware_name) || str(d.name) || str(d.process_name) || str(d.app_name);
}

function hogSteps(item, ctx) {
  const name = hogName(item) || 'it';
  const win = platformOf(item, ctx) === 'win32';
  if (isBloat(item)) {
    if (win) return { pane: 'windows-apps', steps: ['Open Installed apps (button above).', `Find ${name}, choose the three dots next to it, then Uninstall.`] };
    return { steps: ['Quit the app first.', 'In Finder, open Applications and move the app to the Trash.', 'If the app came with its own uninstaller, use that instead.'] };
  }
  if (win) return { steps: ['Press Ctrl+Shift+Esc to open Task Manager.', `Find ${name} under Processes.`, 'If you know what it is and do not need it now, select it and choose End task.'] };
  return { steps: ['Open Activity Monitor (search for it with Spotlight).', `Find ${name} in the CPU or Memory list.`, 'If you know what it is and do not need it now, select it, choose the Stop button, then Quit.'] };
}

// ---------------------------------------------------------------- decisions

const L = (standard, city) => ({ standard, city });

const KEEP = { id: 'keep', label: L('Keep', 'Keep it'), effect: { kind: 'keep' } };
const LATER = { id: 'later', label: L('Later', 'Later'), effect: { kind: 'later' } };

// The Clear-type decision: the engine's own fix when it offered one, else the settings pane or the steps.
function stepsEffect({ pane, steps }) {
  const s = Array.isArray(steps) ? steps.slice() : [];
  return pane ? { kind: 'settings', pane, steps: s } : { kind: 'closer', steps: s };
}

const fixable = (item) => isObj(findingOf(item).fixable);

const alerting = (item) => !!(item && (item.removal_alert || findingOf(item).removal_alert
  || (isObj(findingOf(item).remediation) && findingOf(item).remediation.safety_note)));

// The first decision is the default. Keep leads only on a note (info). On a critical or warning item the safe
// move leads instead: Update it / Change it (a look-up or a settings page), Clear it for a pile that rebuilds on
// its own, else Later; Keep comes last. On an item with a removal warning every acting effect carries
// warning: true, so the runner shows the warning before it acts (ruling R6), and nothing removing leads.
function decisions(item, ctx) {
  const base = baseDecisions(item, ctx);
  const alert = alerting(item);
  const list = alert ? base.map((d) => (['keep', 'later'].includes(d.effect.kind) ? d : { ...d, effect: { ...d.effect, warning: true } })) : base;
  const sev = (item && item.severity) || findingOf(item).severity;
  if (!(sev === 'critical' || sev === 'warning' || alert)) return list;
  const [keep, act, later] = list;
  const kind = kindOf(item);
  const safeAct = !alert && act.effect.kind !== 'fix'
    && (kind === 'crash' || kind === 'setting' || (kind === 'space' && (spaceInfo(item) || {}).verdict === SAFE));
  return safeAct ? [act, later, keep] : [later, act, keep];
}

function baseDecisions(item, ctx) {
  const kind = kindOf(item);
  if (kind === 'crash') {
    return [KEEP, { id: 'update', label: L('Update it', 'Patch it'), effect: { kind: 'link', link: crashLookup(item) }, hint: 'Opens a look-up for the maker\'s update' }, LATER];
  }
  if (kind === 'setting') {
    return [KEEP, { id: 'change', label: L('Change it', 'Rewire it'), effect: stepsEffect(settingSteps(item, ctx)) }, LATER];
  }
  if (kind === 'hog') {
    const bloat = isBloat(item);
    const d = bloat ? { id: 'remove', label: L('Remove it', 'Haul it off') } : { id: 'quit', label: L('Quit it', 'Shut it down') };
    return [KEEP, { ...d, effect: fixable(item) ? { kind: 'fix' } : stepsEffect(hogSteps(item, ctx)) }, LATER];
  }
  const clear = fixable(item)
    ? { id: 'clear', label: L('Clear it', 'Haul it off'), effect: { kind: 'fix' }, hint: 'You see what changes and confirm first' }
    : { id: 'clear', label: L('Clear it', 'Haul it off'), effect: stepsEffect(spaceSteps(item, ctx)), hint: 'Shows you the steps' };
  return [KEEP, clear, LATER];
}

// ---------------------------------------------------------------- research

const unfinished = (item) => !!(item && (item.unfinished || item.complete === false || findingOf(item).complete === false || findingOf(item).unfinished));

const CRASH_WHAT = {
  standard: 'Crashes are not cleared away. The usual fix is an update from the maker.',
  city: 'A breakdown is not scrap. The usual fix is a new part from its maker.',
};
const SETTING_WHAT = { standard: 'A setting, not a pile. Change it only if it matters to you.', city: 'A yard switch, not a pile. Flip it only if it matters to you.' };
const HOG_WHAT = { standard: 'A program using a lot of your computer right now.', city: 'A machine running hot in the yard right now.' };
const BLOAT_WHAT = { standard: 'A program that came pre-installed. Many people never use it.', city: 'A machine that came with the yard. Many never use it.' };

function research(item, ctx) {
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  const f = findingOf(item);
  let rows = [];
  try { rows = ctx && typeof ctx.evidenceRows === 'function' ? ctx.evidenceRows(f, { mode }) || [] : []; } catch (_) { rows = []; }
  if (!Array.isArray(rows)) rows = [];
  const kind = kindOf(item);
  const plat = platformOf(item, ctx);
  const links = [];
  let what = '';
  let verdict = null;
  if (kind === 'space') {
    const info = spaceInfo(item);
    verdict = info ? info.verdict : LOOK;
    what = pick(mode, VERDICTS[verdict]);
    links.push({ kind: 'settings', pane: plat === 'win32' ? 'windows-storage' : 'storage' });
  } else if (kind === 'crash') {
    const maker = verifiedMaker(item, crashSubject(item));
    what = maker && str(maker.what) ? str(maker.what) : pick(mode, CRASH_WHAT);
    links.push(crashLookup(item));
    links.push({ kind: 'settings', pane: plat === 'win32' ? 'windows-update' : 'software-update' });
  } else if (kind === 'setting') {
    what = pick(mode, SETTING_WHAT);
    const s = settingSteps(item, ctx);
    if (s.pane) links.push({ kind: 'settings', pane: s.pane });
  } else if (kind === 'hog') {
    what = pick(mode, isBloat(item) ? BLOAT_WHAT : HOG_WHAT);
    const name = hogName(item);
    if (name) links.push({ kind: 'lookup', source: plat === 'win32' ? 'microsoft-support' : 'web', query: `what is "${name}"` });
    if (isBloat(item) && plat === 'win32') links.push({ kind: 'settings', pane: 'windows-apps' });
  }
  links.push({ kind: 'lesson', concept: 'fix-and-undo' });
  return { rows, what, links, verdict, unfinished: unfinished(item) };
}

// ---------------------------------------------------------------- render

const UNFINISHED = { standard: "This check didn't finish, so there may be more than this.", city: "This check didn't finish, so there may be more in the pile." };
const TAG = {
  space: L('Space', 'Scrap pile'), crash: L('Keeps crashing', 'Breakdown'), setting: L('Setting', 'Yard switch'),
  hog: L('Using a lot', 'Running hot'), other: L('Clutter', 'Scrap'),
};

function fill(text, item) {
  const d = dataOf(findingOf(item));
  return text.replace('{app}', str(d.app_name) || 'an app').replace('{browser}', str(d.browser) || 'browser');
}

// The headline, size first: { size, rest } (both plain strings; render escapes them).
export function headline(item, mode = 'standard') {
  const f = findingOf(item); const d = dataOf(f);
  const kind = kindOf(item);
  const city = mode === 'city';
  if (kind === 'space') {
    if (f.module === 'win_disk_space') {
      const pct = str(d.used_pct_str);
      return { size: pct || fmtBytes(num(d.free_bytes)), rest: city ? `of yard ${str(d.caption)} in use, ${fmtBytes(num(d.free_bytes))} free` : `of drive ${str(d.caption)} in use, ${fmtBytes(num(d.free_bytes))} free` };
    }
    const info = spaceInfo(item);
    if (info && info.count) {
      const c = num(d[info.count]);
      if (c !== null) return { size: String(c), rest: fill(pick(mode, info.what), item) };
    }
    const b = bytesOf(item);
    const size = b !== null ? fmtBytes(b) : str(d.size_formatted) || str(d.total_formatted);
    if (info) return { size, rest: fill(pick(mode, info.what), item) };
    return { size, rest: str(f.title) };
  }
  if (kind === 'crash') {
    const c = crashCount(item);
    const who = crashSubject(item);
    const noun = f.module === 'system_log_errors' || f.module === 'win_event_errors' ? (city ? 'faults logged' : 'errors logged') : (city ? 'breakdowns' : 'crashes');
    return { size: c !== null ? String(c) : '', rest: who ? `${noun}: ${who}` : noun };
  }
  if (kind === 'hog') {
    const name = hogName(item);
    const mem = num(d.memory_bytes);
    if (mem !== null) return { size: fmtBytes(mem), rest: `${city ? 'of power' : 'of memory'}${num(d.cpu_percent) !== null ? `, ${d.cpu_percent}% CPU` : ''}: ${name}` };
    if (str(d.resource_savings)) return { size: str(d.resource_savings), rest: `${city ? 'freed if hauled' : 'freed if removed'}: ${name}` };
    return { size: '', rest: name || str(f.title) };
  }
  return { size: '', rest: str(f.title) };
}

// The biggest piece in a pile, by file name only (the runner shows the full evidence rows).
function topPiece(item) {
  const files = dataOf(findingOf(item)).files;
  if (!Array.isArray(files)) return '';
  let best = null;
  for (const x of files) if (isObj(x) && str(x.path) && (!best || (num(x.size) || 0) > (num(best.size) || 0))) best = x;
  return best ? str(best.path).split(/[\\/]/).filter(Boolean).pop() || '' : '';
}

function render(view, ctx) {
  const v = isObj(view) ? view : {};
  const item = v.item || {};
  const mode = ctx.mode === 'city' ? 'city' : 'standard';
  const esc = ctx.esc;
  const f = findingOf(item);
  const kind = kindOf(item);
  const r = isObj(v.research) ? v.research : research(item, ctx);
  const h = headline(item, mode);
  const look = v.step && typeof v.step.look === 'string' ? v.step.look : '';
  const at = (part) => (look === part ? ' jy-look' : '');
  const verdict = r.verdict && VERDICTS[r.verdict] ? r.verdict : '';
  const parts = [
    `<article class="jy-card jy-card--${esc(kind)}" data-kind="${esc(kind)}">`,
    `<p class="jy-tag">${esc(pick(mode, TAG[kind] || TAG.other))}</p>`,
    `<h3 class="jy-head${at('size')}">${h.size ? `<span class="jy-size">${esc(h.size)}</span> ` : ''}<span class="jy-rest">${esc(h.rest)}</span></h3>`,
  ];
  // The engine's title, unless it only restates the size ("Your Mac has 12.0 GB of unused space" reads as free space).
  if (h.rest !== str(f.title) && str(f.title) && !(h.size && str(f.title).includes(h.size))) parts.push(`<p class="jy-title">${esc(f.title)}</p>`);
  if (r.what) parts.push(`<p class="jy-what${verdict ? ` jy-verdict jy-verdict--${esc(verdict)}` : ''}${at('verdict')}${at('what')}">${esc(r.what)}</p>`);
  if (r.unfinished) parts.push(`<p class="jy-unfinished">${esc(pick(mode, UNFINISHED))}</p>`);
  if (v.step && v.step.say) parts.push(`<p class="jy-say">${esc(pick(mode, v.step.say))}</p>`);
  const top = topPiece(item);
  if (top) parts.push(`<p class="jy-top${at('top')}">${esc(mode === 'city' ? 'Biggest piece: ' : 'Biggest file: ')}<span class="jy-name">${esc(top)}</span></p>`);
  parts.push('</article>');
  return parts.join('');
}

// ---------------------------------------------------------------- summary

const decisionId = (res) => {
  if (!res) return '';
  const d = res.decision !== undefined ? res.decision : res.decisionId !== undefined ? res.decisionId : res.choice;
  return typeof d === 'string' ? d : isObj(d) ? str(d.id) : '';
};

// Space the Clear choices would free. Per check: the bigger of its aggregate and the sum of its
// other piles, so a "total" card and the piles inside it are never added twice.
export function freedBytes(results) {
  const byModule = new Map();
  for (const res of Array.isArray(results) ? results : []) {
    if (!res || decisionId(res) !== 'clear') continue;
    const b = bytesOf(res.item);
    if (b === null) continue;
    const m = str(findingOf(res.item).module) || '?';
    const e = byModule.get(m) || { total: 0, parts: 0 };
    if (isTotal(res.item)) e.total = Math.max(e.total, b); else e.parts += b;
    byModule.set(m, e);
  }
  let sum = 0;
  for (const e of byModule.values()) sum += Math.max(e.total, e.parts);
  return sum;
}

function summary(results, ctx) {
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  const esc = ctx && typeof ctx.esc === 'function' ? ctx.esc : (s) => String(s);
  const list = Array.isArray(results) ? results : [];
  const count = (id) => list.filter((x) => decisionId(x) === id).length;
  const freed = freedBytes(list);
  const kept = count('keep');
  const later = count('later');
  const acted = list.length - kept - later;
  const lines = [];
  if (freed > 0) {
    lines.push(mode === 'city'
      ? `<p class="jy-freed"><span class="jy-size">${esc(fmtBytes(freed))}</span> of scrap your haul-off choices would clear.</p>`
      : `<p class="jy-freed"><span class="jy-size">${esc(fmtBytes(freed))}</span> your Clear choices would free.</p>`);
    lines.push(`<p class="jy-note">${esc(mode === 'city' ? 'A rough count from the sweep. The next sweep shows the real number.' : 'An estimate from the scan. The next checkup shows the real number.')}</p>`);
  } else {
    lines.push(`<p class="jy-freed">${esc(mode === 'city' ? 'Nothing hauled off this round.' : 'Nothing cleared this round.')}</p>`);
  }
  const tally = [];
  if (acted) tally.push(mode === 'city' ? `${acted} sorted for action` : `${acted} to act on`);
  if (kept) tally.push(mode === 'city' ? `${kept} kept in the yard` : `${kept} kept`);
  if (later) tally.push(mode === 'city' ? `${later} set aside` : `${later} for later`);
  if (tally.length) lines.push(`<p class="jy-tally">${esc(tally.join(' · '))}</p>`);
  return `<section class="jy-summary">${lines.join('')}</section>`;
}

// ---------------------------------------------------------------- practice (synthetic only)

const practiceItem = (module, finding) => {
  const f = { module, severity: 'warning', category: 'performance', ...finding };
  return { key: `practice:${module}:${f.title}`, severity: f.severity, finding: f, findings: [f], seen_in: [module], marked: false, held: false, removal_alert: false, practice: true };
};

const PRACTICE_ITEMS = [
  practiceItem('browser_cache_cleanup', {
    title: 'Large Chrome cache: 2.4 GB',
    description: 'Chrome is keeping 2.4 GB of copies of web pages.',
    data: { type: 'large_browser_cache', browser: 'Chrome', size_bytes: 2576980378, size_formatted: '2.4 GB' },
  }),
  practiceItem('large_files_finder', {
    title: 'Big files on your Desktop: 6.8 GB',
    description: 'One large video on your Desktop.',
    data: { type: 'desktop_files', size_bytes: 7301444403, size_formatted: '6.8 GB', file_count: 1, files: [{ path: '~/Desktop/Summer trip, final cut.mov', size: 7301444403 }] },
  }),
  practiceItem('app_crash_analyzer', {
    title: 'PixelPad keeps crashing (9 times in 7 days)',
    description: 'PixelPad has stopped working 9 times in the last week.',
    data: { check: 'unstable_app', app_name: 'PixelPad', crash_count: 9 },
  }),
];

// Steps ask before they tell: `say` asks, `why` (after the move) gives the verdict and its clue. No `expect`:
// an explanation (one GOT IT). `expect` may list several moves that all fit (the first is the best).
const PRACTICE_SCRIPT = [
  { item: 0, look: 'size', say: L('Start with the size, then read what the pile is.', 'Start with the size, then read what the pile is.') },
  { item: 0, look: 'verdict', expect: ['clear', 'later'],
    say: L('A pile of browser cache. Read what it is. What would you do?', 'A pile of browser scrap. Read what it is. What would you do?'),
    why: L('A cache is copies a browser keeps to load pages faster. It rebuilds them, so it is safe to clear.', 'Browser scrap grows back on its own, so it is safe to haul off.') },
  { item: 1, look: 'top', expect: ['keep', 'later'],
    say: L('A big pile. Read the biggest file in it. What would you do?', 'A big pile. Read the biggest piece in it. What would you do?'),
    why: L('Big is not the same as junk. This is a film you made: keep it, or copy it to a backup before clearing.', 'Big is not the same as scrap. This is a film you made: keep it, or copy it somewhere safe first.') },
  { item: 2, look: 'what', expect: 'update',
    say: L('This app keeps crashing. What would you do?', 'This machine keeps breaking down. What would you do?'),
    why: L('There is nothing here to clear away. Update it looks up the maker\'s fix.', 'There is no scrap to haul. Patch it looks up a new part from its maker.') },
];

export default {
  type: 'junkyard',
  title: { standard: 'Storage and clutter', city: 'The Junkyard' },
  concepts: ['fix-and-undo', 'who-made-it'],
  covers: COVERS,
  decisions,
  research,
  practice: { items: PRACTICE_ITEMS, script: PRACTICE_SCRIPT },
  render,
  summary,
};
