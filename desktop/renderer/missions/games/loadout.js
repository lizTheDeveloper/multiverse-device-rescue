// The Loadout: browser add-ons (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md,
// type `loadout`). One card per add-on with its powers in plain words, and one decision:
// Keep / Trim (limit its site access) / Remove. Browser hijacks (start page, search engine, policy) and
// in-browser mining get the same card with moves of their own.
//
// Pure module (missions/contract.js): no DOM, storage, network or globals. Every scan value goes through
// ctx.esc. Browser pages (chrome://, edge://, about:) can't be linked, so a card says what to type. An
// extension id is only ever put into typed steps after it matches the Chrome/Edge id alphabet; names,
// hosts and URLs from the scan never go into steps. Removal is instructions: the engine has no app fix
// for extensions (rescue/app_fixes.json), so a `fix` effect is used only when a finding carries `fixable`.
// Keep is a `mark` when the engine offers `markable` (browser_extension_audit), else `keep`.
//
// macOS and Windows: Chrome, Edge, Brave, Vivaldi, Chromium, Firefox, Safari. The engine's in-browser
// mining check names a Chromium browser by its profile folder, which is "User Data" on Windows, so the
// browser is read from the finding's path there.
import { makerFor, isAlertingItem } from '../contract.js';

const ID_RE = /^[a-p]{32}$/;
const HOST_RE = /^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$/i;
const MAX_VALUE = 200;
const MAX_LOOKUPS = 4;

// Public Chrome Web Store ids of well-known password managers (rescue/known_extensions.py).
const PASSWORD_MANAGERS = {
  hdokiejnpimakedhajhdlcegeplioahd: 'LastPass',
  aeblfdkhhhdcdjpifhhbdiojplfjncoa: '1Password',
  nngceckbapebfimnlniiiahkandclblb: 'Bitwarden',
  fdjamakpfbbddfjaooikfcpapjohcfmg: 'Dashlane',
  ghmbeldphafepmbegfdlkpapadhbakde: 'Proton Pass',
  oboonakemofpalcgghocfoadofidjkkk: 'KeePassXC',
  fooolghllnmhmmndgjiamiiodkpenpbb: 'NordPass',
  bfogiafebfohielmmehodmfbbebbbpei: 'Keeper',
  pnlccmojcmeohlpggmfnbbiapkmbliob: 'RoboForm',
  kmcfomidfpdkfieipokbalgegidffkal: 'Enpass',
};

// `page`: what to type to reach its extensions page; `store`: installs from the Chrome Web Store;
// `chromium`: has Chrome's "Site access" control.
const BROWSERS = {
  chrome: { name: 'Chrome', page: 'chrome://extensions', store: true, chromium: true },
  edge: { name: 'Edge', page: 'edge://extensions', store: false, chromium: true },
  brave: { name: 'Brave', page: 'brave://extensions', store: true, chromium: true },
  vivaldi: { name: 'Vivaldi', page: 'vivaldi://extensions', store: true, chromium: true },
  chromium: { name: 'Chromium', page: 'chrome://extensions', store: true, chromium: true },
  firefox: { name: 'Firefox', page: 'about:addons', store: false, chromium: false },
  safari: { name: 'Safari', page: '', store: false, chromium: false },
  unknown: { name: '', page: '', store: false, chromium: false },
};
const SAFARI = { id: 'safari', ...BROWSERS.safari };
const BROWSER_NAMES = {
  chrome: 'chrome', 'google chrome': 'chrome', edge: 'edge', 'microsoft edge': 'edge', brave: 'brave',
  'brave-browser': 'brave', vivaldi: 'vivaldi', chromium: 'chromium', firefox: 'firefox', safari: 'safari',
};
const BROWSER_PATHS = [
  [/Microsoft[\\/ ]Edge/i, 'edge'], [/BraveSoftware/i, 'brave'], [/Vivaldi/i, 'vivaldi'],
  [/Google[\\/ ]Chrome/i, 'chrome'], [/[\\/]Chromium[\\/]/i, 'chromium'], [/Firefox|Mozilla/i, 'firefox'],
];

const str = (v) => (typeof v === 'string' ? v : v == null ? '' : String(v));
const clip = (s, n = MAX_VALUE) => { const t = str(s); return t.length > n ? `${t.slice(0, n - 1)}…` : t; };
const words = (ctx, standard, city) => (ctx && ctx.mode === 'city' ? city : standard);
const enterKey = (ctx) => (ctx && ctx.platform === 'win32' ? 'Enter' : 'Return');
const dataOf = (f) => (f && f.data && typeof f.data === 'object' ? f.data : {});

function browserOf(finding) {
  const f = finding || {};
  const d = dataOf(f);
  let id = null;
  if (f.module === 'chrome_extensions') id = 'chrome';
  else if (f.module === 'safari_extensions') id = 'safari';
  else {
    const m = /\.(safari|chrome|firefox)_/.exec(str(f.code));
    if (m) id = m[1];
  }
  if (!id) id = BROWSER_NAMES[str(d.browser).trim().toLowerCase()] || null;
  if (!id) {
    const p = str(d.path);
    const hit = BROWSER_PATHS.find(([re]) => re.test(p));
    id = hit ? hit[1] : 'unknown';
  }
  return { id, ...BROWSERS[id] };
}

const KINDS = {
  broad_permissions: 'extension', excessive_permissions: 'extension',
  malicious_extension: 'known-bad', adware_extension: 'known-bad',
  mining_extension: 'miner', mining_startup_page: 'mining-page', mining_hosts_entry: 'mining-hosts',
  chrome_managed_by_policy: 'managed', extension_bloat: 'many', legacy_extensions: 'legacy',
  content_blockers_disabled: 'blockers-off', new_browser_extension: 'new-ext',
};

function kindOf(finding) {
  const f = finding || {};
  const d = dataOf(f);
  const tail = str(f.code).split('.').pop();
  const check = str(d.check);
  for (const k of [tail, check]) {
    if (KINDS[k]) return KINDS[k];
    if (/_(homepage|search_engine)_suspicious$/.test(k)) return 'hijack';
  }
  if (check === 'content_blockers' && d.enabled === false) return 'blockers-off';
  if ((d.extension || d.extension_name) && Array.isArray(d.permissions)) return 'extension';
  return 'list';
}

const nameOf = (f) => { const d = dataOf(f); return str(d.extension || d.extension_name || d.name || (f && f.title)); };
const idOf = (f) => { const id = str(dataOf(f).extension_id); return ID_RE.test(id) ? id : ''; };
const isMining = (k) => k === 'miner' || k === 'mining-page' || k === 'mining-hosts';

// ---- Powers: permissions in plain words ----

const LEVEL_RANK = { high: 0, med: 1, low: 2 };
const ALL_SITES = ['Read and change all your data on all websites', 'Reads and rewrites every page you visit', 'high'];
const POWERS = {
  '<all_urls>': ALL_SITES, all_urls: ALL_SITES, '*://*/*': ALL_SITES, 'http://*/*': ALL_SITES, 'https://*/*': ALL_SITES,
  tabs: ['Read your browsing history', 'Sees where you browse', 'med'],
  history: ['Read and change your browsing history', 'Reads and rewrites where you browsed', 'high'],
  webNavigation: ['Read your browsing history', 'Sees where you browse', 'med'],
  webRequest: ['See every page your browser loads', 'Watches every page that loads', 'med'],
  webRequestBlocking: ['Block or change pages as they load', 'Blocks or rewrites pages as they load', 'high'],
  declarativeNetRequest: ['Block content on pages', 'Blocks content on pages', 'low'],
  cookies: ['Read the cookies that keep you signed in', 'Reads the cookies that keep you signed in', 'high'],
  scripting: ['Run its own code on websites', 'Runs its own code on pages', 'high'],
  debugger: ['Read and change everything on pages it opens', 'Reads and rewrites pages it opens', 'high'],
  clipboardRead: ['Read what you copy', 'Reads what you copy', 'high'],
  clipboardWrite: ['Change what you copy', 'Changes what you copy', 'med'],
  management: ['Manage your other extensions', 'Controls your other add-ons', 'high'],
  proxy: ['Send your browsing through another server', 'Reroutes your browsing', 'high'],
  privacy: ['Change your privacy settings', 'Changes your privacy settings', 'med'],
  contentSettings: ['Change site settings like camera and pop-ups', 'Changes site settings like camera and pop-ups', 'med'],
  downloads: ['Manage your downloads', 'Handles your downloads', 'med'],
  nativeMessaging: ['Talk to an app installed on this computer', 'Talks to an app on this machine', 'med'],
  geolocation: ['Know your location', 'Knows where you are', 'med'],
  activeTab: ['Work on a page only when you click it', 'Works on a page only when you click it', 'low'],
  storage: ['Save its own settings', 'Keeps its own settings', 'low'],
  notifications: ['Show notifications', 'Shows notifications', 'low'],
};

function powers(perms, mode) {
  const seen = new Set();
  const out = [];
  for (const raw of Array.isArray(perms) ? perms : []) {
    const p = str(raw);
    if (!p) continue;
    let entry;
    if (Object.prototype.hasOwnProperty.call(POWERS, p)) {
      const [s, c, level] = POWERS[p];
      entry = { text: mode === 'city' ? c : s, level };
    } else if (/^[a-z*]+:\/\/[^/]+/i.test(p)) {
      const host = clip(p.replace(/^[a-z*]+:\/\//i, '').replace(/\/.*$/, ''), 80);
      entry = { text: mode === 'city' ? `Reads and rewrites pages on ${host}` : `Read and change your data on ${host}`, level: 'med' };
    } else {
      entry = { text: clip(p, 80), level: 'low', raw: true };
    }
    if (seen.has(entry.text)) continue;
    seen.add(entry.text);
    out.push(entry);
  }
  return out.sort((a, b) => LEVEL_RANK[a.level] - LEVEL_RANK[b.level]);
}

// ---- Steps: what to do in the browser (validated values only) ----

function openExtensions(b, id, ctx) {
  const key = enterKey(ctx);
  if (b.chromium) return `In ${b.name}, click the address bar, type ${b.page}${id ? `/?id=${id}` : ''} and press ${key}.`;
  if (b.id === 'firefox') return `In Firefox, click the address bar, type about:addons and press ${key}.`;
  if (b.id === 'safari') return 'In Safari, choose Safari > Settings, then click Extensions.';
  const safari = ctx && ctx.platform === 'darwin' ? ' In Safari, choose Safari > Settings > Extensions.' : '';
  return `Open the browser it’s in. In Chrome type chrome://extensions, in Edge type edge://extensions, in Firefox type about:addons, and press ${key}.${safari}`;
}

const ADMIN_LINE = 'If it says “Installed by your administrator”, it can’t be removed there. Look closer first.';
const SYNC_LINE = 'Do this in every profile of that browser, and anywhere you’re signed in to sync: sync can bring it back.';

function trimSteps(b, id, ctx) {
  if (b.id === 'firefox') return [openExtensions(b, id, ctx), 'Click the add-on, open its “Permissions” tab, and turn off anything it doesn’t need.'];
  if (b.id === 'safari') return [openExtensions(b, id, ctx), 'Select it, click “Edit Websites…”, and set “When visiting other websites” to Ask or Deny.'];
  return [openExtensions(b, id, ctx), 'Find “Site access” and choose “On click”, or “On specific sites” and add only the sites it needs.'];
}

function removeSteps(b, id, ctx, kind) {
  let steps;
  if (b.id === 'firefox') steps = [openExtensions(b, id, ctx), 'Click “…” next to it and choose “Remove”.'];
  else if (b.id === 'safari') steps = [openExtensions(b, id, ctx), 'Select it and click “Uninstall”. If Safari shows the app it came with, move that app to the Trash.'];
  else steps = [openExtensions(b, id, ctx), 'Click “Remove”, then “Remove” again to confirm.', ADMIN_LINE];
  if (kind === 'miner') steps.push(SYNC_LINE);
  return steps;
}

function manySteps(b, ctx) {
  const key = enterKey(ctx);
  if (b.id !== 'unknown') return [openExtensions(b, '', ctx), 'Remove the ones you don’t use or don’t recognise.'];
  const lines = [
    `In Chrome, type chrome://extensions and press ${key}. In Edge, type edge://extensions.`,
    `In Firefox, type about:addons and press ${key}.`,
  ];
  if (!ctx || ctx.platform !== 'win32') lines.push('In Safari, choose Safari > Settings > Extensions.');
  lines.push('Remove the ones you don’t use or don’t recognise.');
  return lines;
}

function resetSteps(b, finding, ctx) {
  const key = enterKey(ctx);
  const search = /search_engine/.test(str(finding.code) + str(dataOf(finding).check));
  const tail = 'If it changes back, an extension or a policy is setting it: look closer.';
  if (b.id === 'safari') {
    return search
      ? ['In Safari, choose Safari > Settings > Search.', 'Choose a search engine you trust.', tail]
      : ['In Safari, choose Safari > Settings > General.', 'Set “Homepage” to a site you trust.', tail];
  }
  if (b.id === 'firefox') {
    return search
      ? [`In Firefox, type about:preferences#search and press ${key}.`, 'Under “Default Search Engine”, choose one you trust.', tail]
      : [`In Firefox, type about:preferences#home and press ${key}.`, 'Set “Homepage and new windows” to Firefox Home or a page you trust.', tail];
  }
  return search
    ? [`In Chrome, type chrome://settings/search and press ${key}.`, 'Under “Search engine used in the address bar”, choose one you trust.', tail]
    : [`In Chrome, type chrome://settings/onStartup and press ${key}.`, 'Choose “Open the New Tab page”, or a page you trust.', tail];
}

function startupSteps(b, ctx) {
  const key = enterKey(ctx);
  const first = b.id === 'chrome' || b.id === 'chromium'
    ? `In ${b.name}, type chrome://settings/onStartup and press ${key}.`
    : b.chromium ? `Open ${b.name}’s settings and find “On startup”.`
      : 'Open the browser’s settings (Chrome, Edge or Brave) and find “On startup”.';
  return [first, 'Remove the page the checkup found, and choose “Open the New Tab page”.',
    'Then check its extensions for anything you don’t recognise.'];
}

function hostsSteps(finding, ctx) {
  const host = str(dataOf(finding).hostname);
  const which = HOST_RE.test(host) ? `the line with ${host}` : 'the line the checkup found';
  const admin = 'Only an administrator can change this file, so look closer at how that line got there.';
  if (ctx && ctx.platform === 'win32') {
    return ['Click Start, type Notepad, right-click it and choose “Run as administrator”.',
      'Choose File > Open, type C:\\Windows\\System32\\drivers\\etc\\hosts and press Enter.',
      `Delete ${which}, then choose File > Save.`, admin];
  }
  const login = ctx && ctx.platform === 'linux' ? 'your password' : 'your Mac’s login password';
  const open = ctx && ctx.platform === 'linux' ? 'Open a terminal.' : 'Open Terminal (in Applications > Utilities).';
  return [open, `Type sudo nano /etc/hosts and press Return, then type ${login}.`,
    `Delete ${which}. Press Control-O, then Return to save, and Control-X to leave.`, admin];
}

function newExtIds(finding) {
  const added = Array.isArray(dataOf(finding).added) ? dataOf(finding).added : [];
  return added.map((e) => str(e).split(/[\\/]/).pop()).filter((id) => ID_RE.test(id));
}

function newExtSteps(finding, ctx) {
  const key = enterKey(ctx);
  const idList = newExtIds(finding).slice(0, 6);
  return [
    `In Chrome, type chrome://extensions and press ${key} (in Edge, edge://extensions; in Brave, brave://extensions).`,
    'Turn on “Developer mode” to see each extension’s ID.',
    idList.length ? `Remove the ones with these IDs, unless you added them: ${idList.join(', ')}.` : 'Remove the ones you didn’t add.',
    ADMIN_LINE,
  ];
}

// ---- Decisions ----

const L = (standard, city = standard) => ({ standard, city });
const keepOf = (item) => (item.finding && item.finding.markable ? { kind: 'mark' } : { kind: 'keep' });

function closerList(kind, b, ctx) {
  const key = enterKey(ctx);
  switch (kind) {
    case 'extension': return ['Do you remember adding it?', 'Does it need this much access for what it does?', 'Look it up: who publishes it, and do the reviews match what it does?'];
    case 'known-bad': return ['Do you remember adding it?', 'Look it up by name before you decide.', 'If it says “Installed by your administrator”, something with admin rights put it there.'];
    case 'miner': return ['Is the computer hot or slow while the browser is open?', 'Do you remember adding it?', 'If it says “Installed by your administrator”, something with admin rights put it there.'];
    case 'mining-page': return ['Did you set this start page yourself?', 'Check the browser’s extensions for one you don’t recognise: it may keep setting the page.'];
    case 'mining-hosts': return ['Did you, or someone who looks after this computer, add it on purpose?', 'Look for other mining software too: only an administrator can change this file.'];
    case 'hijack': return ['Did you choose this yourself?', 'Did you install anything just before it changed?', 'If it keeps coming back, an extension or a policy is setting it.'];
    case 'managed': {
      const list = ['Is this a work or school computer? Then this is normal, and its IT team can tell you more.',
        `In Chrome, type chrome://management and press ${key} to see who manages it.`];
      if (!ctx || ctx.platform === 'darwin') list.push('In System Settings, look for a device-management profile you don’t recognise.');
      return list;
    }
    case 'new-ext': return ['Look each one up by its ID.', 'Did you add an extension after the checkup first took stock?', 'An extension you didn’t add usually means other software put it there.'];
    default: return ['Does everything listed look like something you use?'];
  }
}

function decisions(item, ctx) {
  const f = (item && item.finding) || {};
  const kind = kindOf(f);
  const b = browserOf(f);
  const id = idOf(f);
  const closer = { id: 'closer', label: L('Look closer'), effect: { kind: 'closer', checklist: closerList(kind, b, ctx) } };
  // R6: a removing or trimming move on an item with the removal warning asks the runner to show it first.
  const alerting = isAlertingItem(item);
  const warn = (e) => (alerting ? { ...e, warning: true } : e);
  const removeEffect = (steps) => warn(f.fixable ? { kind: 'fix' } : { kind: 'note', note: 'remove', steps });
  const keep = (standard, city) => ({ id: 'keep', label: L(standard, city), effect: keepOf(item) });
  const remove = (standard, city, steps) => ({ id: 'remove', label: L(standard, city), effect: removeEffect(steps) });
  switch (kind) {
    case 'extension':
      return [
        keep('Keep it', 'Keep it'),
        { id: 'trim', label: L('Trim its access', 'Trim its reach'), effect: warn({ kind: 'note', note: 'trim', steps: trimSteps(b, id, ctx) }) },
        remove('Remove it', 'Drop it', removeSteps(b, id, ctx, kind)),
      ];
    case 'known-bad':
    case 'miner':
      return [closer, remove('Remove it', 'Drop it', removeSteps(b, id, ctx, kind)), keep('Keep it', 'Keep it')];
    case 'mining-page':
      return [closer, { id: 'reset', label: L('Reset start page'), effect: { kind: 'note', note: 'reset', steps: startupSteps(b, ctx) } }];
    case 'mining-hosts':
      return [closer, remove('Remove the line', 'Cut the line', hostsSteps(f, ctx))];
    case 'hijack':
      return [keep('I chose this', 'I chose this'), { id: 'reset', label: L('Reset it'), effect: { kind: 'note', note: 'reset', steps: resetSteps(b, f, ctx) } }, closer];
    case 'managed':
      return [keep('Work or school', 'Work or school'), closer];
    case 'many':
      return [keep('Keep them all', 'Keep the loadout'), { id: 'trim', label: L('Trim the list', 'Lighten the loadout'), effect: warn({ kind: 'note', note: 'trim', steps: manySteps(b, ctx) }) }];
    case 'legacy':
      return [keep('Keep them', 'Keep them'), remove('Remove them', 'Drop them', [openExtensions(SAFARI, '', ctx),
        'Select each old one and click “Uninstall”.',
        'If one isn’t listed: in Finder choose Go > Go to Folder, type ~/Library/Safari/Extensions and press Return, then move its .safariextz file to the Trash.'])];
    case 'blockers-off':
      return [keep('Leave it off', 'Leave it off'), { id: 'turn-on', label: L('Turn one on'), effect: { kind: 'note', note: 'turn-on', steps: [openExtensions(SAFARI, '', ctx), 'Tick a content blocker if you have one. If none is listed, you can leave this.'] } }];
    case 'new-ext':
      return [keep('I added these', 'I packed these'), closer, remove('Remove them', 'Drop them', newExtSteps(f, ctx))];
    default:
      return [keep('Looks right', 'Looks right'), closer];
  }
}

// ---- Research ----

function whatOf(item, kind, b, ctx) {
  const f = item.finding || {};
  const d = dataOf(f);
  // Only this add-on's own verified entry (contract.js makerFor), never another program's.
  const own = makerFor(f);
  const made = own && own.verified && own.what ? own : null;
  const pm = b.store && PASSWORD_MANAGERS[idOf(f)];
  const B = b.name || words(ctx, 'Your browser', 'Your browser');
  switch (kind) {
    case 'extension':
      if (made) return made.what;
      if (pm) return words(ctx, `Its ID matches ${pm}’s password manager in the Chrome Web Store. A password manager needs this access to fill in your passwords.`,
        `Its ID matches ${pm}’s password keeper in the store. It needs this reach to fill in your passwords.`);
      return words(ctx, 'Unknown maker. Broad access is normal for tools like ad blockers and password managers; if you don’t know this one, look it up.',
        'Unknown maker. Big reach is normal for blockers and password keepers; if you don’t know this one, look it up.');
    case 'known-bad':
      return /malicious/.test(str(f.code) + str(d.check))
        ? words(ctx, 'Its name is on a list of known harmful extensions.', 'Its name is on a list of known bad gear.')
        : words(ctx, 'Its name matches add-ons known for showing ads and tracking what you browse.', 'Its name matches gear known for pushing ads and tracking where you browse.');
    case 'miner':
      return words(ctx, 'The checkup found mining code in it: it uses your computer’s power to make money for someone else.',
        'It holds coin-digging code: it runs on your machine’s power for someone else.');
    case 'mining-page':
      return words(ctx, `${B} opens a page that mines cryptocurrency whenever it starts.`, `${B} opens a coin-digging page whenever it starts.`);
    case 'mining-hosts':
      return words(ctx, 'Your hosts file (a system list of web addresses) sends a mining service’s address to another server. Only an administrator can change that file.',
        'Your hosts file (the machine’s address book) sends a coin-digging service somewhere else. Only an administrator can change that file.');
    case 'hijack':
      return /search_engine/.test(str(f.code) + str(d.check))
        ? words(ctx, `${B} searches with an engine that isn’t one of the usual ones. Software sometimes changes this without asking.`, `${B} searches with an unusual engine. Software sometimes swaps it without asking.`)
        : words(ctx, `${B} opens to a page that isn’t one of the usual start pages. Software sometimes changes this without asking.`, `${B} opens to an unusual start page. Software sometimes swaps it without asking.`);
    case 'managed':
      return words(ctx, 'Chrome has policy settings. That’s normal on a work or school computer; on your own computer, something set them.',
        'Chrome takes orders from a policy. Normal on a work or school machine; on your own, something set it.');
    case 'many':
      return words(ctx, 'Each add-on you don’t use is one more thing that can change, or slow the browser down.', 'Every piece of gear you don’t use is extra weight, and one more thing that can change.');
    case 'legacy':
      return words(ctx, 'An old style of Safari extension that Safari no longer supports or checks.', 'Old Safari gear that Safari no longer supports or checks.');
    case 'blockers-off':
      return words(ctx, 'Content blockers stop ads and trackers in Safari. This one is optional.', 'Content blockers stop ads and trackers in Safari. Optional gear.');
    case 'new-ext': {
      const n = Array.isArray(d.added) ? d.added.length : 0;
      return words(ctx, `${n} extension${n === 1 ? '' : 's'} appeared since the checkup first took stock. Only their IDs are known.`,
        `${n} new piece${n === 1 ? '' : 's'} of gear since the first sweep. Only their IDs are known.`);
    }
    default:
      return made ? made.what : '';
  }
}

function lookups(item, kind, b) {
  const f = item.finding || {};
  const d = dataOf(f);
  const out = [];
  const id = idOf(f);
  const name = clip(nameOf(f), 120);
  if (kind === 'extension' || kind === 'known-bad' || kind === 'miner') {
    if (id && b.store) out.push({ kind: 'lookup', source: 'chrome-web-store', query: id });
    else if (name) {
      const what = b.id === 'firefox' ? 'Firefox add-on' : b.name ? `${b.name} extension` : 'browser extension';
      out.push({ kind: 'lookup', source: 'web', query: `"${name}" ${what}` });
    }
  } else if (kind === 'new-ext') {
    for (const x of newExtIds(f).slice(0, MAX_LOOKUPS)) out.push({ kind: 'lookup', source: 'chrome-web-store', query: x });
  } else if (kind === 'hijack') {
    const v = clip(d.homepage || d.engine, 120);
    if (v) out.push({ kind: 'lookup', source: 'web', query: `"${v}"` });
  }
  return out;
}

function research(item, ctx) {
  const it = item || {};
  const f = it.finding || {};
  const kind = kindOf(f);
  const b = browserOf(f);
  const rows = ctx && typeof ctx.evidenceRows === 'function' ? ctx.evidenceRows(f, { mode: ctx.mode }) : [];
  const what = whatOf(it, kind, b, ctx);
  const links = [];
  if (!(ctx && ctx.practice) && !it.practice) links.push(...lookups(it, kind, b));
  if (kind === 'managed' && (!ctx || ctx.platform === 'darwin')) links.push({ kind: 'settings', pane: 'profiles' });
  links.push({ kind: 'lesson', concept: isMining(kind) ? 'wifi-and-mining' : 'browser-add-ons' });
  return { rows: Array.isArray(rows) ? rows : [], what, links };
}

// ---- Render ----

function headingOf(f, kind, b, ctx) {
  const B = b.name || words(ctx, 'Browser', 'Browser');
  switch (kind) {
    case 'extension': case 'known-bad': case 'miner': return nameOf(f);
    case 'mining-page': return words(ctx, `${B} start page`, `${B} start page`);
    case 'mining-hosts': return words(ctx, 'Hosts file entry', 'Address book entry');
    case 'hijack': return /search_engine/.test(str(f.code) + str(dataOf(f).check)) ? `${B} ${words(ctx, 'search engine', 'search engine')}` : `${B} ${words(ctx, 'start page', 'start page')}`;
    case 'managed': return words(ctx, 'Chrome policy', 'Chrome orders');
    case 'many': return words(ctx, 'Lots of add-ons', 'A heavy loadout');
    case 'legacy': return words(ctx, 'Old Safari extensions', 'Old Safari gear');
    case 'blockers-off': return words(ctx, 'Safari content blockers', 'Safari content blockers');
    case 'new-ext': return words(ctx, 'New extensions', 'New gear');
    default: return str(f.title);
  }
}

function fact(esc, label, value, mono = true) {
  return `<div class="lo-fact"><dt>${esc(label)}</dt><dd${mono ? ' class="lo-mono"' : ''}>${esc(clip(value))}</dd></div>`;
}

function body(f, kind, ctx) {
  const esc = ctx.esc;
  const d = dataOf(f);
  if (kind === 'extension' || kind === 'known-bad' || kind === 'miner') {
    const list = powers(d.permissions, ctx.mode);
    let html = '';
    if (list.length) {
      html += `<p class="lo-label">${esc(words(ctx, 'What it can do', 'Its powers'))}</p><ul class="lo-powers">`
        + list.map((p) => `<li class="lo-power lo-power--${p.level}${p.raw ? ' lo-mono' : ''}">${esc(p.text)}</li>`).join('') + '</ul>';
    } else if (kind === 'extension') {
      html += `<p class="lo-none">${esc(words(ctx, 'Asks for no special access', 'No special powers'))}</p>`;
    }
    if (kind === 'miner' && d.evidence) html += `<dl class="lo-facts">${fact(esc, words(ctx, 'What matched', 'What matched'), d.evidence)}</dl>`;
    return html;
  }
  if (kind === 'hijack') {
    const search = /search_engine/.test(str(f.code) + str(d.check));
    return `<dl class="lo-facts">${fact(esc, search ? words(ctx, 'Searches with', 'Searches with') : words(ctx, 'Opens to', 'Opens to'), search ? d.engine : d.homepage)}</dl>`;
  }
  if (kind === 'mining-page') return `<dl class="lo-facts">${fact(esc, words(ctx, 'Opens', 'Opens'), d.url)}${d.profile ? fact(esc, words(ctx, 'Profile', 'Profile'), d.profile) : ''}</dl>`;
  if (kind === 'mining-hosts') return `<dl class="lo-facts">${fact(esc, words(ctx, 'Address', 'Address'), d.hostname)}${fact(esc, words(ctx, 'Sent to', 'Sent to'), d.address)}</dl>`;
  if (kind === 'many') return Number.isFinite(d.count) ? `<p class="lo-count"><span class="lo-count__n">${esc(String(d.count))}</span> ${esc(words(ctx, 'add-ons', 'pieces of gear'))}</p>` : '';
  if (kind === 'legacy' && Array.isArray(d.extensions)) {
    return `<ul class="lo-names">${d.extensions.slice(0, 12).map((n) => `<li>${esc(clip(n, 120))}</li>`).join('')}</ul>`;
  }
  if (kind === 'new-ext' && Array.isArray(d.added)) {
    return `<ul class="lo-names lo-mono">${d.added.slice(0, 12).map((n) => `<li>${esc(clip(str(n).split(/[\\/]/).pop(), 80))}</li>`).join('')}</ul>`;
  }
  return '';
}

function render(view, ctx) {
  const v = view || {};
  const item = v.item || {};
  const f = item.finding || {};
  const kind = kindOf(f);
  const b = browserOf(f);
  const esc = ctx.esc;
  const r = v.research || {};
  const tag = b.name || (isMining(kind) ? words(ctx, 'Browser', 'Browser') : '');
  const say = v.step && v.step.say ? (ctx.mode === 'city' ? v.step.say.city : v.step.say.standard) : '';
  return `<article class="lo-card lo-card--${esc(kind)}">`
    + '<header class="lo-head">'
    + (tag ? `<span class="lo-tag">${esc(tag)}</span>` : '')
    + `<h3 class="lo-name">${esc(clip(headingOf(f, kind, b, ctx), 160))}</h3>`
    + '</header>'
    + (item.unfinished === true ? `<p class="lo-unfinished">${esc(words(ctx, 'This check didn’t finish, so this may not be everything.', 'This sweep didn’t finish, so the list may be short.'))}</p>` : '')
    + (r.what ? `<p class="lo-what">${esc(r.what)}</p>` : '')
    + body(f, kind, ctx)
    + (say ? `<p class="lo-coach">${esc(say)}</p>` : '')
    + '</article>';
}

// ---- Summary ----

function summary(results, ctx) {
  const n = { keep: 0, trim: 0, remove: 0, closer: 0 };
  for (const r of Array.isArray(results) ? results : []) {
    const id = r && (typeof r.decision === 'string' ? r.decision : (r.decision && r.decision.id) || r.id);
    if (id === 'keep') n.keep += 1;
    else if (id === 'trim' || id === 'reset' || id === 'turn-on') n.trim += 1;
    else if (id === 'remove') n.remove += 1;
    else if (id === 'closer') n.closer += 1;
  }
  const total = n.keep + n.trim + n.remove + n.closer;
  if (!total) return `<p class="lo-summary">${words(ctx, 'No add-ons decided in this mission yet.', 'No gear sorted on this run yet.')}</p>`;
  let html = `<p class="lo-summary">${words(ctx,
    `You kept ${n.keep}, chose to trim ${n.trim}, and chose to remove ${n.remove}.`,
    `Gear kept ${n.keep} · to trim ${n.trim} · to remove ${n.remove}.`)}</p>`;
  if (n.closer) html += `<p class="lo-summary">${words(ctx, `${n.closer} to look closer at.`, `${n.closer} to look closer at.`)}</p>`;
  if (n.trim || n.remove) {
    html += `<p class="lo-summary lo-summary--note">${words(ctx,
      'Trimming and removing happen in the browser, with the steps on each card. The next checkup shows whether each change took.',
      'Trims and drops happen in the browser, with the steps on each card. The next sweep shows whether each one took.')}</p>`;
  }
  return html;
}

// ---- Practice: made-up add-ons ----

function practiceItem(key, finding) {
  const f = { category: 'security', ...finding };
  return { key, severity: f.severity, finding: f, findings: [f], seen_in: [f.module], marked: false, held: false, removal_alert: !!f.removal_alert, practice: true };
}

const practice = {
  items: [
    practiceItem('practice:loadout:password-manager', {
      module: 'chrome_extensions', code: 'security.chrome_extensions.broad_permissions', severity: 'warning', removal_alert: true,
      title: 'Extension with broad permissions: KeyKeeper Passwords',
      data: { check: 'broad_permissions', extension: 'KeyKeeper Passwords', extension_id: 'aaaabbbbccccddddeeeeffffgggghhhh', permissions: ['<all_urls>', 'tabs', 'scripting', 'storage'] },
      made_by: [{ subject: 'KeyKeeper Passwords', name: 'KeyKeeper (made up)', verified: true, how: 'practice', what: 'KeyKeeper Passwords: a password manager that fills in your passwords on the sites you use.' }],
    }),
    practiceItem('practice:loadout:coupon', {
      module: 'browser_extension_audit', code: 'security.browser_extension_audit.excessive_permissions', severity: 'warning', removal_alert: true,
      title: 'Extension with broad access: Coupon Hunter Deals',
      data: { check: 'excessive_permissions', browser: 'Chrome', extension: 'Coupon Hunter Deals', extension_id: 'iiiijjjjkkkkllllmmmmnnnnoooopppp', permissions: ['<all_urls>', 'cookies', 'tabs', 'webRequest'] },
    }),
    practiceItem('practice:loadout:theme', {
      module: 'chrome_extensions', code: null, severity: 'info',
      title: 'Midnight Sky Theme',
      data: { check: 'theme', extension: 'Midnight Sky Theme', extension_id: 'ppppooooaaaabbbbccccddddeeeeffff', permissions: [] },
      made_by: [{ subject: 'Midnight Sky Theme', name: 'Sky Themes (made up)', verified: true, how: 'practice', what: 'Midnight Sky Theme: changes the browser’s colours. Nothing else.' }],
    }),
  ],
  script: [
    { item: 0, expect: 'keep', say: {
      standard: 'A password manager can read every site: it has to, to fill in your passwords there. You know it and it needs that access, so keep it.',
      city: 'This gear keeps your passwords. It reaches every site because it fills them in there. You know it and it needs the reach: keep it.' } },
    { item: 1, expect: 'remove', say: {
      standard: 'A coupon add-on from an unknown maker, reading every site and the cookies that keep you signed in. You don’t remember adding it, and it doesn’t need that much: remove it.',
      city: 'Coupon gear from an unknown maker, reaching every site and the cookies that keep you signed in. You never packed it, and it doesn’t need that reach: drop it.' } },
    { item: 2, expect: 'keep', say: {
      standard: 'A theme only changes colours and asks for no special access. Keep it.',
      city: 'A theme only repaints the browser. No special powers: keep it.' } },
  ],
};

export default {
  type: 'loadout',
  title: { standard: 'Browser add-ons', city: 'The Loadout' },
  concepts: ['browser-add-ons', 'wifi-and-mining'],
  covers: [
    { module: 'chrome_extensions' },
    { module: 'safari_extensions' },
    { module: 'browser_extension_audit' },
    { module: 'browser_hijack_check' },
    { module: 'browser_cryptojacking_check' },
    { module: 'security_baseline_diff', codes: ['security.security_baseline_diff.new_browser_extension'] },
  ],
  decisions,
  research,
  practice,
  render,
  summary,
  // Exposed for tests and the preview.
  powers,
  browserOf,
  kindOf,
};
