// Research done for the person: what is already known about an item, and the
// links to check it, built only from fixed templates (spec: "Research").
//
// Games return link INTENTS (contract.js LINK_KINDS); nothing from scan data
// is ever used as a URL. Values go into a template, URL-encoded, after control
// and bidi characters are dropped.
//
//   paneUrl(pane, platform) -> 'x-apple.systempreferences:…' | 'ms-settings:…' | null
//   lookupUrl(source, query) -> 'https://…' | null
//   resolveLink(intent, { mode, platform }) -> { kind, label, url, text, pane?, concept? } | null
//       city mode: a look-up is text to search on another device (url: null)
//   resolveLinks(intents, ctx) -> the resolved ones, unknown or URL-carrying intents dropped
//   whatOf(finding) -> the verified program's description, else 'Unknown maker'
//   unfinishedModules(doc) -> Set of checks that ran but didn't finish
//   assemble(game, item, ctx, { unfinished }) -> { rows, what, links, unfinished }
import '../not-checked.js';
import { SETTINGS_PANES, LOOKUP_SOURCES, LINK_KINDS } from './contract.js';

const NC = globalThis.NotChecked;
const MAC = 'x-apple.systempreferences:';
const SEC = `${MAC}com.apple.preference.security`;

// Every SETTINGS_PANES entry, on macOS (System Settings, macOS 13 and later)
// and Windows (ms-settings: URIs). The macOS ids are the ones setting-panes.js
// verified where they overlap; Privacy_* anchors are TCC's revealElementKeyName.
export const PANE_URLS = Object.freeze({
  'login-items': { darwin: `${MAC}com.apple.LoginItems-Settings.extension`, win32: 'ms-settings:startupapps' },
  'privacy-accessibility': { darwin: `${SEC}?Privacy_Accessibility`, win32: 'ms-settings:privacy' },
  'privacy-input-monitoring': { darwin: `${SEC}?Privacy_ListenEvent`, win32: 'ms-settings:privacy' },
  'privacy-screen-recording': { darwin: `${SEC}?Privacy_ScreenCapture`, win32: 'ms-settings:privacy-graphicscaptureprogrammatic' },
  'privacy-camera': { darwin: `${SEC}?Privacy_Camera`, win32: 'ms-settings:privacy-webcam' },
  'privacy-microphone': { darwin: `${SEC}?Privacy_Microphone`, win32: 'ms-settings:privacy-microphone' },
  'privacy-full-disk': { darwin: `${SEC}?Privacy_AllFiles`, win32: 'ms-settings:privacy-broadfilesystemaccess' },
  'privacy-location': { darwin: `${SEC}?Privacy_LocationServices`, win32: 'ms-settings:privacy-location' },
  'privacy-automation': { darwin: `${SEC}?Privacy_Automation`, win32: 'ms-settings:privacy' },
  network: { darwin: `${MAC}com.apple.Network-Settings.extension`, win32: 'ms-settings:network-status' },
  firewall: { darwin: `${MAC}com.apple.Network-Settings.extension?Firewall`, win32: 'ms-settings:windowsdefender' },
  sharing: { darwin: `${MAC}com.apple.Sharing-Settings.extension`, win32: 'ms-settings:remotedesktop' },
  'software-update': { darwin: `${MAC}com.apple.Software-Update-Settings.extension`, win32: 'ms-settings:windowsupdate' },
  filevault: { darwin: `${SEC}?FileVault`, win32: 'ms-settings:deviceencryption' },
  'lock-screen': { darwin: `${MAC}com.apple.Lock-Screen-Settings.extension`, win32: 'ms-settings:signinoptions' },
  'users-groups': { darwin: `${MAC}com.apple.Users-Groups-Settings.extension`, win32: 'ms-settings:otherusers' },
  storage: { darwin: `${MAC}com.apple.settings.Storage`, win32: 'ms-settings:storagesense' },
  battery: { darwin: `${MAC}com.apple.Battery-Settings.extension`, win32: 'ms-settings:batterysaver' },
  'extensions-browser': { darwin: null, win32: null },
  profiles: { darwin: `${MAC}com.apple.Profiles-Settings.extension`, win32: 'ms-settings:workplace' },
  'time-machine': { darwin: `${MAC}com.apple.Time-Machine-Settings.extension`, win32: 'ms-settings:backup' },
  'apple-id': { darwin: `${MAC}com.apple.systempreferences.AppleIDSettings`, win32: 'ms-settings:yourinfo' },
  vpn: { darwin: `${MAC}com.apple.NetworkExtensionSettingsUI.NESettingsUIExtension`, win32: 'ms-settings:network-vpn' },
  dns: { darwin: `${MAC}com.apple.Network-Settings.extension?DNS`, win32: 'ms-settings:network-status' },
  'startup-apps': { darwin: `${MAC}com.apple.LoginItems-Settings.extension`, win32: 'ms-settings:startupapps' },
  'windows-security': { darwin: SEC, win32: 'ms-settings:windowsdefender' },
  'windows-update': { darwin: `${MAC}com.apple.Software-Update-Settings.extension`, win32: 'ms-settings:windowsupdate' },
  'windows-privacy': { darwin: SEC, win32: 'ms-settings:privacy' },
  'windows-storage': { darwin: `${MAC}com.apple.settings.Storage`, win32: 'ms-settings:storagesense' },
  'windows-firewall': { darwin: `${MAC}com.apple.Network-Settings.extension?Firewall`, win32: 'ms-settings:windowsdefender' },
  'windows-apps': { darwin: null, win32: 'ms-settings:appsfeatures' },
  'privacy-contacts': { darwin: `${SEC}?Privacy_Contacts`, win32: 'ms-settings:privacy-contacts' },
  'screen-time': { darwin: `${MAC}com.apple.Screen-Time-Settings.extension`, win32: 'ms-settings:family-group' },
  'windows-bitlocker': { darwin: `${SEC}?FileVault`, win32: 'ms-settings:deviceencryption' },
  'windows-signin': { darwin: `${MAC}com.apple.Lock-Screen-Settings.extension`, win32: 'ms-settings:signinoptions' },
  'windows-backup': { darwin: `${MAC}com.apple.Time-Machine-Settings.extension`, win32: 'ms-settings:backup' },
  'windows-findmydevice': { darwin: `${MAC}com.apple.systempreferences.AppleIDSettings`, win32: 'ms-settings:findmydevice' },
  'windows-power': { darwin: `${MAC}com.apple.Battery-Settings.extension`, win32: 'ms-settings:powersleep' },
});

// R5: a settings intent's `permission` picks the exact Windows privacy page.
// Keyring's key ids and the kTCCService names both work.
export const WINDOWS_PERMISSION_PANES = Object.freeze({
  camera: 'ms-settings:privacy-webcam', microphone: 'ms-settings:privacy-microphone', location: 'ms-settings:privacy-location',
  contacts: 'ms-settings:privacy-contacts', screen: 'ms-settings:privacy-graphicscaptureprogrammatic',
  'full-disk': 'ms-settings:privacy-broadfilesystemaccess', keyboard: 'ms-settings:privacy', accessibility: 'ms-settings:privacy',
  automation: 'ms-settings:privacy', 'screen-time': 'ms-settings:family-group',
  kTCCServiceCamera: 'ms-settings:privacy-webcam', kTCCServiceMicrophone: 'ms-settings:privacy-microphone',
  kTCCServiceAddressBook: 'ms-settings:privacy-contacts', kTCCServiceScreenCapture: 'ms-settings:privacy-graphicscaptureprogrammatic',
  kTCCServiceSystemPolicyAllFiles: 'ms-settings:privacy-broadfilesystemaccess', kTCCServiceListenEvent: 'ms-settings:privacy',
  kTCCServiceAccessibility: 'ms-settings:privacy', kTCCServiceAppleEvents: 'ms-settings:privacy',
});

// Panes with no settings page to open, and why (the game says what to do instead).
export const NO_PANE = Object.freeze({
  'extensions-browser': {
    darwin: 'A browser’s add-ons live in the browser itself; its pages (chrome://extensions) can’t be opened from another app.',
    win32: 'A browser’s add-ons live in the browser itself; its pages (chrome://extensions) can’t be opened from another app.',
  },
  'windows-apps': { darwin: 'macOS has no settings page listing installed apps; they are in the Applications folder.' },
});

// What a settings button says. City mode: game words, no page names needed.
const PANE_LABEL = {
  'login-items': 'Login Items', 'startup-apps': 'Startup apps', 'privacy-accessibility': 'Accessibility',
  'privacy-input-monitoring': 'Input Monitoring', 'privacy-screen-recording': 'Screen Recording', 'privacy-camera': 'Camera',
  'privacy-microphone': 'Microphone', 'privacy-full-disk': 'Full Disk Access', 'privacy-location': 'Location Services',
  'privacy-automation': 'Automation', network: 'Network', firewall: 'Firewall', 'windows-firewall': 'Firewall', sharing: 'Sharing',
  'software-update': 'Software Update', 'windows-update': 'Windows Update', filevault: 'FileVault', 'lock-screen': 'Lock Screen',
  'users-groups': 'Users', storage: 'Storage', 'windows-storage': 'Storage', battery: 'Battery', profiles: 'Profiles',
  'time-machine': 'Backups', 'apple-id': 'Your account', vpn: 'VPN', dns: 'DNS', 'windows-security': 'Security',
  'privacy-contacts': 'Contacts', 'screen-time': 'Screen Time', 'windows-bitlocker': 'Device encryption',
  'windows-signin': 'Sign-in', 'windows-backup': 'Backup', 'windows-findmydevice': 'Find my device', 'windows-power': 'Power',
  'windows-privacy': 'Privacy', 'windows-apps': 'Apps',
};

const own = (o, k) => Object.prototype.hasOwnProperty.call(o, k);

export function paneUrl(pane, platform) {
  if (!own(PANE_URLS, pane)) return null;
  const p = PANE_URLS[pane];
  return platform === 'darwin' || platform === 'win32' ? p[platform] || null : null;
}

const MAX_QUERY = 120;
// Drop control, format and separator characters (newlines, bidi overrides,
// zero-width), collapse spaces, cap the length.
export function cleanQuery(q) {
  return String(q == null ? '' : q).replace(/[\p{Cc}\p{Cf}\p{Zl}\p{Zp}]/gu, ' ').replace(/\s+/g, ' ').trim().slice(0, MAX_QUERY);
}

const SEARCH = 'https://duckduckgo.com/?q=';
const CHROME_ID = /^[a-p]{32}$/;
const quoted = (q) => `"${q.replace(/"/g, '')}"`;
const search = (q, site = '') => `${SEARCH}${encodeURIComponent(site ? `site:${site} ${quoted(q)}` : quoted(q))}`;

export function lookupUrl(source, query) {
  if (!LOOKUP_SOURCES.includes(source)) return null;
  const q = cleanQuery(query);
  if (!q) return null;
  if (source === 'chrome-web-store') return CHROME_ID.test(q) ? `https://chromewebstore.google.com/detail/${q}` : search(q);
  if (source === 'apple-support') return search(q, 'support.apple.com');
  if (source === 'microsoft-support') return search(q, 'support.microsoft.com');
  // 'maker-site': program_descriptions.json lists no sites yet, so a search
  // for the verified maker's name; 'web': the exact quoted name.
  return search(q);
}

const LOOKUP_LABEL = {
  web: { standard: 'Search the web', city: 'Search the name' },
  'apple-support': { standard: 'Search Apple Support', city: 'Search the maker’s help' },
  'microsoft-support': { standard: 'Search Microsoft Support', city: 'Search the maker’s help' },
  'chrome-web-store': { standard: 'See it in the Chrome Web Store', city: 'Look it up in the store' },
  'maker-site': { standard: 'Search for the maker', city: 'Search the maker' },
};

export function resolveLink(l, { mode = 'standard', platform = null } = {}) {
  if (!l || typeof l !== 'object' || !LINK_KINDS.includes(l.kind) || 'href' in l || 'url' in l) return null;
  const city = mode === 'city';
  if (l.kind === 'settings') {
    if (!SETTINGS_PANES.includes(l.pane)) return null;
    const perm = typeof l.permission === 'string' && own(WINDOWS_PERMISSION_PANES, l.permission) ? WINDOWS_PERMISSION_PANES[l.permission] : null;
    const url = platform === 'win32' && perm ? perm : paneUrl(l.pane, platform);
    const name = PANE_LABEL[l.pane] || 'Settings';
    const label = { standard: `Open ${name} settings`, city: 'Open the settings' };
    return { kind: 'settings', pane: l.pane, url, label, text: url ? '' : (NO_PANE[l.pane] && NO_PANE[l.pane][platform]) || '',
      ...(l.warning === true ? { warning: true } : {}) };
  }
  if (l.kind === 'lookup') {
    const q = cleanQuery(l.query);
    if (!q || !LOOKUP_SOURCES.includes(l.source)) return null;
    const label = LOOKUP_LABEL[l.source] || LOOKUP_LABEL.web;
    // A watched computer keeps browser history: in city mode the search is
    // words to type somewhere else, never a link.
    if (city) return { kind: 'lookup', source: l.source, url: null, label, text: `Search for “${q}” on another device.` };
    return { kind: 'lookup', source: l.source, url: lookupUrl(l.source, q), label, text: '' };
  }
  if (typeof l.concept !== 'string' || !l.concept) return null;
  return { kind: 'lesson', concept: l.concept, url: null, label: { standard: 'Learn how to read this', city: 'Training: how to read this' }, text: '' };
}

export function resolveLinks(links, ctx = {}) {
  return (Array.isArray(links) ? links : []).map((l) => resolveLink(l, ctx)).filter(Boolean);
}

export function whatOf(finding) {
  const mb = finding && Array.isArray(finding.made_by) ? finding.made_by.filter(Boolean) : [];
  const known = mb.find((m) => m.verified === true && typeof m.what === 'string' && m.what.trim());
  return known ? known.what.trim() : 'Unknown maker';
}

export const UNFINISHED_LINE = 'This check didn’t finish, so it may have missed something here.';

export function unfinishedModules(doc) {
  return new Set(NC.notCheckedParts(doc).unfinished.map((x) => x.name));
}

// One item's research: the game's own, checked and resolved. A game that
// throws gives the evidence rows and no links rather than breaking the screen.
export function assemble(game, item, ctx, { unfinished = new Set() } = {}) {
  let r = null;
  try { r = game && typeof game.research === 'function' ? game.research(item, ctx) : null; } catch (_) { r = null; }
  const f = (item && item.finding) || {};
  let rows = r && Array.isArray(r.rows) ? r.rows : null;
  if (!rows) { try { rows = ctx.evidenceRows(f, { mode: ctx.mode }) || []; } catch (_) { rows = []; } }
  const what = r && typeof r.what === 'string' && r.what.trim() ? r.what : whatOf(f);
  const mods = (item && Array.isArray(item.seen_in) ? item.seen_in : [f.module]).filter(Boolean);
  const set = unfinished instanceof Set ? unfinished : new Set(unfinished || []);
  return { rows, what, links: resolveLinks(r && r.links, ctx), unfinished: mods.some((m) => set.has(m)) ? UNFINISHED_LINE : '' };
}
