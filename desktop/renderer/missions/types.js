// Little missions: which kind of thing each finding is about (its type), and
// the missions a scan becomes (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md).
//
//   TYPE_TITLES[type] -> { standard, city }
//   BASE_COVERS[type] -> [{ module, codes? }]   the spec's table, macOS and Windows
//   ODD_JOBS                                   modules that can warn on macOS and go to Odd Jobs on purpose
//   WIN_ODD_JOBS                               the same on Windows
//   buildTable(games) -> table                 a registered game's `covers` replaces its type's entry
//   doubleClaims(table) -> [problem]            two types claiming the same (module, code)
//   typeOf(finding, table) -> type id           info -> 'notes'; unmapped -> 'simple'
//   groupMissions(doc, { mode, table }) -> Mission[]
//   missionCounts(missions) -> { todo, notes }  equal to NotChecked.scanCounts(doc, { mode }).todo / .notes
//   missionRows(missions) -> Row[]             a district's list: a type's parts folded, notes batches as one row
//
// Mission = { id, type, district, severity, items, title: {standard, city}, part, of, notes }
// Item    = a NotChecked.displayItems item + { removal_alert }
//
// Built only from NotChecked.displayItems, so a mission never counts anything
// the list doesn't. Pure; no DOM, no storage.
import { TYPE_IDS, claimConflicts, isMonitoringFinding, isAlertingItem } from './contract.js';
import { districtIdFor, DISTRICTS, OUTSKIRTS } from '../game/findings-to-city.js';

const NC = globalThis.NotChecked;

export const MAX_ITEMS = 4;
export const NOTES_BATCH = 5;

export const TYPE_TITLES = Object.freeze({
  door: { standard: 'Things that start on their own', city: 'The Door' },
  keyring: { standard: 'Apps with powerful access', city: 'The Keyring' },
  loadout: { standard: 'Browser add-ons', city: 'The Loadout' },
  seal: { standard: 'App seals', city: 'Seal Check' },
  switchboard: { standard: 'Network lines', city: 'The Switchboard' },
  locker: { standard: 'Suspicious files', city: 'The Evidence Locker' },
  locks: { standard: 'Settings and locks', city: 'Lock Run' },
  junkyard: { standard: 'Storage and clutter', city: 'The Junkyard' },
  notes: { standard: 'Good to know', city: 'Signal or Noise' },
  simple: { standard: 'Other', city: 'Odd Jobs' },
});

const whole = (...mods) => mods.map((module) => ({ module }));
const SBD = 'security.security_baseline_diff.';

// The spec's table. A module listed whole and also with codes under another
// type: the codes win for those findings (firewall "off" -> Lock Run).
export const BASE_COVERS = Object.freeze({
  door: [
    ...whole('launch_agent_audit', 'launchd_persistence_audit', 'login_items_cleanup', 'login_items', 'scheduled_tasks_audit',
      'cron_jobs_audit', 'startup_optimizer', 'startup_auditor', 'ai_worm_persistence', 'crypto_miner_persistence', 'kext_audit',
      'kernel_extensions_audit', 'system_extensions_check', 'system_extensions',
      'win_autoruns_audit', 'win_scheduled_tasks', 'win_scheduled_tasks_security', 'win_startup',
      'win_startup_programs_audit', 'win_services_audit', 'win_services_security_audit'),
    { module: 'security_baseline_diff', codes: [`${SBD}new_persistence`] },
  ],
  keyring: whole('app_permissions', 'privacy_permissions_audit', 'accessibility_permissions', 'keylogger_indicators',
    'screen_time_audit', 'location_services'),
  loadout: [
    ...whole('chrome_extensions', 'safari_extensions', 'browser_extension_audit', 'browser_hijack_check', 'browser_cryptojacking_check'),
    { module: 'security_baseline_diff', codes: [`${SBD}new_browser_extension`] },
  ],
  seal: [
    ...whole('code_signature_audit', 'gatekeeper_quarantine_check', 'suspicious_processes', 'certificate_audit', 'certificate_trust_audit'),
    { module: 'win_suspicious_processes', codes: ['security.win_suspicious_processes.suspicious_path', 'security.win_suspicious_processes.no_file_path'] },
  ],
  switchboard: [
    ...whole('firewall_rules_audit', 'open_ports_scan', 'network_connections_monitor', 'suspicious_connections',
      'dns_config', 'dns_poisoning_check', 'dns_over_https_check', 'hosts_file_check', 'network_proxy', 'network_proxy_check',
      'network_proxy_detect', 'remote_login_check', 'sharing_preferences_audit', 'sharing_services', 'router_security_audit',
      'wifi_security_audit', 'vpn_leak_check', 'airdrop_config', 'airdrop_security_check',
      'win_firewall_rules_audit', 'win_hosts_file', 'win_hosts_file_check', 'win_proxy_detect', 'win_rdp_check',
      'win_remote_access_audit', 'win_network_shares_audit', 'win_dns_config'),
    { module: 'security_baseline_diff', codes: [`${SBD}new_listening_port`] },
    // A hosts-file line found by the mining check is a line in the address book.
    { module: 'browser_cryptojacking_check', checks: ['mining_hosts_entry'] },
  ],
  locker: whole('ai_worm_filesystem', 'ai_worm_iocs', 'ai_worm_git_ssh', 'ai_worm_lateral', 'ai_worm_network', 'ai_threat_indicators',
    'malware_scan_indicators', 'cryptojacking_iocs', 'crypto_miner_detect', 'rootkit_check',
    'win_malware_indicators', 'win_crypto_miner_detect', 'win_rootkit_check'),
  // (win_suspicious_processes' harmful programs: the Locker game claims them by code.)
  locks: [
    ...whole('automatic_updates', 'update_checker', 'encryption_check', 'filevault_recovery', 'screen_lock_check', 'lock_screen_check',
      'find_my_mac_check', 'guest_account_check', 'firmware_password', 'login_password_policy', 'antivirus_status',
      'macos_version_support', 'macos_eol_check', 'backup_status', 'time_machine_check', 'session_revocation_scan',
      'appleid_security_check',
      'win_defender', 'win_defender_deep_check', 'win_antivirus_status', 'win_bitlocker', 'win_bitlocker_check', 'win_firewall',
      'win_updates', 'win_windows_update_status', 'win_uac_check', 'win_autorun', 'win_local_admin_audit', 'win_credential_manager_audit'),
    ...whole('firewall_audit', 'clamav_scanner', 'browser_privacy_check', 'default_browser'),
    { module: 'firewall_rules_audit', codes: ['security.firewall_rules_audit.alf_', 'security.firewall_rules_audit.stealth_'] },
    { module: 'rootkit_check', codes: ['security.rootkit_check.sip_disabled'] },
    { module: 'win_rootkit_check', codes: ['security.win_rootkit_check.secure_boot_disabled'] },
    { module: 'win_malware_indicators', codes: ['security.win_malware_indicators.safe_mode_disabled'] },
    { module: 'security_baseline_diff', codes: [`${SBD}protection_disabled`] },
  ],
  junkyard: whole('storage_cleanup', 'large_files_finder', 'library_cache_cleanup', 'browser_cache_cleanup', 'trash_cleanup',
    'docker_cleanup', 'xcode_cleanup', 'mail_attachment_cleanup', 'crash_log_analyzer', 'app_crash_analyzer',
    'resource_hog_identifier', 'system_log_errors', 'process_scanner', 'temp_file_scanner',
    'win_disk_cleanup', 'win_temp_cleanup', 'win_temp_files', 'win_temp_files_cleanup', 'win_bloatware', 'win_disk_space'),
  notes: [],
  simple: [],
});

// Checks that can warn on macOS and go to Odd Jobs on purpose: hardware,
// system health and one-off settings with no mini-game of their own, and the
// two monitoring checks (held in city mode; in standard mode their own
// actions, with the removal warning, in Odd Jobs).
export const ODD_JOBS = Object.freeze([
  'stalkerware_scan', 'mvt_spyware_scan',
  'airport_wifi_scan', 'application_compatibility', 'application_crash_report', 'audio_config', 'audio_troubleshoot',
  'battery_health', 'bluetooth_diagnostics', 'core_services_reset', 'coreaudio_reset', 'directory_permissions',
  'disk_health', 'disk_permissions_repair', 'disk_smart_check', 'disk_utility_firstaid', 'display_config', 'display_issues',
  'filesystem_health_check', 'font_issues', 'gpu_health', 'handoff_continuity', 'homebrew_health', 'hostname_check', 'icloud_status',
  'icloud_storage_check', 'icloud_storage', 'input_devices', 'kernel_panic_check', 'keychain_health', 'login_keychain_repair',
  'mail_config', 'network_diagnostics', 'network_interface_audit', 'network_interfaces_check', 'network_speed_test',
  'notifications_config', 'photos_library_check', 'pram_nvram_check', 'printer_diagnostics', 'printer_queue',
  'recovery_partition_check', 'rosetta_status', 'safe_boot_check', 'safe_mode_check', 'screen_time_password', 'sleep_wake_issues',
  'smart_status', 'smc_reset_check', 'smcreset_guide', 'software_inventory', 'system_age_check', 'time_machine_exclusions',
  'time_machine_health', 'time_sync_check', 'usb_devices_check', 'user_account_health', 'wifi_diagnostics', 'wifi_password_recovery',
  'arp_spoof_check', 'ethernet_diagnostics', 'lan_device_inventory', 'clamshell_mode', 'disk_fragmentation_check', 'disk_io_health',
  'disk_space', 'font_cache_repair', 'font_cache', 'macos_user_cleanup', 'memory_pressure_check', 'memory_pressure', 'network_quality',
  'notification_center_check', 'power_settings', 'energy_saver_check', 'energy_settings', 'screen_resolution_scaling', 'spotlight_rebuild', 'spotlight_repair',
  'spotlight_status', 'swap_memory_check', 'swap_usage', 'thermal_throttle_check', 'thermal_throttle', 'user_profile_size',
  'bluetooth_audit', 'disk_encryption_recovery', 'evidence_bundle', 'login_window_settings',
  'mdm_enrollment_check', 'mdm_enrollment', 'sip_gatekeeper', 'siri_privacy', 'ssh_key_audit', 'sudo_config_audit', 'sudo_touchid',
  'usb_device_audit', 'user_account_audit', 'vpn_config', 'xprotect_status', 'screen_time_parental',
  // Split by code above; its other warnings (none today) would be Odd Jobs.
  'security_baseline_diff',
]);

// The same on Windows: checks that can warn on Windows and go to Odd Jobs on
// purpose (hardware, repair tools and system health with no mini-game; the
// monitoring checks, as on macOS). Shared modules listed in ODD_JOBS count too.
export const WIN_ODD_JOBS = Object.freeze([
  'win_activation', 'win_activation_check', 'win_audio_check', 'win_battery', 'win_bluetooth_check', 'win_boot_config_check',
  'win_boot_time', 'win_disk_health', 'win_dism_health', 'win_display_check', 'win_event_log_health', 'win_memory_diagnostics',
  'win_network_adapters', 'win_network_diag', 'win_network_reset', 'win_print_spooler_check', 'win_printer_check',
  'win_printer_issues', 'win_recovery_options', 'win_safe_mode_check', 'win_search_index', 'win_sfc_check', 'win_startup_repair',
  'win_user_profiles', 'win_wifi_diagnostics', 'win_winsock_check', 'win_wmi_health',
  // Its unsigned drivers are Seal Check's (by data.check); its other warnings are driver health.
  'win_driver_check',
  // Telemetry and advertising settings (its location switch is the Keyring's), and domain policy notes.
  'win_cortana_telemetry', 'win_group_policy_audit',
]);

// Where the grouping puts a check whatever a game's own covers say (UX audit
// P3), applied last in buildTable: a whole move takes the module from every
// other type; a narrow move (codes or checks) adds a claim that wins over a
// whole one. A game that already claims the same keeps it (no double claim).
export const MOVES = Object.freeze([
  { module: 'browser_cryptojacking_check', checks: ['mining_hosts_entry'], to: 'switchboard' },
  // Sleep, screen-off and Power Nap are settings, not clutter. Lock Run is
  // their place once games/locks.js has a lock for them (today it would draw
  // them as "Automatic updates"); until then, Odd Jobs (listed in ODD_JOBS).
  { module: 'energy_saver_check', to: 'simple' },
  { module: 'energy_settings', to: 'simple' },
  { module: 'power_settings', to: 'simple' },
]);

// To-dos that are shown as notes (Good to know / Signal or Noise): the list
// counts them as to-dos, so missionCounts does too. A code prefix, as covers.
export const NOTE_CODES = Object.freeze([
  'security.clamav_scanner.clamav_not_installed', // an optional extra scanner, not a lock left open
]);
const isNoteCode = (code) => typeof code === 'string' && NOTE_CODES.some((p) => code.startsWith(p));

// A wildcard ({ module: '*', severities }) is kept but never matched here:
// every info item goes to the notes missions anyway, and it claims nothing
// another game claims (contract.js claimConflicts skips it).
const cleanCovers = (covers) => (Array.isArray(covers) ? covers : [])
  .filter((c) => c && typeof c.module === 'string' && c.module)
  .map((c) => (c.module === '*' ? { module: '*', severities: Array.isArray(c.severities) ? c.severities.slice() : [] }
    : { module: c.module,
      ...(Array.isArray(c.codes) && c.codes.length ? { codes: c.codes.filter((x) => typeof x === 'string' && x) } : {}),
      ...(Array.isArray(c.checks) && c.checks.length ? { checks: c.checks.filter((x) => typeof x === 'string' && x) } : {}) }));

// { [type]: [{ module, codes? }] }. `games`: registered game modules (or
// anything with { type, covers }); a game with `covers` replaces its type's entry.
export function buildTable(games = []) {
  const table = {};
  for (const t of TYPE_IDS) table[t] = cleanCovers(BASE_COVERS[t]);
  for (const g of Array.isArray(games) ? games : []) {
    if (g && TYPE_IDS.includes(g.type) && Array.isArray(g.covers)) table[g.type] = cleanCovers(g.covers);
  }
  for (const mv of MOVES) {
    const narrow = mv.codes ? { codes: mv.codes.slice() } : mv.checks ? { checks: mv.checks.slice() } : null;
    if (!narrow) {
      for (const t of TYPE_IDS) if (t !== mv.to) table[t] = table[t].filter((c) => c.module !== mv.module);
      // Odd Jobs is the fallback type: nothing to claim there.
      if (mv.to !== 'simple' && !table[mv.to].some((c) => c.module === mv.module && !c.codes && !c.checks)) table[mv.to].push({ module: mv.module });
      continue;
    }
    const same = (c) => c.module === mv.module && JSON.stringify(c.codes || c.checks) === JSON.stringify(narrow.codes || narrow.checks);
    for (const t of TYPE_IDS) if (t !== mv.to) table[t] = table[t].filter((c) => !same(c));
    if (!table[mv.to].some(same)) table[mv.to].push({ module: mv.module, ...narrow });
  }
  return table;
}

const DEFAULT_TABLE = buildTable();

// Two types claiming the same (module, code): contract.js claimConflicts.
export function doubleClaims(table) {
  return claimConflicts(table);
}

// The type a finding's to-do belongs to, ignoring its severity (a note the
// person calls odd becomes an item of this type).
export function claimedType(finding, table = DEFAULT_TABLE) {
  const module = finding && finding.module;
  const code = finding && typeof finding.code === 'string' ? finding.code : '';
  const check = finding && finding.data && typeof finding.data.check === 'string' ? finding.data.check : '';
  let wholeType = null;
  let best = null;
  let byCheck = null;
  for (const t of TYPE_IDS) {
    for (const c of table[t] || []) {
      if (c.module === '*' || c.module !== module) continue;
      if (c.checks && !c.codes) { if (check && c.checks.includes(check) && !byCheck) byCheck = t; continue; }
      if (!c.codes) { if (!wholeType) wholeType = t; continue; }
      for (const p of c.codes) if (code && code.startsWith(p) && (!best || p.length > best.len)) best = { type: t, len: p.length };
    }
  }
  return best ? best.type : byCheck || wholeType || 'simple';
}

export function typeOf(finding, table = DEFAULT_TABLE) {
  if (!finding || finding.severity === 'info' || isNoteCode(finding.code)) return 'notes';
  return claimedType(finding, table);
}

const RANK = { critical: 2, warning: 1, info: 0 };
// Which kind of mission comes first at the same severity: known-bad files,
// then what starts on its own, the network, seals, powerful access, add-ons,
// settings, clutter, the rest.
export const IMPORTANCE = Object.freeze(['locker', 'door', 'switchboard', 'seal', 'keyring', 'loadout', 'locks', 'junkyard', 'simple', 'notes']);
const importance = (t) => { const i = IMPORTANCE.indexOf(t); return i < 0 ? IMPORTANCE.length : i; };
const NOT_CHECKED_CODE = /_(?:unknown|failed|unavailable|permission_denied)$/;
const ORDER_OF_DISTRICT = new Map([...DISTRICTS.map((d) => d.id), OUTSKIRTS.id].map((id, i) => [id, i]));
const isFixable = (f) => !!(f && f.fixable && typeof f.fixable === 'object');
const isStale = (item) => item.findings.some((f) => f && f.data && f.data.mark_stale === true);

// The removal warning: contract.js's one rule (an item warns when any of its findings does).
function withAlert(item) {
  return { ...item, removal_alert: isAlertingItem(item) };
}
const leads = (item) => (item.removal_alert || item.findings.some(isFixable) ? 1 : 0);

// The district of a check: its module's category, as findings-to-city places it.
function districtOfItem(item, cats) {
  const f = item.finding || {};
  return districtIdFor(cats.get(f.module) || f.category || null);
}

function partsOf(items, size) {
  const out = [];
  for (let i = 0; i < items.length; i += size) out.push(items.slice(i, i + size));
  return out;
}

/*
 * groupMissions(doc, { mode, table, odd, batchNotes }) -> Mission[]
 * - To-do items (critical, warning; stale marks as normal items) by (type,
 *   district), worst first, alerting or fixable first, at most MAX_ITEMS each.
 * - Keyring findings (one per permission, listing apps) become one item per
 *   app (R4), carrying its keys; `sourceKeys` says which list items it came from.
 * - Notes (info) by district, NOTES_BATCH each (or the notes game's own
 *   `batchNotes`), after every to-do mission. A note the person called odd
 *   (`odd`: a Set of item keys) is an item of its own type instead.
 * - Every item: `district`, `removal_alert`, and `unfinished` when one of its
 *   checks didn't finish (R2).
 * - City mode: held items are in displayItems' `held` list, never here.
 */
export function groupMissions(doc, { mode = 'standard', table = DEFAULT_TABLE, odd = null, batchNotes = null } = {}) {
  const list = NC.displayItems(doc, { mode });
  const mods = (doc && Array.isArray(doc.modules) ? doc.modules : []).filter(Boolean);
  const cats = new Map(mods.map((m) => [m.name, m.category]));
  const unfinished = new Set(NC.notCheckedParts(doc).unfinished.map((x) => x.name));
  const dress = (item) => ({ ...withAlert(item), district: districtOfItem(item, cats), unfinished: item.seen_in.some((m) => unfinished.has(m)) });
  const oddSet = odd instanceof Set ? odd : new Set(odd || []);
  // R8: a Lock Run check's "couldn't check" note is a Lock Run item.
  const lockNote = (i) => claimedType(i.finding, table) === 'locks' && NOT_CHECKED_CODE.test(String(i.finding.code || ''));
  const promoted = new Set(list.info.filter((i) => oddSet.has(i.key) || lockNote(i)).map((i) => i.key));
  const oddNotes = list.info.filter((i) => promoted.has(i.key)).map((i) => ({ ...i, fromNote: true }));
  const all = [...list.critical, ...list.warning, ...list.marked.filter(isStale), ...oddNotes].map(dress);
  // NOTE_CODES: a to-do shown with the notes (as a note: severity info, the list's in `listSeverity`).
  const asNote = (i) => !i.fromNote && isNoteCode(i.finding && i.finding.code);
  const todo = all.filter((i) => !asNote(i));
  const shownAsNotes = all.filter(asNote).map((i) => ({ ...i, severity: 'info', listSeverity: i.severity, asNote: true }));
  const groups = new Map();
  for (const item of todo) {
    const type = item.fromNote ? claimedType(item.finding, table) : typeOf({ ...item.finding, severity: item.severity }, table);
    const k = `${type}|${item.district}`;
    if (!groups.has(k)) groups.set(k, { type, district: item.district, items: [] });
    groups.get(k).items.push(item);
  }
  const missions = [];
  for (const g of groups.values()) {
    const items = g.type === 'keyring' ? perApp(g.items) : g.items;
    const sorted = items.map((it, i) => ({ it, i }))
      .sort((a, b) => (RANK[b.it.severity] - RANK[a.it.severity]) || (leads(b.it) - leads(a.it)) || (a.i - b.i)).map((x) => x.it);
    const parts = partsOf(sorted, MAX_ITEMS);
    parts.forEach((part, n) => missions.push(mission(g.type, g.district, part, n + 1, parts.length, false)));
  }
  // Worst first, then alerting or fixable, then by what the type is about
  // (IMPORTANCE), never type-major by table order; a type's parts stay in order.
  missions.sort((a, b) => (RANK[b.severity] - RANK[a.severity]) || (leadsMission(b) - leadsMission(a))
    || (importance(a.type) - importance(b.type))
    || ((ORDER_OF_DISTRICT.get(a.district) ?? 99) - (ORDER_OF_DISTRICT.get(b.district) ?? 99)) || (a.part - b.part));
  const notes = [...shownAsNotes, ...list.info.filter((i) => !promoted.has(i.key)).map(dress)];
  for (const b of notesBatches(notes, batchNotes)) missions.push(mission('notes', b.area, b.items, b.part, b.parts, true));
  return missions;
}

const districtRank = (d) => ORDER_OF_DISTRICT.get(d) ?? 99;
function notesBatches(notes, batchNotes) {
  if (typeof batchNotes === 'function') {
    try {
      const got = batchNotes(notes, { areaOf: (i) => i.district, size: NOTES_BATCH });
      if (Array.isArray(got) && got.reduce((n, b) => n + ((b && b.items && b.items.length) || 0), 0) === notes.length) {
        return got.map((b) => ({ area: b.area, part: b.part, parts: b.parts, items: b.items }));
      }
    } catch (_) { /* the foundation's own batches */ }
  }
  const by = new Map();
  for (const item of notes) { if (!by.has(item.district)) by.set(item.district, []); by.get(item.district).push(item); }
  const out = [];
  for (const [area, items] of [...by.entries()].sort(([a], [b]) => districtRank(a) - districtRank(b))) {
    const parts = partsOf(items, NOTES_BATCH);
    parts.forEach((batch, n) => out.push({ area, part: n + 1, parts: parts.length, items: batch }));
  }
  return out;
}

// R4: the apps a permission finding lists (data.apps as paths, ids or
// {path, bundle_id, id, name}; data.processes; or one data.bundle_id).
function appSubjects(f) {
  const d = f && f.data && typeof f.data === 'object' ? f.data : {};
  const out = [];
  for (const a of Array.isArray(d.apps) ? d.apps : []) {
    if (typeof a === 'string' && a) out.push({ subject: a, name: '' });
    else if (a && typeof a === 'object') {
      const subject = [a.path, a.bundle_id, a.id, a.name].find((x) => typeof x === 'string' && x);
      if (subject) out.push({ subject, name: typeof a.name === 'string' ? a.name : '' });
    }
  }
  for (const p of Array.isArray(d.processes) ? d.processes : []) if (typeof p === 'string' && p) out.push({ subject: p, name: '' });
  if (!out.length && typeof d.bundle_id === 'string' && d.bundle_id) out.push({ subject: d.bundle_id, name: '' });
  return out;
}
const permissionOf = (f) => (f && f.data && typeof f.data.service === 'string' && f.data.service) || (f && f.code) || (f && f.title) || '';

// One item per app, each with its keys (every permission finding that lists
// it). The original findings stay on the item (marks, evidence). A finding
// that names no app stays one item. Monitoring comes from ALL the findings
// (contract.js isMonitoringFinding): one monitoring finding makes the app's
// item warn and lead with that finding (so it pays nothing and is remembered
// for the session only), and one held finding holds it. The key carries the
// district, as the grouping does, so the same app in two districts is two items.
function perApp(items) {
  const apps = new Map();
  const sev = new Map(); // finding -> the list severity of the item it came in
  const out = [];
  for (const item of items) {
    let named = false;
    for (const f of item.findings) sev.set(f, item.severity);
    for (const f of item.findings) {
      for (const a of appSubjects(f)) {
        named = true;
        const k = `${item.district}|${a.subject}`;
        let app = apps.get(k);
        if (!app) {
          app = { ...item, key: `app|${item.district}|${a.subject}`, app: { subject: a.subject, name: a.name }, finding: f, findings: [], seen_in: [], keys: [], sourceKeys: [] };
          apps.set(k, app);
          out.push(app);
        }
        if (!app.findings.includes(f)) app.findings.push(f);
        if (!app.seen_in.includes(f.module)) app.seen_in.push(f.module);
        if (!app.keys.some((x) => x.finding === f)) app.keys.push({ permission: permissionOf(f), finding: f });
        if (!app.sourceKeys.includes(item.key)) app.sourceKeys.push(item.key);
        if (RANK[item.severity] > RANK[app.severity]) app.severity = item.severity;
        const watched = isMonitoringFinding(f);
        const leadWatched = isMonitoringFinding(app.finding);
        if ((watched && !leadWatched) || (watched === leadWatched && RANK[item.severity] > RANK[sev.get(app.finding) || 'info'])) app.finding = f;
        app.removal_alert = app.removal_alert || item.removal_alert || watched;
        app.held = app.held || item.held === true;
        app.unfinished = app.unfinished || item.unfinished;
        app.marked = app.marked && item.marked;
      }
    }
    if (!named) out.push(item);
  }
  return out;
}

function leadsMission(m) {
  return m.items.some((i) => leads(i)) ? 1 : 0;
}

function mission(type, district, items, part, of, notes) {
  const severity = items.reduce((s, i) => (RANK[i.severity] > RANK[s] ? i.severity : s), 'info');
  return { id: `${type}:${district}:${part}`, type, district, severity, items, title: { ...TYPE_TITLES[type] }, part, of, notes };
}

// The list's numbers: an app item made from several permission findings
// counts each list item once (sourceKeys), so todo equals scanCounts.todo; a
// note made an item (odd, or a Lock Run "couldn't check") still counts as a
// note, and a to-do shown as a note (NOTE_CODES) still counts as a to-do.
export function missionCounts(missions) {
  const todo = new Set(); let notes = 0;
  for (const m of missions || []) {
    if (m.notes) { for (const i of m.items) { if (i.asNote) todo.add(i.key); else notes += 1; } continue; }
    for (const i of m.items) { if (i.fromNote) { notes += 1; continue; } for (const k of i.sourceKeys || [i.key]) todo.add(k); }
  }
  return { todo: todo.size, notes };
}

/*
 * missionRows(missions) -> Row[]   the district list's rows (UX audit P1-4)
 * Row = { id, type, district, severity, title, notes, missions, items, apps }
 * - The parts of one type in one district at one severity are one row, where
 *   its first part is ("The Keyring · 11 parts, 41 apps"). Opening it opens
 *   its first part not done yet; the next part follows it in the mission order.
 * - Every notes batch of a district is one row ("Good to know · 28 batches").
 * `items`: the items in all its parts; `apps`: how many are apps (Keyring).
 * Pure: the missions are kept as they are, in their order.
 */
export function missionRows(missions) {
  const rows = [];
  const at = new Map();
  for (const m of Array.isArray(missions) ? missions : []) {
    if (!m || !Array.isArray(m.items)) continue;
    const k = m.notes ? `notes|${m.district}` : `${m.type}|${m.district}|${m.severity}`;
    let row = at.get(k);
    if (!row) {
      row = { id: `row:${k}`, type: m.type, district: m.district, severity: m.severity, title: { ...m.title }, notes: !!m.notes, missions: [], items: 0, apps: 0 };
      at.set(k, row);
      rows.push(row);
    }
    row.missions.push(m);
    row.items += m.items.length;
    row.apps += m.items.filter((i) => i && i.app).length;
    if (RANK[m.severity] > RANK[row.severity]) row.severity = m.severity;
  }
  return rows;
}
