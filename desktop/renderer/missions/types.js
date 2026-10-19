// Little missions: which kind of thing each finding is about (its type), and
// the missions a scan becomes (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md).
//
//   TYPE_TITLES[type] -> { standard, city }
//   BASE_COVERS[type] -> [{ module, codes? }]   the spec's table, macOS and Windows
//   ODD_JOBS                                   modules that can warn on macOS and go to Odd Jobs on purpose
//   buildTable(games) -> table                 a registered game's `covers` replaces its type's entry
//   doubleClaims(table) -> [problem]            two types claiming the same (module, code)
//   typeOf(finding, table) -> type id           info -> 'notes'; unmapped -> 'simple'
//   groupMissions(doc, { mode, table }) -> Mission[]
//   missionCounts(missions) -> { todo, notes }  equal to NotChecked.scanCounts(doc, { mode }).todo / .notes
//
// Mission = { id, type, district, severity, items, title: {standard, city}, part, of, notes }
// Item    = a NotChecked.displayItems item + { removal_alert }
//
// Built only from NotChecked.displayItems, so a mission never counts anything
// the list doesn't. Pure; no DOM, no storage.
import { TYPE_IDS } from './contract.js';
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
      'win_autorun', 'win_autoruns_audit', 'win_scheduled_tasks', 'win_scheduled_tasks_security', 'win_startup',
      'win_startup_programs_audit', 'win_services_audit', 'win_services_security_audit'),
    { module: 'security_baseline_diff', codes: [`${SBD}new_persistence`] },
  ],
  keyring: whole('app_permissions', 'privacy_permissions_audit', 'accessibility_permissions', 'keylogger_indicators',
    'screen_time_audit', 'location_services'),
  loadout: [
    ...whole('chrome_extensions', 'safari_extensions', 'browser_extension_audit', 'browser_hijack_check', 'browser_cryptojacking_check'),
    { module: 'security_baseline_diff', codes: [`${SBD}new_browser_extension`] },
  ],
  seal: whole('code_signature_audit', 'gatekeeper_quarantine_check', 'suspicious_processes', 'certificate_audit',
    'certificate_trust_audit', 'win_suspicious_processes'),
  switchboard: [
    ...whole('firewall_audit', 'firewall_rules_audit', 'open_ports_scan', 'network_connections_monitor', 'suspicious_connections',
      'dns_config', 'dns_poisoning_check', 'dns_over_https_check', 'hosts_file_check', 'network_proxy', 'network_proxy_check',
      'network_proxy_detect', 'remote_login_check', 'sharing_preferences_audit', 'sharing_services', 'router_security_audit',
      'wifi_security_audit', 'vpn_leak_check', 'airdrop_config', 'airdrop_security_check',
      'win_firewall_rules_audit', 'win_hosts_file', 'win_hosts_file_check', 'win_proxy_detect', 'win_rdp_check',
      'win_remote_access_audit', 'win_network_shares_audit', 'win_dns_config'),
    { module: 'security_baseline_diff', codes: [`${SBD}new_listening_port`] },
  ],
  locker: whole('ai_worm_filesystem', 'ai_worm_iocs', 'ai_worm_git_ssh', 'ai_worm_lateral', 'ai_worm_network', 'ai_threat_indicators',
    'malware_scan_indicators', 'clamav_scanner', 'cryptojacking_iocs', 'crypto_miner_detect', 'rootkit_check', 'temp_file_scanner',
    'win_malware_indicators', 'win_crypto_miner_detect', 'win_rootkit_check'),
  locks: [
    ...whole('automatic_updates', 'update_checker', 'encryption_check', 'filevault_recovery', 'screen_lock_check', 'lock_screen_check',
      'find_my_mac_check', 'guest_account_check', 'firmware_password', 'login_password_policy', 'antivirus_status',
      'macos_version_support', 'macos_eol_check', 'backup_status', 'time_machine_check', 'session_revocation_scan',
      'appleid_security_check',
      'win_defender', 'win_defender_deep_check', 'win_antivirus_status', 'win_bitlocker', 'win_bitlocker_check', 'win_firewall',
      'win_updates', 'win_windows_update_status', 'win_uac_check'),
    { module: 'firewall_audit', codes: ['security.firewall_audit.global_state'] },
    { module: 'firewall_rules_audit', codes: ['security.firewall_rules_audit.alf_'] },
    { module: 'security_baseline_diff', codes: [`${SBD}protection_disabled`] },
  ],
  junkyard: whole('storage_cleanup', 'large_files_finder', 'library_cache_cleanup', 'browser_cache_cleanup', 'trash_cleanup',
    'docker_cleanup', 'xcode_cleanup', 'mail_attachment_cleanup', 'crash_log_analyzer', 'app_crash_analyzer', 'energy_saver_check',
    'energy_settings', 'resource_hog_identifier', 'system_log_errors', 'process_scanner',
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
  'battery_health', 'bluetooth_diagnostics', 'core_services_reset', 'coreaudio_reset', 'default_browser', 'directory_permissions',
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
  'notification_center_check', 'power_settings', 'screen_resolution_scaling', 'spotlight_rebuild', 'spotlight_repair',
  'spotlight_status', 'swap_memory_check', 'swap_usage', 'thermal_throttle_check', 'thermal_throttle', 'user_profile_size',
  'bluetooth_audit', 'browser_privacy_check', 'disk_encryption_recovery', 'evidence_bundle', 'login_window_settings',
  'mdm_enrollment_check', 'mdm_enrollment', 'sip_gatekeeper', 'siri_privacy', 'ssh_key_audit', 'sudo_config_audit', 'sudo_touchid',
  'usb_device_audit', 'user_account_audit', 'vpn_config', 'xprotect_status', 'screen_time_parental',
  // Split by code above; its other warnings (none today) would be Odd Jobs.
  'security_baseline_diff',
]);

const cleanCovers = (covers) => (Array.isArray(covers) ? covers : [])
  .filter((c) => c && typeof c.module === 'string' && c.module)
  .map((c) => (Array.isArray(c.codes) && c.codes.length ? { module: c.module, codes: c.codes.filter((x) => typeof x === 'string' && x) } : { module: c.module }));

// { [type]: [{ module, codes? }] }. `games`: registered game modules (or
// anything with { type, covers }); a game with `covers` replaces its type's entry.
export function buildTable(games = []) {
  const table = {};
  for (const t of TYPE_IDS) table[t] = cleanCovers(BASE_COVERS[t]);
  for (const g of Array.isArray(games) ? games : []) {
    if (g && TYPE_IDS.includes(g.type) && Array.isArray(g.covers)) table[g.type] = cleanCovers(g.covers);
  }
  return table;
}

const DEFAULT_TABLE = buildTable();

// Two claims on one module conflict when both are whole, or both have codes
// and one code is a prefix of the other. A whole claim and a code claim
// don't: the code claim is more specific and wins for its findings.
export function doubleClaims(table) {
  const out = [];
  const claims = [];
  for (const t of TYPE_IDS) for (const c of (table && table[t]) || []) claims.push({ type: t, ...c });
  for (let i = 0; i < claims.length; i += 1) {
    for (let j = i + 1; j < claims.length; j += 1) {
      const a = claims[i]; const b = claims[j];
      if (a.module !== b.module) continue;
      if (!a.codes && !b.codes) { out.push(`${a.module} is claimed whole by ${a.type} and ${b.type}`); continue; }
      if (!a.codes || !b.codes) continue;
      for (const x of a.codes) for (const y of b.codes) {
        if (x.startsWith(y) || y.startsWith(x)) out.push(`${a.module} code ${x.length > y.length ? x : y} is claimed by ${a.type} and ${b.type}`);
      }
    }
  }
  return out;
}

// The type a finding's to-do belongs to, ignoring its severity (a note the
// person calls odd becomes an item of this type).
export function claimedType(finding, table = DEFAULT_TABLE) {
  const module = finding && finding.module;
  const code = finding && typeof finding.code === 'string' ? finding.code : '';
  let wholeType = null;
  let best = null;
  for (const t of TYPE_IDS) {
    for (const c of table[t] || []) {
      if (c.module !== module) continue;
      if (!c.codes) { if (!wholeType) wholeType = t; continue; }
      for (const p of c.codes) if (code && code.startsWith(p) && (!best || p.length > best.len)) best = { type: t, len: p.length };
    }
  }
  return best ? best.type : wholeType || 'simple';
}

export function typeOf(finding, table = DEFAULT_TABLE) {
  if (!finding || finding.severity === 'info') return 'notes';
  return claimedType(finding, table);
}

const RANK = { critical: 2, warning: 1, info: 0 };
const ORDER_OF_DISTRICT = new Map([...DISTRICTS.map((d) => d.id), OUTSKIRTS.id].map((id, i) => [id, i]));
const isAlerting = (f) => !!f && (f.removal_alert === true || !!(f.remediation && f.remediation.safety_note));
const isFixable = (f) => !!(f && f.fixable && typeof f.fixable === 'object');
const isStale = (item) => item.findings.some((f) => f && f.data && f.data.mark_stale === true);

function withAlert(item) {
  return { ...item, removal_alert: item.findings.some(isAlerting) };
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
 * groupMissions(doc, { mode, table }) -> Mission[]
 * - To-do items (critical, warning; stale marks as normal items) by (type,
 *   district), worst first, alerting or fixable first, at most MAX_ITEMS each.
 * - Notes (info) by district, NOTES_BATCH each, after every to-do mission.
 * - City mode: held items are in displayItems' `held` list, never here.
 */
export function groupMissions(doc, { mode = 'standard', table = DEFAULT_TABLE } = {}) {
  const list = NC.displayItems(doc, { mode });
  const cats = new Map((doc && Array.isArray(doc.modules) ? doc.modules : []).filter(Boolean).map((m) => [m.name, m.category]));
  const todo = [...list.critical, ...list.warning, ...list.marked.filter(isStale)].map(withAlert);
  const groups = new Map();
  for (const item of todo) {
    const type = typeOf({ ...item.finding, severity: item.severity }, table);
    const district = districtOfItem(item, cats);
    const k = `${type}|${district}`;
    if (!groups.has(k)) groups.set(k, { type, district, items: [] });
    groups.get(k).items.push(item);
  }
  const missions = [];
  for (const g of groups.values()) {
    const sorted = g.items.map((it, i) => ({ it, i }))
      .sort((a, b) => (RANK[b.it.severity] - RANK[a.it.severity]) || (leads(b.it) - leads(a.it)) || (a.i - b.i)).map((x) => x.it);
    const parts = partsOf(sorted, MAX_ITEMS);
    parts.forEach((items, n) => missions.push(mission(g.type, g.district, items, n + 1, parts.length, false)));
  }
  missions.sort((a, b) => (RANK[b.severity] - RANK[a.severity]) || (leadsMission(b) - leadsMission(a))
    || (TYPE_IDS.indexOf(a.type) - TYPE_IDS.indexOf(b.type))
    || ((ORDER_OF_DISTRICT.get(a.district) ?? 99) - (ORDER_OF_DISTRICT.get(b.district) ?? 99)) || (a.part - b.part));
  const notesBy = new Map();
  for (const item of list.info.map(withAlert)) {
    const d = districtOfItem(item, cats);
    if (!notesBy.has(d)) notesBy.set(d, []);
    notesBy.get(d).push(item);
  }
  const notes = [...notesBy.entries()].sort(([a], [b]) => (ORDER_OF_DISTRICT.get(a) ?? 99) - (ORDER_OF_DISTRICT.get(b) ?? 99));
  for (const [district, items] of notes) {
    const parts = partsOf(items, NOTES_BATCH);
    parts.forEach((batch, n) => missions.push(mission('notes', district, batch, n + 1, parts.length, true)));
  }
  return missions;
}

function leadsMission(m) {
  return m.items.some((i) => leads(i)) ? 1 : 0;
}

function mission(type, district, items, part, of, notes) {
  const severity = items.reduce((s, i) => (RANK[i.severity] > RANK[s] ? i.severity : s), 'info');
  return { id: `${type}:${district}:${part}`, type, district, severity, items, title: { ...TYPE_TITLES[type] }, part, of, notes };
}

export function missionCounts(missions) {
  let todo = 0; let notes = 0;
  for (const m of missions || []) { if (m.notes) notes += m.items.length; else todo += m.items.length; }
  return { todo, notes };
}
