'use strict';

/*
 * "Open in System Settings": the Mac settings pages a finding or a lesson can
 * open, and which findings each one belongs to.
 *
 * Opening a page changes nothing. The person makes the change there, so every
 * button says that ("Opens the Software Update page. You make the change there.").
 * URLs open only through window.rescue.openSetting, which main checks against
 * the scheme allowlist in setting-urls.js.
 *
 * Verified on macOS 26.3.1 (build 25D771280a), without opening System Settings:
 * - Pane ids are the CFBundleIdentifier of each extension in
 *   /System/Library/ExtensionKit/Extensions/*.appex/Contents/Info.plist, each with
 *   SettingsExtensionAttributes.allowsXAppleSystemPreferencesURLScheme = true.
 *   com.apple.preference.security is that file's legacyBundleIdentifier for
 *   com.apple.settings.PrivacySecurity.extension (SecurityPrivacyExtension.appex).
 * - Anchors are keys in the pane's own en.lproj/*.searchTerms: "FileVault" and
 *   "Privacy_AllFiles" in PrivacySecurity.searchTerms (Privacy_AllFiles is also the
 *   ALL_FILES revealElementKeyName in TCCServiceList.plist), "Firewall" in
 *   Network.appex's NetworkSearchGroups.searchTerms.
 * - Network panes (verified on macOS 26, 2026-10-18): Wi-Fi.appex has
 *   CFBundleIdentifier com.apple.wifi-settings-extension with
 *   allowsXAppleSystemPreferencesURLScheme = true. "DNS", "Proxies", "VPN" and
 *   "Ethernet" are keys in Network.appex's NetworkSearchGroups.searchTerms, the
 *   same file that verifies "Firewall".
 * Mac only for now; Windows (ms-settings:) can be added as a second table.
 */
const SettingPanes = (function () {
  const PREFIX = 'x-apple.systempreferences:';
  const MAC_PANES = {
    softwareUpdate: { url: `${PREFIX}com.apple.Software-Update-Settings.extension`, page: 'Software Update page' },
    fileVault: { url: `${PREFIX}com.apple.preference.security?FileVault`, page: 'FileVault section of Privacy & Security' },
    lockScreen: { url: `${PREFIX}com.apple.Lock-Screen-Settings.extension`, page: 'Lock Screen page' },
    firewall: { url: `${PREFIX}com.apple.Network-Settings.extension?Firewall`, page: 'Firewall section of Network' },
    sharing: { url: `${PREFIX}com.apple.Sharing-Settings.extension`, page: 'Sharing page' },
    loginItems: { url: `${PREFIX}com.apple.LoginItems-Settings.extension`, page: 'Login Items page' },
    privacySecurity: { url: `${PREFIX}com.apple.preference.security`, page: 'Privacy & Security page' },
    wifi: { url: `${PREFIX}com.apple.wifi-settings-extension`, page: 'Wi-Fi page' },
    networkDns: { url: `${PREFIX}com.apple.Network-Settings.extension?DNS`, page: 'DNS section of Network' },
    networkProxies: { url: `${PREFIX}com.apple.Network-Settings.extension?Proxies`, page: 'Proxies section of Network' },
    networkVpn: { url: `${PREFIX}com.apple.Network-Settings.extension?VPN`, page: 'VPN section of Network' },
    networkEthernet: { url: `${PREFIX}com.apple.Network-Settings.extension?Ethernet`, page: 'Ethernet section of Network' },
    fullDiskAccess: { url: `${PREFIX}com.apple.preference.security?Privacy_AllFiles`, page: 'Full Disk Access list in Privacy & Security' },
  };

  // Finding code -> pane, only where that pane is where the finding's own
  // "What to do" sends the person. Codes are shared by a module's "all fine"
  // info findings, so a button shows only on critical and warning cards.
  const CODE_PANES = {
    'security.automatic_updates.automatic_check': 'softwareUpdate',
    'security.automatic_updates.automatic_download': 'softwareUpdate',
    'security.automatic_updates.auto_install_macos': 'softwareUpdate',
    'security.automatic_updates.critical_update': 'softwareUpdate',
    'security.automatic_updates.config_data': 'softwareUpdate',
    'security.automatic_updates.app_store_auto': 'softwareUpdate',
    'security.encryption_check.filevault_disabled': 'fileVault',
    'security.filevault_recovery.fv_disabled': 'fileVault',
    'security.lock_screen_check.screensaver_password': 'lockScreen',
    'security.lock_screen_check.screensaver_delay': 'lockScreen',
    'security.lock_screen_check.display_sleep': 'lockScreen',
    'security.screen_lock_check.screen_lock_required': 'lockScreen',
    'security.screen_lock_check.screen_lock_delay': 'lockScreen',
    'security.screen_lock_check.screensaver_idle_time': 'lockScreen',
    'security.firewall_audit.global_state': 'firewall',
    'security.firewall_audit.stealth_mode': 'firewall',
    'security.firewall_rules_audit.alf_disabled': 'firewall',
    'security.firewall_rules_audit.stealth_disabled': 'firewall',
    'security.firewall_rules_audit.too_many_apps': 'firewall',
    'security.firewall_rules_audit.allow_signed_enabled': 'firewall',
    'security.remote_login_check.ssh_enabled': 'sharing',
    'security.remote_login_check.screen_sharing_enabled': 'sharing',
    'security.remote_login_check.remote_management_enabled': 'sharing',
    'security.remote_login_check.remote_apple_events_enabled': 'sharing',
    'security.sharing_services.screen_sharing': 'sharing',
    'security.sharing_services.file_sharing': 'sharing',
    'security.sharing_services.remote_login': 'sharing',
    'security.sharing_services.remote_management': 'sharing',
    'security.sharing_services.printer_sharing': 'sharing',
    'security.sharing_preferences_audit.screen_sharing': 'sharing',
    'security.sharing_preferences_audit.file_sharing': 'sharing',
    'security.sharing_preferences_audit.remote_login': 'sharing',
    'security.sharing_preferences_audit.remote_management': 'sharing',
    'security.sharing_preferences_audit.printer_sharing': 'sharing',
    // Network. Not mapped: router, ARP and LAN codes (fixed on the router or
    // by looking at the network, not on this Mac), wpa2_only (the router),
    // and the Ethernet warnings (their advice is a cable or a router port;
    // networkEthernet is here for when one names a Mac setting).
    'network.wifi_security_audit.wep_connected': 'wifi',
    'network.wifi_security_audit.open_network_connected': 'wifi',
    'network.wifi_security_audit.wep_saved': 'wifi',
    'network.wifi_security_audit.open_saved': 'wifi',
    'network.network_proxy_check.remote_pac_url': 'networkProxies',
    'network.network_proxy_check.pac_url_detected': 'networkProxies',
    'network.network_proxy_check.suspicious_localhost_proxy': 'networkProxies',
    'network.network_proxy_check.proxy_enabled': 'networkProxies',
    'network.dns_over_https_check.unencrypted_dns': 'networkDns',
    'network.dns_over_https_check.no_encryption_configured': 'networkDns',
    'network.vpn_leak_check.dns_leak': 'networkVpn',
    'network.vpn_leak_check.split_tunneling': 'networkVpn',
    'network.vpn_leak_check.vpn_not_connected': 'networkVpn',
  };
  // Findings with no code: every login_items finding is about login items;
  // update_checker's macOS-updates finding (not its Homebrew one).
  const MODULE_PANES = {
    login_items: () => 'loginItems',
    update_checker: (f) => (f.data && f.data.check === 'os_updates' ? 'softwareUpdate' : null),
  };

  const isMac = (platform) => platform === 'darwin';

  function pane(key) {
    return Object.prototype.hasOwnProperty.call(MAC_PANES, key) ? MAC_PANES[key] : null;
  }

  // `finding` carries `module` (groupFindingsBySeverity adds it).
  function paneKeyForFinding(finding) {
    if (!finding || (finding.severity !== 'critical' && finding.severity !== 'warning')) return null;
    if (finding.code && Object.prototype.hasOwnProperty.call(CODE_PANES, finding.code)) return CODE_PANES[finding.code];
    const byModule = Object.prototype.hasOwnProperty.call(MODULE_PANES, finding.module) ? MODULE_PANES[finding.module] : null;
    return byModule ? byModule(finding) : null;
  }

  // What a button for this pane says it does. It opens a page; nothing more.
  function hintFor(key) {
    const p = pane(key);
    return p ? `Opens the ${p.page}. You make the change there.` : '';
  }

  function esc(value) {
    return String(value == null ? '' : value)
      .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
  }

  // The plain results' button for a finding card, or '' (not a Mac, or no pane).
  function findingButtonHtml(finding, platform) {
    if (!isMac(platform)) return '';
    const key = paneKeyForFinding(finding);
    const p = key && pane(key);
    if (!p) return '';
    return `<div class="setting-link">
      <button type="button" class="btn btn--secondary btn--small" data-setting-url="${esc(p.url)}">Open in System Settings</button>
      <p class="muted setting-link__hint">${esc(hintFor(key))}</p>
    </div>`;
  }

  // A lesson question's `setting` key -> what the game draws, or null.
  function lessonSetting(key, platform) {
    if (!isMac(platform)) return null;
    const p = pane(key);
    return p ? { key, hint: hintFor(key) } : null;
  }

  function urlFor(key) {
    const p = pane(key);
    return p ? p.url : null;
  }

  return { MAC_PANES, CODE_PANES, MODULE_PANES, isMac, pane, urlFor, paneKeyForFinding, hintFor, findingButtonHtml, lessonSetting };
})();

if (typeof module !== 'undefined' && module.exports) {
  module.exports = SettingPanes;
}
// A top-level const isn't a window property; game mode's ES modules read it from window.
if (typeof window !== 'undefined') {
  window.SettingPanes = SettingPanes;
}
