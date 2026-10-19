// Lock Run: settings and locks (spec: docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md,
// "locks"). A row of locks, one per item. Each lock says what it protects, its state, and where its switch lives.
// Decisions: Turn it on (a settings-pane intent, or "Show me how" when there is no pane to open) / Done (re-check
// that check) / Not now. A pure module: it returns decisions, research and link intents; the runner acts.
//
// Never asks for a password or a recovery key. Recovery-key locks always say never to paste the key anywhere.
import { isAlertingItem } from '../contract.js';

// Where a check couldn't look. Such a lock is never shown as fine: its state is "Not checked".
const COULDNT_TITLE = /^(?:we\s+)?(?:couldn[’']t|could\s+not)\s+(?:check|list|read|see|tell|find\s+out)\b/i;
const COULDNT_CHECKS = new Set([
  'os_updates_not_checked', 'brew_not_checked', 'version_unavailable', 'service_check_failed',
  'status_check_failed', 'timemachine_status_unknown', 'tm_unknown', 'no_backup_date', 'chip_type_detection',
  'firmware_password_unknown', 'firmware_password_permission_denied', 'firmware_password_unavailable',
  'unable_to_check',
]);
const COULDNT_CODE = /_(?:unknown|failed|unavailable|permission_denied)$/;

const NEVER_PASTE = {
  standard: 'Never type or paste your recovery key into this app, a website, a chat or an email. No one helping you needs it. Keep it written down somewhere safe, away from the computer.',
  city: 'Never type or paste your recovery key into this app, a website, a chat or an email. Keep it written down somewhere safe, away from the computer.',
};

// The locks. `mac` / `win`: where the switch lives (`where`), the pane to open (`pane`, a SETTINGS_PANES id, or
// null when there is nothing to open), the steps to show when there is no pane (`how`), and a fixed look-up.
const LOCKS = {
  updates: {
    name: { standard: 'Automatic updates', city: 'Patch lock' },
    protects: 'Installs the fixes for security holes for you.',
    concept: 'auto-updates',
    mac: { where: 'System Settings > General > Software Update. Click the “i” next to Automatic updates and turn each switch on.', pane: 'software-update' },
    win: { where: 'Settings > Windows Update. Install what is waiting, and resume updates if they are paused.', pane: 'windows-update' },
  },
  'os-support': {
    name: { standard: 'System still supported', city: 'Foundation age' },
    state: { standard: 'Out of date', city: 'Aging' },
    protects: 'Security fixes only reach systems the maker still supports.',
    concept: 'auto-updates',
    mac: { where: 'System Settings > General > Software Update shows the newest macOS this Mac can run.', pane: 'software-update', lookup: { source: 'apple-support', query: 'macOS compatibility' } },
    win: { where: 'Settings > Windows Update shows whether a newer version of Windows is offered.', pane: 'windows-update', lookup: { source: 'microsoft-support', query: 'Windows lifecycle' } },
  },
  'app-updates': {
    name: { standard: 'Package updates', city: 'Toolbox patches' },
    state: { standard: 'Out of date', city: 'Aging' },
    protects: 'Keeps tools you installed with Homebrew up to date.',
    concept: 'auto-updates',
    mac: { where: 'In Terminal, Homebrew updates its packages with: brew upgrade', pane: null, how: ['Open Terminal.', 'Type brew outdated to see the list.', 'Type brew upgrade to update them.'] },
    win: { where: '', pane: null, how: [] },
  },
  encryption: {
    name: { standard: 'Disk encryption', city: 'Vault lock' },
    protects: 'Keeps your files unreadable if the computer is lost or stolen.',
    concept: 'disk-encryption',
    mac: { where: 'System Settings > Privacy & Security > FileVault. Turn it on and keep the recovery key it shows you.', pane: 'filevault' },
    win: { where: 'Settings > Privacy & security > Device encryption, or Control Panel > BitLocker Drive Encryption.', pane: 'windows-bitlocker', how: ['Open Control Panel > System and Security > BitLocker Drive Encryption.', 'Choose Turn on BitLocker for the drive.', 'Save the recovery key where you can find it without this computer.'], lookup: { source: 'microsoft-support', query: 'Turn on BitLocker' } },
  },
  'recovery-key': {
    name: { standard: 'Recovery key', city: 'Spare vault key' },
    state: { standard: 'Missing', city: 'Missing' },
    on: { standard: 'Open FileVault', city: 'Open the vault' },
    protects: 'Lets you unlock your disk if you forget your password.',
    concept: 'disk-encryption',
    neverPaste: true,
    mac: { where: 'System Settings > Privacy & Security > FileVault. Apple’s guide shows how to make a new recovery key.', pane: 'filevault', lookup: { source: 'apple-support', query: 'FileVault recovery key' } },
    win: { where: 'Control Panel > BitLocker Drive Encryption > Back up your recovery key.', pane: null, how: ['Open Control Panel > System and Security > BitLocker Drive Encryption.', 'Choose Back up your recovery key.', 'Print it or save it somewhere other than this computer.'], lookup: { source: 'microsoft-support', query: 'Back up your BitLocker recovery key' } },
  },
  firewall: {
    name: { standard: 'Firewall', city: 'Outer wall' },
    protects: 'Blocks connections other computers on the network didn’t get asked for.',
    concept: null,
    mac: { where: 'System Settings > Network > Firewall. Turn it on.', pane: 'firewall' },
    win: { where: 'Windows Security > Firewall & network protection. Turn the firewall on for each network.', pane: 'windows-firewall' },
  },
  'screen-lock': {
    name: { standard: 'Screen lock', city: 'Screen lock' },
    protects: 'Asks for your password when you step away.',
    concept: 'lock-screen',
    mac: { where: 'System Settings > Lock Screen. Set “Require password after screen saver begins or display is turned off” to Immediately.', pane: 'lock-screen' },
    win: { where: 'Settings > Accounts > Sign-in options. Set “If you’ve been away, when should Windows require you to sign in again?” to When PC wakes up.', pane: 'windows-signin', how: ['Open Settings > Accounts > Sign-in options.', 'Under Additional settings, choose When PC wakes up from sleep.'] },
  },
  'auto-login': {
    name: { standard: 'Sign-in at start', city: 'Front gate' },
    state: { standard: 'On', city: 'Open' },
    protects: 'Makes anyone who turns the computer on sign in first.',
    concept: 'lock-screen',
    on: { standard: 'Turn it off', city: 'Shut the gate' },
    mac: { where: 'System Settings > Users & Groups. Set “Automatically log in as” to Off.', pane: 'users-groups' },
    win: { where: 'The netplwiz window: tick “Users must enter a user name and password to use this computer”.', pane: null, how: ['Press Windows+R, type netplwiz and choose OK.', 'Tick “Users must enter a user name and password to use this computer”.', 'Choose OK.'], lookup: { source: 'microsoft-support', query: 'turn off automatic sign-in Windows' } },
  },
  guest: {
    name: { standard: 'Guest access', city: 'Visitor door' },
    state: { standard: 'On', city: 'Open' },
    protects: 'Keeps people without an account out of your computer and shared folders.',
    concept: null,
    on: { standard: 'Turn it off', city: 'Close the door' },
    mac: { where: 'System Settings > Users & Groups > Guest User. Turn off “Allow guests to log in to this computer”.', pane: 'users-groups' },
    win: { where: 'An administrator turns the Guest account off in Computer Management > Local Users and Groups > Users.', pane: null, how: ['Open Computer Management (search for it in Start).', 'Go to Local Users and Groups > Users.', 'Open Guest and tick Account is disabled.'], lookup: { source: 'microsoft-support', query: 'disable guest account Windows' } },
  },
  'guest-share': {
    name: { standard: 'Guest access to shared folders', city: 'Visitor shelf' },
    state: { standard: 'On', city: 'Open' },
    protects: 'Keeps your shared folders for people you named.',
    concept: null,
    on: { standard: 'Turn it off', city: 'Close the shelf' },
    mac: { where: 'System Settings > General > Sharing > File Sharing (i). Choose each shared folder and set Everyone to No Access.', pane: 'sharing' },
    win: { where: '', pane: null, how: [] },
  },
  'find-my': {
    name: { standard: 'Find My', city: 'Homing beacon' },
    protects: 'Lets you find, lock or erase a lost computer.',
    concept: null,
    mac: { where: 'System Settings > your name > iCloud > Find My Mac. Turn it on.', pane: 'apple-id' },
    win: { where: 'Settings > Privacy & security > Find my device.', pane: 'windows-findmydevice', how: ['Open Settings > Privacy & security > Find my device.', 'Turn it on.'] },
  },
  location: {
    name: { standard: 'Location for Find My', city: 'Beacon signal' },
    protects: 'Lets Find My show where a lost computer is.',
    concept: null,
    mac: { where: 'System Settings > Privacy & Security > Location Services. Turn it on, then check that Find My is allowed.', pane: 'privacy-location' },
    win: { where: '', pane: null, how: [] },
  },
  firmware: {
    name: { standard: 'Startup security', city: 'Boot lock' },
    protects: 'Stops someone starting your computer from another disk.',
    concept: null,
    mac: { where: 'On an Intel Mac: start up in macOS Recovery, then choose Utilities > Startup Security Utility.', pane: null, how: ['Start the Mac in macOS Recovery (Apple’s guide shows the keys for your Mac).', 'Choose Utilities > Startup Security Utility.', 'Turn on the firmware password and write it down somewhere safe.'], lookup: { source: 'apple-support', query: 'set a firmware password on your Mac' } },
    win: { where: '', pane: null, how: [] },
  },
  password: {
    name: { standard: 'Password rules', city: 'Key rules' },
    protects: 'Makes sign-in passwords hard to guess.',
    concept: 'password-prompts',
    mac: { where: 'System Settings > Users & Groups. Choose your account to change its password.', pane: 'users-groups' },
    win: { where: 'An administrator sets these in Local Security Policy > Account Policies > Password Policy.', pane: null, how: ['Open Local Security Policy (search for secpol in Start).', 'Go to Account Policies > Password Policy.', 'Set a minimum password length of at least 12.'], lookup: { source: 'microsoft-support', query: 'Windows password policy minimum length' } },
  },
  antivirus: {
    name: { standard: 'Virus protection', city: 'Shield' },
    protects: 'Catches known harmful files before they run.',
    concept: null,
    mac: { where: 'Open the antivirus app and turn its protection back on. macOS’s own protection, XProtect, needs no switch.', pane: null, how: ['Open the antivirus app from Applications.', 'Turn its protection back on, or remove the app if you no longer use it.'] },
    win: { where: 'Windows Security > Virus & threat protection. Turn on each protection that is off.', pane: 'windows-security' },
  },
  uac: {
    name: { standard: 'Permission prompts', city: 'Ask-first bell' },
    protects: 'Asks before apps make big changes to the computer.',
    concept: 'password-prompts',
    mac: { where: '', pane: null, how: [] },
    win: { where: 'Control Panel > User Accounts > Change User Account Control settings. Move the slider back to the default.', pane: null, how: ['Search for UAC in Start and open Change User Account Control settings.', 'Move the slider to the second notch from the top.', 'Choose OK.'], lookup: { source: 'microsoft-support', query: 'User Account Control settings' } },
  },
  autorun: {
    name: { standard: 'AutoRun and AutoPlay', city: 'Auto-open latch' },
    state: { standard: 'On', city: 'Open' },
    protects: 'Stops a plugged-in USB stick or disc from starting a program by itself.',
    concept: null,
    on: { standard: 'Turn it off', city: 'Shut the latch' },
    mac: { where: '', pane: null, how: [] },
    win: { where: 'Settings > Bluetooth & devices > AutoPlay. Turn off “Use AutoPlay for all media and devices”.', pane: null,
      how: ['Open Settings > Bluetooth & devices > AutoPlay.', 'Turn off “Use AutoPlay for all media and devices”.'], lookup: { source: 'microsoft-support', query: 'turn AutoPlay on or off Windows' } },
  },
  admins: {
    name: { standard: 'Administrator accounts', city: 'Master keys' },
    protects: 'Keeps the accounts that can change everything few, known and locked with a password.',
    concept: 'password-prompts',
    mac: { where: 'System Settings > Users & Groups. Check which accounts are administrators.', pane: 'users-groups' },
    win: { where: 'Settings > Accounts > Other users. Check which accounts are administrators, and remove any you don’t know.', pane: 'users-groups',
      how: ['Open Settings > Accounts > Other users.', 'Choose each account and check its account type.', 'Change an account you don’t use every day to Standard user.'] },
  },
  'saved-logins': {
    name: { standard: 'Saved sign-ins', city: 'Spare keys' },
    protects: 'Keeps the passwords Windows remembers for other computers and sites few and current.',
    concept: null,
    mac: { where: '', pane: null, how: [] },
    win: { where: 'Control Panel > User Accounts > Credential Manager. Remove saved sign-ins you no longer use.', pane: null,
      how: ['Search for Credential Manager in Start and open it.', 'Choose Windows Credentials.', 'Open each one you don’t use any more and choose Remove.'], lookup: { source: 'microsoft-support', query: 'Credential Manager Windows' } },
  },
  backups: {
    name: { standard: 'Backups', city: 'Archive' },
    protects: 'Keeps a copy of your files if the disk fails or files are lost.',
    concept: null,
    mac: { where: 'System Settings > General > Time Machine. Add a backup disk and turn on automatic backups.', pane: 'time-machine' },
    win: { where: 'Control Panel > Recovery > Configure System Restore. Turn on protection for the main drive.', pane: null, how: ['Search for Create a restore point in Start and open it.', 'Choose the main drive, then Configure.', 'Turn on system protection and choose OK.'], lookup: { source: 'microsoft-support', query: 'System Restore' } },
  },
  sessions: {
    name: { standard: 'Saved sign-in keys', city: 'Spare keys' },
    state: { standard: 'To look at', city: 'Unchecked' },
    protects: 'Decides which other computers can sign in to this one.',
    concept: 'remote-access-scams',
    on: { standard: 'Show me how', city: 'Show me how' },
    mac: { where: 'The keys are listed in the file shown below. If you don’t use Remote Login, turn it off in System Settings > General > Sharing.', pane: null, how: ['Look at the file shown below: each line is one computer that can sign in.', 'Keep the lines you recognise.', 'If you don’t use Remote Login, turn it off in System Settings > General > Sharing.'] },
    win: { where: 'The keys are listed in the file shown below.', pane: null, how: ['Look at the file shown below: each line is one computer that can sign in.', 'Keep the lines you recognise.'] },
  },
  stealth: {
    name: { standard: 'Stealth mode', city: 'Quiet wall' },
    protects: 'Stops your computer answering when other devices on the network check whether it is there.',
    concept: null,
    mac: { where: 'System Settings > Network > Firewall > Options. Turn on “Enable stealth mode”.', pane: 'firewall' },
    win: { where: '', pane: null, how: [] },
  },
  sip: {
    name: { standard: 'System Integrity Protection', city: 'Core seal' },
    protects: 'Stops any app, even one with your password, from changing the core parts of macOS.',
    concept: null,
    mac: { where: 'In macOS Recovery: Utilities > Terminal, type csrutil enable, then restart.', pane: null,
      how: ['Shut down the Mac.', 'Apple silicon: hold the power button until the startup options appear, then choose Options. Intel: hold Command-R while it starts.',
        'Choose Utilities > Terminal, type csrutil enable, press Return, and restart.', 'If you turned it off for special software on purpose, you can leave it.'],
      lookup: { source: 'apple-support', query: 'System Integrity Protection' } },
    win: { where: '', pane: null, how: [] },
  },
  'secure-boot': {
    name: { standard: 'Secure Boot', city: 'Boot seal' },
    protects: 'Stops unknown software from running before Windows starts.',
    concept: null,
    mac: { where: '', pane: null, how: [] },
    win: { where: 'Settings > System > Recovery > Advanced startup > Restart now, then Troubleshoot > Advanced options > UEFI Firmware Settings. Turn Secure Boot on.', pane: null,
      how: ['Open Settings > System > Recovery.', 'Next to Advanced startup, choose Restart now.', 'Choose Troubleshoot > Advanced options > UEFI Firmware Settings, then Restart.', 'Find Secure Boot in the firmware settings and turn it on.'],
      lookup: { source: 'microsoft-support', query: 'Secure Boot' } },
  },
  'safe-mode': {
    name: { standard: 'Safe Mode option', city: 'Emergency exit' },
    state: { standard: 'Missing', city: 'Bricked up' },
    protects: 'Lets the computer start with only the basics, which helps remove stubborn software.',
    concept: null,
    mac: { where: '', pane: null, how: [] },
    win: { where: 'Windows Security > Virus & threat protection > Scan options. Run a Microsoft Defender Offline scan, then ask a technical helper to restore Safe Mode.', pane: 'windows-security',
      lookup: { source: 'microsoft-support', query: 'Microsoft Defender Offline scan' } },
  },
  scanner: {
    name: { standard: 'ClamAV scanner', city: 'Scanner' },
    state: { standard: 'Needs a look', city: 'Idle' },
    protects: 'ClamAV is an optional free scanner for known harmful files. It matters only if you chose to use it.',
    concept: null,
    mac: { where: 'ClamAV runs from Terminal. If you don’t use it, you can leave this.', pane: null,
      how: ['If you don’t use ClamAV, choose Not now.', 'To install or repair it with Homebrew, type brew install clamav in Terminal.',
        'To update its list of known harmful files, type freshclam.', 'To start its background scanner, type brew services start clamav.'] },
    win: { where: '', pane: null, how: [] },
  },
  'browser-safety': {
    name: { standard: 'Safari safety settings', city: 'Browser shutters' },
    protects: 'Warns you about scam websites and limits who can follow you from site to site.',
    concept: null,
    mac: { where: 'Safari > Settings. Under Privacy, turn on “Prevent cross-site tracking”; under Security, turn on “Warn when visiting a fraudulent website”.', pane: null,
      how: ['Open Safari.', 'Choose Safari > Settings, then Privacy.', 'Turn on Prevent cross-site tracking.', 'Choose Security and turn on Warn when visiting a fraudulent website.'] },
    win: { where: '', pane: null, how: [] },
  },
  'default-browser': {
    name: { standard: 'Default browser', city: 'Gate to the web' },
    state: { standard: 'Missing', city: 'Missing' },
    protects: 'Opens web links in a browser that is really on this computer.',
    concept: null,
    mac: { where: 'System Settings > Desktop & Dock > Default web browser. Choose a browser you have.', pane: null,
      how: ['Open System Settings > Desktop & Dock.', 'Find Default web browser.', 'Choose a browser you have, like Safari.'] },
    win: { where: 'Settings > Apps > Default apps. Choose a browser you have.', pane: null, how: ['Open Settings > Apps > Default apps.', 'Choose a browser you have and set it as default.'] },
  },
  'apple-id': {
    name: { standard: 'Apple account', city: 'Citizen pass' },
    protects: 'Protects your Apple account and your saved passwords.',
    concept: null,
    mac: { where: 'System Settings > your name. Sign in, then turn on iCloud Keychain under iCloud > Passwords.', pane: 'apple-id' },
    win: { where: '', pane: null, how: [] },
  },
};

// Module (and data.check or code) -> lock id.
const BY_CHECK = {
  update_checker: (c) => (c === 'brew_outdated' || c === 'brew_not_checked' ? 'app-updates' : 'updates'),
  macos_version_support: () => 'os-support',
  macos_eol_check: () => 'os-support',
  filevault_recovery: (c) => (c === 'fv_disabled' ? 'encryption' : 'recovery-key'),
  disk_encryption_recovery: (c) => (c === 'fv_disabled' ? 'encryption' : 'recovery-key'),
  screen_lock_check: (c) => (c === 'automatic_login' ? 'auto-login' : 'screen-lock'),
  guest_account_check: (c) => (c === 'guest_afp_access' || c === 'guest_smb_access' ? 'guest-share' : 'guest'),
  find_my_mac_check: (c, code) => (/location_services/.test(code) ? 'location' : /icloud_not_signed_in/.test(code) ? 'apple-id' : 'find-my'),
  login_password_policy: (c) => ({ auto_login: 'auto-login', guest_account_enabled: 'guest', ask_password: 'screen-lock', password_delay: 'screen-lock', screensaver_timeout: 'screen-lock', remote_login_enabled: 'sessions' }[c] || 'password'),
  appleid_security_check: (c) => (c === 'autoupdate_disabled' || c === 'autoupdate_unknown' ? 'updates' : 'apple-id'),
  win_bitlocker: (c, code) => (/no_recovery_key/.test(code) ? 'recovery-key' : 'encryption'),
  win_bitlocker_check: (c, code) => (/no_recovery_key/.test(code) ? 'recovery-key' : 'encryption'),
  win_user_accounts: (c) => ({ guest_enabled: 'guest', auto_login: 'auto-login' }[c] || 'password'),
  win_local_admin_audit: (c) => ({ guest_enabled: 'guest', builtin_admin_enabled: 'admins', excessive_admins: 'admins', admin_accounts: 'admins' }[c] || 'password'),
  firewall_audit: (c, code) => (/stealth_mode/.test(code) || /^stealth_mode/.test(c) ? 'stealth' : 'firewall'),
  firewall_rules_audit: (c, code) => (/\.stealth_/.test(code) || /^stealth_/.test(c) ? 'stealth' : 'firewall'),
};
const BY_MODULE = {
  automatic_updates: 'updates', win_updates: 'updates', win_windows_update_status: 'updates', win_update_history: 'updates',
  encryption_check: 'encryption', win_firewall: 'firewall',
  rootkit_check: 'sip', win_rootkit_check: 'secure-boot', win_malware_indicators: 'safe-mode', clamav_scanner: 'scanner',
  browser_privacy_check: 'browser-safety', default_browser: 'default-browser',
  lock_screen_check: 'screen-lock', firmware_password: 'firmware', antivirus_status: 'antivirus',
  win_defender: 'antivirus', win_defender_deep_check: 'antivirus', win_antivirus_status: 'antivirus',
  win_uac_check: 'uac', win_credential_guard: 'password',
  backup_status: 'backups', time_machine_check: 'backups', win_restore_points: 'backups', win_shadow_copies_check: 'backups',
  session_revocation_scan: 'sessions',
  win_autorun: 'autorun', win_credential_manager_audit: 'saved-logins',
};

const isWinModule = (m) => /^win_/.test(String(m || ''));
const dataOf = (f) => (f && f.data && typeof f.data === 'object' ? f.data : {});

// The lock an item belongs to, or 'updates' as a calm default for an unknown settings item.
export function lockOf(finding) {
  const f = finding || {};
  const check = String(dataOf(f).check || '');
  const code = String(f.code || '');
  const byCheck = BY_CHECK[f.module];
  const id = byCheck ? byCheck(check, code) : BY_MODULE[f.module];
  return LOCKS[id] ? id : null;
}

// True when the check couldn't look: such a lock is "Not checked", never fine.
export function couldntCheck(item) {
  const f = (item && item.finding) || {};
  const d = dataOf(f);
  if (item && (item.unfinished === true || item.incomplete === true || item.complete === false)) return true;
  if (COULDNT_TITLE.test(String(f.title || ''))) return true;
  if (COULDNT_CHECKS.has(String(d.check || ''))) return true;
  if (COULDNT_CODE.test(String(f.code || ''))) return true;
  return f.module === 'macos_eol_check' && 'error' in d;
}

const platformOf = (item, ctx) => (isWinModule(item && item.finding && item.finding.module) || (ctx && ctx.platform === 'win32') ? 'win' : 'mac');

function lockFor(item, ctx) {
  const id = lockOf(item && item.finding) || 'updates';
  const lock = LOCKS[id];
  const side = lock[platformOf(item, ctx)];
  const place = side && (side.where || side.pane || (side.how && side.how.length)) ? side : lock.mac;
  return { id, lock, place };
}

const modules = (item) => {
  const seen = Array.isArray(item && item.seen_in) ? item.seen_in.filter((m) => typeof m === 'string') : [];
  const lead = item && item.finding && item.finding.module;
  return [...new Set([lead, ...seen].filter((m) => typeof m === 'string' && m))];
};

// contract.js's one monitoring rule.
const alerting = (item) => isAlertingItem(item);

// The runner draws the buttons, the removal-warning line, the evidence rows and the links (ruling R1); render
// returns only the lock card.
export function decisions(item, ctx) {
  const { lock, place } = lockFor(item, ctx);
  const unknown = couldntCheck(item);
  const mods = modules(item);
  const recheck = { kind: 'recheck', module: mods[0] || null, modules: mods };
  const later = { id: 'later', label: { standard: 'Not now', city: 'Not now' }, effect: { kind: 'later' } };
  let on;
  if (place.pane) {
    const label = unknown ? { standard: 'Check it myself', city: 'Check it myself' } : (lock.on || { standard: 'Turn it on', city: 'Lock it' });
    on = { id: 'on', label, effect: { kind: 'settings', pane: place.pane }, hint: 'Opens the settings page. You make the change there.' };
  } else {
    on = { id: 'on', label: { standard: 'Show me how', city: 'Show me how' }, effect: { kind: 'closer', checklist: (place.how || []).slice() }, hint: 'Shows the steps. You make the change.' };
  }
  const done = {
    id: 'done',
    label: unknown ? { standard: 'Check again', city: 'Check again' } : { standard: 'Done', city: 'Check the lock' },
    effect: recheck,
    hint: 'Runs this check again to see the change.',
  };
  // A lock on something that can alert whoever set it up (saved sign-in keys): the runner shows the removal
  // warning before it opens the steps or the page (controller ruling R6).
  if (alerting(item)) on.effect.warning = true;
  return [on, done, later];
}

export function research(item, ctx) {
  const f = (item && item.finding) || {};
  const { id, lock, place } = lockFor(item, ctx);
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  let rows = [];
  try { rows = ctx && typeof ctx.evidenceRows === 'function' ? ctx.evidenceRows(f, { mode }) || [] : []; } catch (_) { rows = []; }
  const links = [];
  if (place.pane) links.push({ kind: 'settings', pane: place.pane });
  if (place.lookup) links.push({ kind: 'lookup', source: place.lookup.source, query: place.lookup.query });
  if (lock.concept) links.push({ kind: 'lesson', concept: lock.concept });
  const unknown = couldntCheck(item);
  return {
    rows: Array.isArray(rows) ? rows : [],
    what: lock.protects,
    links,
    lock: id,
    where: place.where || '',
    steps: (place.how || []).slice(),
    notChecked: unknown ? 'This check didn’t finish, so this lock isn’t known to be on. Look for yourself, then check again.' : '',
    neverPaste: lock.neverPaste ? NEVER_PASTE[mode] : '',
  };
}

const STATE = {
  open: { standard: 'Off', city: 'Unlocked' },
  unknown: { standard: 'Not checked', city: 'In the fog' },
};

function lockIcon(state) {
  // A small inline padlock, decorative only. Open: the shackle lifts. Fog: an outline with a question mark.
  if (state === 'unknown') {
    return '<svg class="lk-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M8 11V7a4 4 0 0 1 8 0v4" fill="none" stroke="currentColor" stroke-width="2" stroke-dasharray="2 2"/><rect x="5" y="11" width="14" height="10" rx="2" fill="none" stroke="currentColor" stroke-width="2"/><path d="M10.5 14.5a1.5 1.5 0 1 1 2 1.4V17" fill="none" stroke="currentColor" stroke-width="1.6"/></svg>';
  }
  return '<svg class="lk-icon" viewBox="0 0 24 24" aria-hidden="true" focusable="false"><path d="M8 11V7a4 4 0 0 1 7.6-1.7" fill="none" stroke="currentColor" stroke-width="2"/><rect x="5" y="11" width="14" height="10" rx="2" fill="currentColor"/></svg>';
}

// The row of locks in this mission: where you are in it. Past locks are "visited", never drawn shut: a decision
// isn't proof the setting changed (only a re-check is).
function row(view) {
  const total = Math.max(1, Math.min(12, Number(view.total) || 1));
  const at = Math.max(0, Math.min(total - 1, Number(view.index) || 0));
  let out = '<ol class="lk-row" aria-hidden="true">';
  for (let i = 0; i < total; i += 1) out += `<li class="lk-pip${i === at ? ' lk-pip--here' : ''}${i < at ? ' lk-pip--past' : ''}">${lockIcon('open')}</li>`;
  return `${out}</ol>`;
}

export function render(view, ctx) {
  const v = view || {};
  const item = v.item || {};
  const f = item.finding || {};
  const mode = ctx.mode === 'city' ? 'city' : 'standard';
  const e = ctx.esc;
  const r = v.research || research(item, ctx);
  const { lock } = lockFor(item, ctx);
  const unknown = couldntCheck(item);
  const state = unknown ? 'unknown' : 'open';
  const pos = `${Number(v.index) + 1 || 1} of ${Number(v.total) || 1}`;
  const steps = (r.steps || []).map((s) => `<li>${e(s)}</li>`).join('');
  const step = v.step && v.step.say ? `<p class="lk-coach">${e(v.step.say[mode] || v.step.say.standard || '')}</p>` : '';
  return `<section class="lk lk--${state}${v.practice ? ' lk--practice' : ''}" data-lock="${e(r.lock || '')}">
  ${row(v)}
  ${step}
  <div class="lk-card">
    <div class="lk-head">${lockIcon(state)}<div>
      <p class="lk-kicker">${e(mode === 'city' ? `Lock ${pos}` : `Setting ${pos}`)}${v.practice ? ` · ${e(mode === 'city' ? 'Drill' : 'Practice')}` : ''}</p>
      <h3 class="lk-name">${e(lock.name[mode])}</h3>
    </div><span class="lk-state lk-state--${state}">${e(state === 'open' && lock.state ? lock.state[mode] : STATE[state][mode])}</span></div>
    <p class="lk-title">${e(f.title || '')}</p>
    <dl class="lk-facts">
      <div><dt>${e(mode === 'city' ? 'Guards' : 'Protects')}</dt><dd>${e(r.what || lock.protects)}</dd></div>
      ${r.where ? `<div><dt>${e(mode === 'city' ? 'Switch' : 'Where')}</dt><dd>${e(r.where)}</dd></div>` : ''}
    </dl>
    ${r.notChecked ? `<p class="lk-note lk-note--fog">${e(r.notChecked)}</p>` : ''}
    ${r.neverPaste ? `<p class="lk-note lk-note--key"><strong>${e('Your recovery key stays with you.')}</strong> ${e(r.neverPaste)}</p>` : ''}
    ${steps ? `<ol class="lk-steps">${steps}</ol>` : ''}
  </div>
</section>`;
}

// results: [{ item, decision }] where decision is a decision id or a Decision.
export function summary(results, ctx) {
  const mode = ctx && ctx.mode === 'city' ? 'city' : 'standard';
  const e = ctx.esc;
  const list = Array.isArray(results) ? results : [];
  const idOf = (r) => (r && typeof r.decision === 'object' && r.decision ? r.decision.id : r && r.decision);
  const n = (id) => list.filter((r) => idOf(r) === id).length;
  const on = n('on'); const done = n('done'); const later = n('later');
  const unknown = list.filter((r) => r && r.item && couldntCheck(r.item)).length;
  const lines = [];
  if (mode === 'city') {
    lines.push(`${list.length} ${list.length === 1 ? 'lock' : 'locks'} visited.`);
    if (done) lines.push(`${done} sent for a re-check. A lock counts once the re-check shows it shut.`);
    if (on) lines.push(`${on} ${on === 1 ? 'switch' : 'switches'} opened for you to flip.`);
    if (later) lines.push(`${later} left for another run.`);
    if (unknown) lines.push(`${unknown} still in the fog: the scout couldn’t see ${unknown === 1 ? 'it' : 'them'}.`);
  } else {
    lines.push(`You looked at ${list.length} ${list.length === 1 ? 'setting' : 'settings'}.`);
    if (done) lines.push(`${done} will be checked again. A setting counts as on once the check shows it.`);
    if (on) lines.push(`${on} settings ${on === 1 ? 'page' : 'pages'} opened for you to change.`);
    if (later) lines.push(`${later} set aside. They stay on your list.`);
    if (unknown) lines.push(`${unknown} couldn’t be checked, so ${unknown === 1 ? 'it isn’t' : 'they aren’t'} known to be on.`);
  }
  lines.push(mode === 'city' ? 'A shut lock lowers the odds; it doesn’t rule everything out.' : 'Locks lower the odds of a problem. They don’t rule one out.');
  return `<div class="lk-sum">${lines.map((l) => `<p>${e(l)}</p>`).join('')}</div>`;
}

// Synthetic practice locks (no real data): updates off, FileVault off, screen lock never.
const practiceItem = (module, code, title, data, severity = 'warning') => {
  const finding = { module, code, title, description: '', severity, category: 'security', data };
  return { key: `practice:${code}`, severity, finding, findings: [finding], seen_in: [module], marked: false, held: false, removal_alert: false, practice: true };
};

const practice = {
  items: [
    practiceItem('automatic_updates', 'security.automatic_updates.automatic_check', 'Your Mac is not checking for updates automatically', { check: 'automatic_check' }),
    practiceItem('encryption_check', 'security.encryption_check.filevault_disabled', 'Your Mac’s disk encryption is off', { fdesetup_output: 'FileVault is Off.' }, 'critical'),
    practiceItem('screen_lock_check', 'security.screen_lock_check.screen_lock_required', 'Your Mac does not lock after sleeping', { check: 'screen_lock_required', value: '0' }, 'critical'),
  ],
  // Steps ask before they tell: `say` asks, `why` (after the move) gives the verdict and its clue. No `expect`:
  // an explanation (one GOT IT). `expect` may list several moves that all fit (the first is the best).
  script: [
    { item: 0, say: { standard: 'Each lock says what it protects and where its switch is.', city: 'Each lock says what it guards and where its lever is.' } },
    { item: 0, expect: 'on',
      say: { standard: 'Automatic updates are off. Read what this protects and where the switch is. What would you do?', city: 'Patches don’t come in on their own. Read what this guards and where the lever is. What would you do?' },
      why: { standard: '“Where” is the exact switch. Turn it on opens that page, and you flip the switch there.', city: '“Switch” is where the lever is. Lock it opens that panel, and you flip it there.' } },
    { item: 1, expect: 'on',
      say: { standard: 'Disk encryption is off. What would you do?', city: 'The vault is unlocked. What would you do?' },
      why: { standard: 'Turn it on opens FileVault. It shows you a recovery key when you turn it on: write it down. Never paste it anywhere.', city: 'Lock it opens the vault panel. The vault hands you a spare key: write it down. Never paste it anywhere.' } },
    { item: 2, expect: ['done', 'on'],
      say: { standard: 'In this practice, you already changed this setting yourself. What would you do?', city: 'In this drill, you already flipped this lever yourself. What would you do?' },
      why: { standard: 'Done checks again, and the lock counts once the check sees it.', city: 'Check the lock sends the scout again, and it counts once the scout sees it shut.' } },
  ],
};

export const covers = [
  { module: 'automatic_updates' }, { module: 'update_checker' }, { module: 'appleid_security_check' },
  { module: 'macos_version_support' }, { module: 'macos_eol_check' },
  { module: 'encryption_check' }, { module: 'filevault_recovery' }, { module: 'disk_encryption_recovery' },
  // The firewall switch, stealth mode, and "couldn't check" for both (the Switchboard keeps the rules).
  { module: 'firewall_audit' },
  { module: 'firewall_rules_audit', codes: ['security.firewall_rules_audit.alf_', 'security.firewall_rules_audit.stealth_'] },
  // Protection switches inside checks other games own (a code claim wins over their whole claim).
  { module: 'rootkit_check', codes: ['security.rootkit_check.sip_disabled'] },
  { module: 'clamav_scanner' },
  { module: 'browser_privacy_check' }, { module: 'default_browser' },
  { module: 'screen_lock_check' }, { module: 'lock_screen_check' }, { module: 'login_password_policy' },
  { module: 'find_my_mac_check' }, { module: 'guest_account_check' }, { module: 'firmware_password' },
  { module: 'antivirus_status' }, { module: 'backup_status' }, { module: 'time_machine_check' },
  { module: 'session_revocation_scan' },
  // Windows equivalents
  { module: 'win_updates' }, { module: 'win_windows_update_status' }, { module: 'win_update_history' },
  { module: 'win_bitlocker' }, { module: 'win_bitlocker_check' },
  { module: 'win_defender' }, { module: 'win_defender_deep_check' }, { module: 'win_antivirus_status' },
  { module: 'win_firewall' }, { module: 'win_uac_check' }, { module: 'win_credential_guard' },
  { module: 'win_user_accounts', codes: ['security.win_user_accounts.guest_account_enabled', 'security.win_user_accounts.auto_login_enabled', 'security.win_user_accounts.no_min_password_length'] },
  { module: 'win_restore_points' }, { module: 'win_shadow_copies_check' },
  { module: 'win_rootkit_check', codes: ['security.win_rootkit_check.secure_boot_disabled'] },
  { module: 'win_malware_indicators', codes: ['security.win_malware_indicators.safe_mode_disabled'] },
  // AutoRun/AutoPlay is a switch; admin accounts and saved sign-ins are locks (the Mac's guest and password ones are here too).
  { module: 'win_autorun' }, { module: 'win_local_admin_audit' }, { module: 'win_credential_manager_audit' },
];

export const LOCK_IDS = Object.keys(LOCKS);

export default {
  type: 'locks',
  title: { standard: 'Settings and locks', city: 'Lock Run' },
  concepts: ['auto-updates', 'disk-encryption', 'lock-screen', 'couldnt-check'],
  covers,
  decisions,
  research,
  practice,
  render,
  summary,
};
