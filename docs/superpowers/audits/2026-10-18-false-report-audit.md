# False-report audit: macOS 26.3.1

**Date:** 2026-10-18. **Machine:** Apple silicon MacBook Pro (M3 Max), macOS 26.3.1 (25D771280a).
**Why:** the tester said "It still says my Mac's firewall is off, which is also not true. Make sure
that all the checks that are showing up are based on the real data." Find My Mac had already been
fixed for the same reason (commit 3210f94): macOS 26 moved a setting, and a value the check couldn't
read was reported as "off".

**Method:** one full read-only scan (`rescue scan --json --no-attribution`). Each critical and warning
finding was then checked against a read-only command run directly on this Mac (`socketfilterfw`,
`fdesetup status`, `defaults read`, `plutil -p`, `pmset -g`, `system_profiler`, `tmutil
destinationinfo`, `sysadminctl -screenLock status`, `cupsctl`, `launchctl print`, `netstat`,
`ifconfig`, read-only `sqlite3` of the user TCC.db, and so on). Nothing was changed on the Mac: no
`sudo`, no `--auto`/`--yes`, and System Settings was never opened. Serials, account emails, tokens,
MAC addresses, hostnames and personal file names are redacted.

## Bottom line

| Verdict | Count (critical + warning findings) |
|---|---|
| TRUE: this Mac really has it | 55 |
| FALSE: the check was wrong | 31 |
| CAN'T TELL: transient, or not independently re-derived | 20 |

All 31 false reports trace back to a fixed root cause in 24 modules. Every fix has a regression test
built from the real (redacted) output seen on this Mac. Finding codes stay the same. Where a check
can't read a setting it now gives an info-level "couldn't check" finding with a new `*_unknown`
code, and never says "off".

### The firewall

Two modules read the firewall's state:

- `firewall_rules_audit` ran `defaults read /Library/Preferences/com.apple.alf globalstate`. macOS
  15 stopped keeping the firewall's state in that file, and on macOS 26 the file isn't there at all.
  The command failed, the failure counted as "off", and the result was a **critical** "Your Mac's
  firewall is turned off". The truth here is `socketfilterfw --getglobalstate` → `Firewall is
  enabled. (State = 1)`. The module now reads `socketfilterfw` for the global state, stealth mode,
  block-all and allow-signed. Its `--listapps` parser also missed the two-line format and counted
  0 apps when there were 38.
- `firewall_audit` already used `socketfilterfw`, but it only looked for the word "disabled". So it
  missed macOS 15+'s `Firewall stealth mode is off`, and it said nothing when the tool couldn't run.

Both modules now share pure parsers in `rescue/macos_firewall.py`, which return on, off or unknown.

### Root causes of the false reports

| Pattern | Modules |
|---|---|
| Read a place macOS 15/26 no longer writes; treated "missing" as "off" | firewall_rules_audit (alf.plist), handoff_continuity + airdrop_config (Bluetooth `ControllerPowerState`), appleid_security_check (auto-update `AutomaticCheckEnabled`), lock_screen_check (`askForPassword`), wifi_diagnostics (`airport` tool, removed in 14.4) |
| Read a domain/file that never held the setting | appleid_security_check (`com.apple.iCloudKeychain`), handoff_continuity + icloud_status (`com.apple.iCloud.plist`), sharing_services (printer sharing from AFP prefs) |
| Admin/root refusal read as "off" | time_sync_check (`systemsetup`), filevault_recovery + disk_encryption_recovery (`fdesetup has*recoverykey`; also "unknown" rendered as "present") |
| Parser didn't match real output | battery_health (Apple silicon `MaxCapacity` is a %), default_browser (LSHandlers key order), audio_troubleshoot (device nesting), crash_log_analyzer + app_crash_analyzer + application_crash_report (`<process>-<date>.ips` names), vpn_config (`*` lines skipped), spotlight_repair (`Index is read-only.`), hostname_check (space counted as a symbol) |
| Wrong source of truth | filesystem_health_check (`Encrypted:` of the sealed System volume), time_machine_check (plist exists ⇒ "set up"), sharing_preferences_audit (substring of per-user helper labels), ssh_key_audit (known_hosts counted as a private key), sudo_touchid (no iBridge on Apple silicon), network_diagnostics (tunnel pseudo-interfaces) |
| "Couldn't check" shown as a warning | backup_status, filevault_recovery, disk_encryption_recovery |

### Info findings with the same pattern (also fixed)

`icloud_status` ("iCloud is not signed in"), `airdrop_config` ("Bluetooth is disabled"),
`sudo_touchid` ("No Touch ID hardware detected"), `vpn_config` ("No VPN configured"),
`handoff_continuity` ("Handoff is disabled" for an absent key; now couldn't-check), `time_sync_check`
("Automatic timezone setting is off" for an absent key), `filesystem_health_check` ("Your storage
type: Unknown"; macOS 26 prints `Type (Bundle):`), and the FileVault recovery summaries
("Personal recovery key: present" when unknown).

### Fixed after review

- **Screen Sharing / File Sharing that is on could never be reported** (`sharing_services`). The
  exact-label check ran against the user's `launchctl list`, which never lists the system daemons
  `com.apple.screensharing` and `com.apple.smbd`. Every sharing module now uses
  `rescue/macos_launchd.py` to read `launchctl print system/<label>`, which needs no admin
  (loaded → on; `Could not find service` → off; anything else → couldn't check).
- **Remote Login read as "off" without admin** (`remote_login_check`, `sharing_services`,
  `sharing_preferences_audit`). `systemsetup -getremotelogin` needs admin, and its refusal was
  read as "off". For a security check that misses a real problem, so it is not a safe default.
  Remote Login now comes from `launchctl print system/com.openssh.sshd`, and Remote Apple Events
  from `system/com.apple.AEServer`. `systemsetup` is only a fallback, and only its exact "On/Off"
  answer counts. Unreadable services get an info "couldn't check" (`sharing_unknown`,
  `remote_access_unknown`), and "all disabled" is no longer claimed when something couldn't be read.
- `sharing_services`: a failed `cupsctl` now means unknown, not off. `airdrop_config`: unreadable
  Bluetooth means unknown. `audio_troubleshoot`: matches the exact `Audio` heading, and an empty
  device list is a "couldn't check". `appleid_security_check`: says "Security updates only" when
  only `CriticalUpdateInstall` is on. `default_browser`: a bundle id containing a quote never
  reaches the `mdfind` query.
- `docs/commands.md` lists every `socketfilterfw` command again: the argument lists are now literal.
- All ten new `*_unknown` codes point to their parent finding's walkthrough.

### Not fixed (noted for follow-up)

1. `spotlight_status`, `spotlight_rebuild` (info): still treat `Index is read-only.` as "indexing
   disabled".
2. `vpn_leak_check` (warning, claim correct): its `vpn_configs` data holds "Available", picked up
   from the `scutil --nc list` header line.
3. `icloud_storage_check` (info): reports iCloud Drive and Photos as "disabled". This audit didn't
   confirm or rule that out.
4. `sudo_touchid` (info): the fingerprint count comes from counting `bioutil -rs` lines, so it is
   wrong (7 on this Mac).
5. `sharing_services`, `remote_login_check` (warning when on): Remote Management is still read from
   the user's `launchctl list` (`com.apple.RemoteDesktop.agent`) and from the RemoteManagement and
   RemoteDesktop preference files, and `remote_login_check` also reads Screen Sharing from
   `ARD_AllLocalUsers`. Neither was checked on a Mac with Remote Management on. A preference file
   left over from an old setup can read as "on", and an unreadable state still reads as "off".

## Triage table (critical and warning findings from the first scan)

| # | Sev | Module | Code | What it claimed | Ground truth (command → output, redacted) | Verdict | Root cause (if false) / note |
|---|---|---|---|---|---|---|---|
| 1 | critical | `crash_log_analyzer` | `—` | browser has crashed 19 times in the last 7 days | `~/Library/Logs/DiagnosticReports`: 19 `browser_crashpad_handler-*.ips` in 7 days (bug_type 309, EXC_BREAKPOINT); no `browser-*` reports | **FALSE** | Name split on `_`: `browser_crashpad_handler` (crash-reporter helper) counted as `browser`. Now `rescue/crash_reports.py`. |
| 2 | critical | `crash_log_analyzer` | `—` | chrome has crashed 88 times in the last 7 days | 88 `chrome_crashpad_handler-*.ips` in 7 days (EXC_BREAKPOINT, parent launchd); no Chrome app crashes | **FALSE** | Same: Chrome's crash-reporter helper counted as Chrome. |
| 3 | critical | `disk_space` | `—` | Your disk /System/Volumes/Data is 97% full | `df -h /System/Volumes/Data` → 94–100% used during the audit | **TRUE** |  |
| 4 | critical | `firewall_rules_audit` | `security.firewall_rules_audit.alf_disabled` | Your Mac's firewall is turned off | `socketfilterfw --getglobalstate` → `Firewall is enabled. (State = 1)`; `/Library/Preferences/com.apple.alf.plist` → No such file | **FALSE** | Read `defaults read /Library/Preferences/com.apple.alf globalstate`; that plist is gone on macOS 15+/26, failure read as off. Now socketfilterfw; unreadable → `alf_unknown` info. |
| 5 | critical | `resource_hog_identifier` | `—` | opencode is using a lot of your computer's power | point-in-time CPU sample at scan time; not reproducible later | **CAN'T TELL** | Transient. |
| 6 | critical | `resource_hog_identifier` | `—` | python is using a lot of your computer's power | point-in-time CPU sample (the scan itself / test runs) | **CAN'T TELL** | Transient. |
| 7 | critical | `time_machine_health` | `—` | No Time Machine backup destination is set up | `tmutil destinationinfo` → `tmutil: No destinations configured.` | **TRUE** |  |
| 8 | warning | `accessibility_permissions` | `security.accessibility_permissions.excessive_accessibility` | Many apps can control your Mac (14) | TCC.db (read-only) Accessibility grants: 14 | **TRUE** |  |
| 9 | warning | `accessibility_permissions` | `security.accessibility_permissions.suspicious_accessibility` | Apps you may not recognize can control your Mac (11) | the 11 bundle IDs listed do hold Accessibility (Claude, OBS, Loom, Wispr Flow…) | **TRUE** | Real grants; 'may not recognize' is a judgement, not a claim of malware. |
| 10 | warning | `ai_worm_filesystem` | `security.ai_worm_filesystem.obfuscated_script` | Script downloads and runs code: <personal file>.js | file exists and matches the download-and-run pattern; contents not inspected (personal file) | **CAN'T TELL** |  |
| 11 | warning | `ai_worm_filesystem` | `security.ai_worm_filesystem.obfuscated_script` | Script downloads and runs code: <personal file>.js | file exists and matches the download-and-run pattern; contents not inspected (personal file) | **CAN'T TELL** |  |
| 12 | warning | `app_crash_analyzer` | `—` | browser keeps crashing (19 times in 7 days) | as above (browser_crashpad_handler) | **FALSE** | `stem.split('_')[0]`; same parser fix. |
| 13 | warning | `app_crash_analyzer` | `—` | chrome keeps crashing (88 times in 7 days) | as above (chrome_crashpad_handler) | **FALSE** | Same. |
| 14 | warning | `app_permissions` | `security.app_permissions.accessibility_access` | 14 app(s) can control your Mac | TCC.db Accessibility grants: 14 | **TRUE** |  |
| 15 | warning | `appleid_security_check` | `security.appleid_security_check.autoupdate_disabled` | Your Mac doesn't install updates automatically | `defaults read /Library/Preferences/com.apple.SoftwareUpdate` → `AutomaticallyInstallMacOSUpdates = 1; CriticalUpdateInstall = 1; AutomaticDownload = 1`; `AutomaticCheckEnabled` absent | **FALSE** | Read only AutomaticCheckEnabled (absent = default on) and treated missing as off. Now reads the whole domain; unknown → `autoupdate_unknown` info. |
| 16 | warning | `appleid_security_check` | `security.appleid_security_check.icloud_keychain` | iCloud Keychain is disabled | `MobileMeAccounts.plist` → service `KEYCHAIN_SYNC` `Enabled = true`; `com.apple.iCloudKeychain` domain does not exist | **FALSE** | Read a preferences domain macOS never creates. Now KEYCHAIN_SYNC; unknown → `icloud_keychain_unknown` info. |
| 17 | warning | `application_crash_report` | `—` | App 'browser' crashed 42 times recently | 42 `browser_crashpad_handler-*.ips` total | **FALSE** | `rsplit('_', 2)`; same parser fix. |
| 18 | warning | `application_crash_report` | `—` | App 'chrome' crashed 108 times recently | 108 `chrome_crashpad_handler-*.ips` total | **FALSE** | Same. |
| 19 | warning | `audio_config` | `—` | Your volume is set very low (0%) | `osascript -e 'get volume settings'` → `output volume:0 … output muted:true` | **TRUE** |  |
| 20 | warning | `audio_troubleshoot` | `—` | No microphone was found on your Mac | `system_profiler SPAudioDataType` lists `MacBook Pro Microphone` (Default Input Device: Yes) and two USB mics | **FALSE** | Parser expected devices at 4 spaces; real output nests them at 8 under `Devices:`, so it found one device named 'Devices'. |
| 21 | warning | `audio_troubleshoot` | `—` | Your Mac's volume is set to zero | same as above | **TRUE** |  |
| 22 | warning | `automatic_updates` | `security.automatic_updates.app_store_auto` | App Store apps are not updating automatically | `defaults read /Library/Preferences/com.apple.commerce AutoUpdate` → `0` | **TRUE** |  |
| 23 | warning | `backup_status` | `—` | No backup drive is set up for Time Machine | `tmutil destinationinfo` → No destinations configured | **TRUE** | Text no longer claims 'Time Machine is on'. |
| 24 | warning | `backup_status` | `—` | We couldn't check your backup status | Time Machine's on/off state isn't readable without admin | **FALSE** | A couldn't-check shown as a warning. Now info. |
| 25 | warning | `battery_health` | `—` | Your battery holds 1.6% of its original power | `system_profiler SPPowerDataType` → `Maximum Capacity: 85%`, `Condition: Normal`; ioreg `MaxCapacity = 100`, `DesignCapacity = 6249`, `AppleRawMaxCapacity = 5265` | **FALSE** | Divided MaxCapacity (a % on Apple silicon) by DesignCapacity (mAh): 100/6249 = 1.6%. |
| 26 | warning | `browser_cache_cleanup` | `—` | Chrome is storing a large amount of temporary files (4.0 GB) | `du -sh ~/Library/Caches/Google` → 4.2G | **TRUE** |  |
| 27 | warning | `chrome_extensions` | `security.chrome_extensions.broad_permissions` | Extension with broad permissions: Claude | manifest grants `<all_urls>` / `http(s)://*/*` (checked Claude, LastPass, Sprint Reader; OneTab via localized manifest) | **TRUE** |  |
| 28 | warning | `chrome_extensions` | `security.chrome_extensions.broad_permissions` | Extension with broad permissions: LastPass: Free Password Manager | manifest grants `<all_urls>` / `http(s)://*/*` (checked Claude, LastPass, Sprint Reader; OneTab via localized manifest) | **TRUE** |  |
| 29 | warning | `chrome_extensions` | `security.chrome_extensions.broad_permissions` | Extension with broad permissions: OneTab | manifest grants `<all_urls>` / `http(s)://*/*` (checked Claude, LastPass, Sprint Reader; OneTab via localized manifest) | **TRUE** |  |
| 30 | warning | `chrome_extensions` | `security.chrome_extensions.broad_permissions` | Extension with broad permissions: Sprint Reader - Speed Reading Extension | manifest grants `<all_urls>` / `http(s)://*/*` (checked Claude, LastPass, Sprint Reader; OneTab via localized manifest) | **TRUE** |  |
| 31 | warning | `clamav_scanner` | `security.clamav_scanner.clamav_not_installed` | You don't have ClamAV antivirus installed | `which clamscan` → not found | **TRUE** | Opinion that one is needed; the fact is right. |
| 32 | warning | `crash_log_analyzer` | `—` | ExcUserFault has crashed 4 times in the last 7 days | 3 `ExcUserFault_qlmanage-*.ips` in 7 days | **FALSE** | Misnamed (`ExcUserFault` instead of `ExcUserFault_qlmanage`, a Quick Look user fault); fixed by the same parser. |
| 33 | warning | `crypto_miner_detect` | `security.crypto_miner_detect.high_cpu_process` | A program called python3 is using a lot of power | point-in-time CPU sample of python3 (test/scan processes) | **CAN'T TELL** | Transient. |
| 34 | warning | `default_browser` | `—` | Your default browser '-' might be missing | `LSHandlers` entry for https: `LSHandlerRoleAll = "com.google.chrome"`; Chrome at /Applications | **FALSE** | Took the next `LSHandlerRoleAll` after the scheme line; macOS sorts keys so it read the next entry's nested `"-"`. Now parses whole entries. |
| 35 | warning | `disk_encryption_recovery` | `security.disk_encryption_recovery.recovery_key_unknown` | We couldn't check if your Mac has a disk recovery key | `fdesetup haspersonalrecoverykey` → `Error: This command requires root access.` | **FALSE** | Couldn't-check shown as a warning, and the summary said 'present' for 'unknown'. Now info + 'couldn't check'. |
| 36 | warning | `disk_permissions_repair` | `—` | Your /usr/local folder is locked by the system | `ls -ld /usr/local` → `root wheel` | **TRUE** | macOS default; Homebrew on Apple silicon uses /opt/homebrew. |
| 37 | warning | `dns_config` | `—` | Your Mac is using DNS servers we don't recognize: 45.90.28.163, 45.90.30.163 | resolvers 45.90.28.163 / 45.90.30.163 (NextDNS) configured | **TRUE** |  |
| 38 | warning | `energy_saver_check` | `—` | Your Mac is set to never sleep | `pmset -g custom` AC Power: `sleep 0` | **TRUE** | On AC only (battery: 1 min). |
| 39 | warning | `energy_saver_check` | `—` | Your screen is set to never turn off | `pmset -g custom` AC Power: `displaysleep 0` | **TRUE** | On AC only. |
| 40 | warning | `energy_settings` | `—` | Power Nap is enabled | `pmset -g` → `powernap 1` | **TRUE** |  |
| 41 | warning | `energy_settings` | `—` | Your Mac is set to never sleep | `pmset -g custom` AC `sleep 0` | **TRUE** |  |
| 42 | warning | `filesystem_health_check` | `—` | Your laptop's data isn't encrypted | `fdesetup status` → `FileVault is On.`; `diskutil info /` → `Encrypted: No`, `FileVault: Yes` | **FALSE** | Read `Encrypted:` of the sealed System volume (always No). Now fdesetup, then diskutil's `FileVault:`; unknown no longer = unencrypted. |
| 43 | warning | `filevault_recovery` | `security.filevault_recovery.recovery_key_unknown` | We could not check your FileVault recovery key | `fdesetup haspersonalrecoverykey` → requires root | **FALSE** | Couldn't-check as warning + 'present' summary. Now info + 'couldn't check'. |
| 44 | warning | `firewall_rules_audit` | `security.firewall_rules_audit.allow_signed_enabled` | Firewall automatically allows signed apps | `socketfilterfw --getallowsigned` → built-in and downloaded signed software ENABLED | **TRUE** | Apple's default; real setting. |
| 45 | warning | `font_issues` | `—` | Several fonts are installed in more than one place (1) | not independently checked | **CAN'T TELL** |  |
| 46 | warning | `handoff_continuity` | `—` | Bluetooth is off | `system_profiler SPBluetoothDataType` → `State: On`; `defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState` → does not exist | **FALSE** | Read a key macOS 26 no longer writes; missing = off. Now system_profiler; unknown → info. |
| 47 | warning | `handoff_continuity` | `—` | Bluetooth is off, so some Apple features won't work | same | **FALSE** | Same. |
| 48 | warning | `handoff_continuity` | `—` | iCloud is not signed in | `defaults read MobileMeAccounts Accounts` → an account with `AccountID`, `LoggedIn = 1` | **FALSE** | Read a `com.apple.iCloud.plist` domain that doesn't exist. Now MobileMeAccounts. |
| 49 | warning | `hostname_check` | `—` | Your computer's name has a space in it | ComputerName contains a space | **TRUE** | Apple's default name; low value but true. |
| 50 | warning | `hostname_check` | `—` | Your computer's name has unusual symbols | the only non-alphanumeric character is the space | **FALSE** | Counted the space a second time as a symbol. |
| 51 | warning | `hostname_check` | `—` | Your computer's two names don't match | `scutil --get ComputerName` = `MacBook Pro`, `LocalHostName` = `MacBook-Pro-2` | **TRUE** | They differ (macOS added -2). |
| 52 | warning | `hosts_file_check` | `security.hosts_file_check.suspicious_ip_redirect` | 1 website names are being redirected to unusual addresses | `/etc/hosts` has 1 Adobe creativecloud entry pointing at a public IP | **TRUE** |  |
| 53 | warning | `kernel_panic_check` | `—` | Your Mac crashed 1 times in the last 30 days | `/Library/Logs/DiagnosticReports/panic-full-2026-10-07-…panic`: userspace watchdog timeout (WindowServer) | **TRUE** |  |
| 54 | warning | `kext_audit` | `security.kext_audit.kext_file` | Old-style driver file found: HighPointIOP | `/Library/Extensions/{HighPointIOP,HighPointRR,usbserial}.kext` exist | **TRUE** |  |
| 55 | warning | `kext_audit` | `security.kext_audit.kext_file` | Old-style driver file found: HighPointRR | `/Library/Extensions/{HighPointIOP,HighPointRR,usbserial}.kext` exist | **TRUE** |  |
| 56 | warning | `kext_audit` | `security.kext_audit.kext_file` | Old-style driver file found: usbserial | `/Library/Extensions/{HighPointIOP,HighPointRR,usbserial}.kext` exist | **TRUE** |  |
| 57 | warning | `launch_agent_audit` | `security.launch_agent_audit.missing_program` | Background task 'com.<user>.calendar-sync' points to a missing file | plist's ProgramArguments[0] (`~/src/<project>/.venv/bin/python`) → No such file | **TRUE** |  |
| 58 | warning | `launch_agent_audit` | `security.launch_agent_audit.suspicious_path` | Background task 'ai.hermes.gateway-<name>' runs from a hidden folder | program is `~/.hermes/…/venv/bin/python` | **TRUE** | Hidden folder, but the user's own agent. |
| 59 | warning | `launch_agent_audit` | `security.launch_agent_audit.suspicious_path` | Background task 'ai.hermes.gateway-<name>' runs from a hidden folder | program is `~/.hermes/…/venv/bin/python` | **TRUE** | Hidden folder, but the user's own agent. |
| 60 | warning | `launchd_persistence_audit` | `security.launchd_persistence_audit.suspicious_path` | Background task runs from a hidden folder: ai.hermes.gateway-<name> | same as above | **TRUE** |  |
| 61 | warning | `launchd_persistence_audit` | `security.launchd_persistence_audit.suspicious_path` | Background task runs from a hidden folder: ai.hermes.gateway-<name> | same as above | **TRUE** |  |
| 62 | warning | `library_cache_cleanup` | `—` | Your app cache folders are using a lot of space (10.2 GB) | `du -sh ~/Library/Caches` → 9.9G | **TRUE** |  |
| 63 | warning | `library_cache_cleanup` | `—` | Your Google cache is taking up a lot of space (4.0 GB) | `du -sh ~/Library/Caches/Google` → 4.2G | **TRUE** |  |
| 64 | warning | `lock_screen_check` | `security.lock_screen_check.display_sleep` | Your Mac screen never turns off automatically | `pmset -g` → `displaysleep 0` (AC) | **TRUE** |  |
| 65 | warning | `lock_screen_check` | `security.lock_screen_check.screensaver_password` | Your Mac does not ask for a password after the screen saver starts | `sysadminctl -screenLock status` → `screenLock delay is immediate`; `defaults read com.apple.screensaver askForPassword` → does not exist | **FALSE** | Anything but askForPassword=1 counted as off; the key is absent on current macOS. Now sysadminctl; unknown → `screensaver_password_unknown` info. |
| 66 | warning | `login_items` | `—` | Known extra software starts at login: Dropbox | System Events login items: Amical, Dropbox, PacketTunnelMacex, Speedify | **TRUE** |  |
| 67 | warning | `login_items_cleanup` | `—` | Many apps start automatically (40) | count from launch agents + login items; not recounted | **CAN'T TELL** |  |
| 68 | warning | `login_items_cleanup` | `—` | Old startup entries for missing apps (1) | calendar-sync agent's program is missing (above) | **TRUE** |  |
| 69 | warning | `login_items_cleanup` | `—` | Some startup apps use a lot of power (5) | not independently checked | **CAN'T TELL** |  |
| 70 | warning | `login_password_policy` | `security.login_password_policy.screensaver_timeout` | Screensaver waits 60 minutes | `defaults -currentHost read com.apple.screensaver idleTime` → 3600 | **TRUE** |  |
| 71 | warning | `memory_pressure` | `—` | Your Mac is leaning on swap, disk space used as memory (5.6 GB) | `sysctl vm.swapusage` → used 5673M of 7168M | **TRUE** |  |
| 72 | warning | `memory_pressure_check` | `—` | Your computer is using 79.4% of its swap (overflow memory on disk) | same (79%) | **TRUE** |  |
| 73 | warning | `network_connections_monitor` | `security.network_connections_monitor.unusual_ports` | Connections on uncommon ports (1) | `netstat -an` LISTEN includes 1883, 5000, 7000, 8765, 8766 … | **TRUE** | Local dev servers. |
| 74 | warning | `network_diagnostics` | `—` | Your gif0 connection is off | `ifconfig gif0` → `flags=8010<POINTOPOINT,MULTICAST>` (tunnel pseudo-interface) | **FALSE** | Reported a tunnel pseudo-interface that's always down as a connection that's off. Now skipped. |
| 75 | warning | `network_diagnostics` | `—` | Your stf0 connection is off | `ifconfig stf0` → `flags=0<>` (6to4 pseudo-interface) | **FALSE** | Same. |
| 76 | warning | `network_interface_audit` | `—` | Wi-Fi is not your top priority connection | `networksetup -listnetworkserviceorder` → Wi-Fi is #12 | **TRUE** |  |
| 77 | warning | `power_settings` | `—` | Your Mac is set to never sleep | `pmset -g custom` AC Power: `sleep 0` | **TRUE** |  |
| 78 | warning | `privacy_permissions_audit` | `security.privacy_permissions_audit.camera_microphone_combo` | Apps with both camera and microphone access (15) | camera grants 15 (TCC.db); intersection not recomputed | **CAN'T TELL** |  |
| 79 | warning | `privacy_permissions_audit` | `security.privacy_permissions_audit.excessive_camera` | Many apps can use your camera (15) | TCC.db camera grants (auth_value=2): 15 | **TRUE** |  |
| 80 | warning | `privacy_permissions_audit` | `security.privacy_permissions_audit.excessive_microphone` | Many apps can use your microphone (41) | TCC.db microphone grants: 41 | **TRUE** |  |
| 81 | warning | `privacy_permissions_audit` | `security.privacy_permissions_audit.screen_accessibility_combo` | Apps with screen recording and control access (7) | not recomputed (screen-capture grants live in the system TCC.db) | **CAN'T TELL** |  |
| 82 | warning | `router_security_audit` | `—` | Your router's SSH is open to all devices | `nc -z -G 2 192.168.0.1 22` → succeeded | **TRUE** |  |
| 83 | warning | `screen_lock_check` | `security.screen_lock_check.screensaver_idle_time` | Your screensaver waits 60 minutes to start | `defaults -currentHost read com.apple.screensaver idleTime` → 3600 | **TRUE** |  |
| 84 | warning | `security_baseline_diff` | `security.security_baseline_diff.new_browser_extension` | 1 new browser extension(s) since 2026-10-10T18:44:55+00:00 | compared with the 2026-10-10 baseline Device Rescue saved; not re-derived | **CAN'T TELL** |  |
| 85 | warning | `security_baseline_diff` | `security.security_baseline_diff.new_listening_port` | 7 new listening port(s) since 2026-10-10T18:44:55+00:00 | compared with the 2026-10-10 baseline Device Rescue saved; not re-derived | **CAN'T TELL** |  |
| 86 | warning | `security_baseline_diff` | `security.security_baseline_diff.new_persistence` | 1 new persistence item(s) since 2026-10-10T18:44:55+00:00 | compared with the 2026-10-10 baseline Device Rescue saved; not re-derived | **CAN'T TELL** |  |
| 87 | warning | `session_revocation_scan` | `security.session_revocation_scan.ssh_authorized_keys` | 1 saved key(s) could let another computer log in to this one | `~/.ssh/authorized_keys` has 1 key | **TRUE** |  |
| 88 | warning | `sharing_preferences_audit` | `security.sharing_preferences_audit.screen_sharing` | Screen Sharing is enabled on your Mac | `launchctl print system/com.apple.screensharing` → Could not find service; nothing listening on 5900; user `launchctl list` has only `com.apple.screensharing.agent/.menuextra/.MessagesAgent` | **FALSE** | Substring match on per-user helper labels. Now exact label + system daemon check. |
| 89 | warning | `sharing_services` | `security.sharing_services.printer_sharing` | Printer Sharing is enabled on your Mac | `cupsctl` → `_share_printers=0` | **FALSE** | Read the AFP file server's prefs (exist on most Macs). Now cupsctl. |
| 90 | warning | `sleep_wake_issues` | `—` | Bluetooth devices can wake your Mac from sleep | not independently checked | **CAN'T TELL** |  |
| 91 | warning | `spotlight_repair` | `—` | Spotlight search is turned off on your main drive | `mdutil -s /` → `Index is read-only.`; `mdfind` returns results (Spotlight works) | **FALSE** | Anything but 'Indexing enabled' = off. Only 'Indexing disabled' is off now; else info couldn't-confirm. |
| 92 | warning | `ssh_key_audit` | `security.ssh_key_audit.bad_key_perms` | Your private key google_compute_known_hosts is open to other users | `~/.ssh/google_compute_known_hosts` begins `compute.<id> ssh-ed25519 AAAA…` (public host keys, gcloud) | **FALSE** | `ssh-keygen -l` also fingerprints public-key files, so a known_hosts file counted as a private key. |
| 93 | warning | `startup_optimizer` | `—` | 32 apps start automatically in the background | not recounted | **CAN'T TELL** |  |
| 94 | warning | `suspicious_connections` | `security.suspicious_connections.unusual_listening_port` | node is waiting for connections from other devices on port 8765, 8766 | `netstat -an` → node listening on *.8765 and *.8766 | **TRUE** | Local dev server. |
| 95 | warning | `suspicious_processes` | `security.suspicious_processes.high_cpu` | Programs using a lot of power: 3 | point-in-time CPU sample | **CAN'T TELL** | Transient. |
| 96 | warning | `system_extensions_check` | `—` | No extra security software is installed | no third-party security system extensions | **TRUE** |  |
| 97 | warning | `system_log_errors` | `—` | Found 4978 errors from known Mac issues | counts from `log show` at scan time; not re-run | **CAN'T TELL** |  |
| 98 | warning | `system_log_errors` | `—` | Your Mac logged 77828 errors in the last hour | counts from `log show` at scan time; not re-run | **CAN'T TELL** |  |
| 99 | warning | `temp_file_scanner` | `—` | Found 77.4 GB of reclaimable disk space | not re-measured | **CAN'T TELL** |  |
| 100 | warning | `time_machine_check` | `—` | We could not check your last backup date | `tmutil destinationinfo` → No destinations configured; com.apple.TimeMachine.plist holds only `PreferencesVersion = 6` | **FALSE** | 'Plist readable' counted as 'Time Machine is set up'. Now tmutil destinationinfo; reports not-configured instead. |
| 101 | warning | `time_sync_check` | `—` | Your Mac is not syncing its clock automatically | `systemsetup -getusingnetworktime` → `You need administrator access to run this tool... exiting!`; timed running with `server time.apple.com` | **FALSE** | The admin-refusal text has no 'On', so it read as off. Now only 'Network Time: On/Off' counts; else info. |
| 102 | warning | `update_checker` | `—` | 199 outdated Homebrew package(s) | `HOMEBREW_NO_AUTO_UPDATE=1 brew outdated --quiet \| wc -l` → 199 | **TRUE** |  |
| 103 | warning | `update_checker` | `—` | 2 macOS update(s) available | `softwareupdate -l` not re-run (network); SoftwareUpdate prefs list pending product keys | **CAN'T TELL** |  |
| 104 | warning | `vpn_leak_check` | `—` | Your VPN is set up but not currently connected | `scutil --nc list` → Speedify VPN `(Disconnected)` | **TRUE** | (its `vpn_configs` data says 'Available', a header-parsing slip; claim is right) |
| 105 | warning | `wifi_diagnostics` | `—` | Wi-Fi is off or unavailable | `networksetup -getairportpower en0` → On; `system_profiler SPAirPortDataType` → `Status: Connected`, -39 dBm; airport tool absent | **FALSE** | Used the `airport` tool (removed in macOS 14.4); its absence = 'Wi-Fi off'. Now system_profiler; unreadable → info. |
| 106 | warning | `wifi_password_recovery` | `—` | You have a lot of saved Wi-Fi networks (197) | `networksetup -listpreferredwirelessnetworks en0` → 197 networks | **TRUE** |  |

## After the fixes: each fixed module re-run read-only on this Mac

Each module was re-run with `rescue run <module> < /dev/null` (stdin closed, so no fix gets applied),
and the full scan was run once more. Critical and warning findings went from 106 to 89. None of the
31 false reports came back. The corrected checks now surface three true findings that the old code
hid.

| Module | New output on this Mac |
|---|---|
| `firewall_rules_audit` | warning *Your Mac responds to network pings* (stealth off: TRUE), warning *Many apps are allowed through your firewall (38)* (TRUE, was 0), warning *allows signed apps* (TRUE), info summary `Firewall: On / Stealth Mode: Off / Block All Incoming: No / Allow Signed Software: Yes / Allowed Applications: 38`. No "firewall is turned off". |
| `firewall_audit` | warning *Your Mac responds to network pings* (now sees `Firewall stealth mode is off`). |
| `crash_log_analyzer`, `app_crash_analyzer`, `application_crash_report` | Now name `chrome_crashpad_handler` (88 in 7 days), `browser_crashpad_handler` (19), `ExcUserFault_qlmanage` (3): the real processes. |
| `appleid_security_check` | info only: `Apple ID signed in: Yes / iCloud Keychain: Enabled / Automatic updates: Enabled`. |
| `audio_troubleshoot` | info device list (11 devices) + warning volume is zero (TRUE). No "no microphone". |
| `backup_status` | warning *No backup drive is set up* (TRUE), couldn't-check now **info**. |
| `battery_health` | No issues (85%, Normal). |
| `default_browser` | info `Google Chrome (com.google.chrome)`, a standard app. |
| `filesystem_health_check` | info `Disk encryption status: Yes`; storage type now reads APFS. |
| `filevault_recovery`, `disk_encryption_recovery` | info couldn't-check (needs root); summary says `Personal recovery key: couldn't check`. |
| `handoff_continuity` | info: *Couldn't check whether Handoff is on*, *Bluetooth is on*, *Wi-Fi is on*, *iCloud is signed in*. |
| `hostname_check` | space + names-differ warnings remain (TRUE); "unusual symbols" gone. |
| `lock_screen_check` | only warning *screen never turns off* (TRUE on AC). |
| `network_diagnostics` | no gif0/stf0 findings. |
| `sharing_preferences_audit` | info *Sharing services are properly disabled*. |
| `sharing_services` | No issues: Screen Sharing, File Sharing and Remote Login read as off via `launchctl print system/<label>` (`Could not find service`), printer sharing off via `cupsctl`. |
| `remote_login_check` | info *All remote access services are disabled*, now read without admin (`com.openssh.sshd` and `com.apple.AEServer` not loaded). |
| `spotlight_repair` | info *Couldn't confirm Spotlight indexing* (macOS said "Index is read-only."). |
| `ssh_key_audit` | info only; known_hosts files no longer listed as keys. |
| `time_machine_check` | critical *Your Mac is not automatically backing up your files* (TRUE: no destination). |
| `time_sync_check` | info *Couldn't check whether your clock sets itself* (needs admin). |
| `wifi_diagnostics` | No issues (connected, -39 dBm). |
| `icloud_status` (info) | *iCloud account signed in*. |
| `airdrop_config` (info) | no "Bluetooth is disabled". |
| `sudo_touchid` (info) | *Touch ID hardware detected*. Its fingerprint count (7) comes from counting `bioutil -rs` lines and is wrong. This is info only; noted for follow-up. |
| `vpn_config` (info) | *Your VPN settings (1 found)*. |

Verification (after merging main and the review fixes): `uv run python scripts/generate_integrity_manifest.py`, plus regenerating
`docs/commands.md`, `docs/REMEDIATION_CATALOG.md` and `docs/modules.md` (`--check` clean); `pytest
-q` → 4329 passed, 7 skipped; `ruff check` → clean.
