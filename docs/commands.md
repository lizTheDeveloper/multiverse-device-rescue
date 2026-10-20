# What each check runs

!!! info "This page is generated"
    Written by `python scripts/generate_command_catalog.py` from the module
    source code. CI runs it with `--check`, so it cannot drift from what ships.
    Do not edit it by hand.

Every check in Reclaim City is a Python file under `modules/`. Most of them
gather evidence by running ordinary system commands — the same ones you could
type yourself. This page lists, for every check, each command it can run.

- `…` marks an argument filled in at runtime (a path, a user name, a value
  read from an earlier command).
- **Built at runtime** counts calls whose program name itself is computed, so
  it cannot be shown here.
- Which commands actually run depends on the platform and on what each earlier
  command returned. To see exactly what ran on *your* machine, with exit codes
  and timings:

```console
$ rescue scan --trace --json > results.json      # commands stream to stderr
$ rescue scan --trace --profile digital_security_reset --json 2> trace.jsonl >/dev/null
```

In the desktop app, open **Show technical details** while a checkup runs.

Besides commands, checks read files (launch agents, browser profiles, logs)
directly; read a module's `__init__.py` for the full picture. No check writes
anything — `fix()` is separate and always asks first.


## Bloatware

### `login_items`

```text
osascript -e 'tell application "System Events" to get the name of every login item'
```

### `process_scanner`

Runs no external commands; reads files and system APIs only.

### `startup_auditor`

```text
launchctl list
launchctl unload -w …
```

### `win_bloatware`

```text
powershell -Command 'Get-AppxPackage | Select-Object Name, Publisher | ConvertTo-Csv -NoTypeInformation'
```

## Integrity

### `accessibility_check`

```text
defaults read -g …
defaults read …
```

### `airport_wifi_scan`


Plus 2 command(s) built at runtime.

### `app_crash_analyzer`

Runs no external commands; reads files and system APIs only.

### `application_compatibility`

```text
arch -x86_64 /usr/bin/true
system_profiler SPApplicationsDataType
```

### `application_crash_report`

Runs no external commands; reads files and system APIs only.

### `audio_config`

```text
defaults read -g com.apple.sound.beep.muted
defaults read -g com.apple.sound.default.output
osascript -e 'output volume of (get volume settings)'
system_profiler SPAudioDataType
```

### `audio_troubleshoot`

```text
defaults read -g com.apple.sound.beep.muted
defaults read -g com.apple.sound.default.input
defaults read -g com.apple.sound.default.output
osascript -e 'output volume of (get volume settings)'
system_profiler SPAudioDataType
```

### `backup_status`

```text
defaults read /Library/Preferences/com.apple.TimeMachine AutoBackup
tmutil destinationinfo
tmutil latestbackup
```

### `battery_health`

```text
ioreg -l
system_profiler SPPowerDataType
```

### `bluetooth_diagnostics`

```text
system_profiler SPBluetoothDataType
```

### `core_services_reset`


Plus 1 command(s) built at runtime.

### `coreaudio_reset`

```text
defaults read -g com.apple.sound.default.output
pgrep -x coreaudiod
system_profiler SPAudioDataType
```

### `crash_log_analyzer`

Runs no external commands; reads files and system APIs only.

### `default_browser`

```text
defaults read com.apple.LaunchServices/com.apple.launchservices.secure LSHandlers
duti -x …
mdfind …
```

### `directory_permissions`

Runs no external commands; reads files and system APIs only.

### `disk_health`

```text
diskutil info /
```

### `disk_permissions_repair`

```text
stat -f %Su …
```

### `disk_smart_check`

```text
df -B1 /
diskutil apfs list
diskutil info /
system_profiler SPNVMeDataType
system_profiler SPStorageDataType
```

### `disk_utility_firstaid`

```text
diskutil info /
diskutil verifyVolume /
```

### `display_config`

```text
defaults read com.apple.AppleDisplayBrightness
defaults read com.apple.CoreBrightness
defaults read com.apple.CoreBrightness CBUser
system_profiler SPDisplaysDataType
```

### `display_issues`

```text
defaults read com.apple.CoreBrightness
defaults read com.apple.CoreBrightness CBUser
defaults read com.apple.windowserver DisplayResolutionEnabled
system_profiler SPDisplaysDataType
```

### `dns_config`

```text
networksetup -getdnsservers …
scutil --dns
```

### `filesystem_health_check`

```text
df -i /
diskutil apfs list
diskutil info /
diskutil verifyVolume /
fdesetup status
```

### `font_issues`

```text
find … -type f '(' -name '*.ttf' -o -name '*.otf' -o -name '*.ttc' -o -name '*.dfont' ')'
```

### `gpu_health`

```text
log show --predicate 'eventMessage contains "GPU"' --last 7d --style compact
system_profiler SPDisplaysDataType
```

### `handoff_continuity`

```text
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState
defaults read MobileMeAccounts Accounts
defaults read com.apple.coreservices.useractivityd ActivityReceivingAllowed
networksetup -getairportpower en0
system_profiler SPBluetoothDataType
```

### `homebrew_health`

```text
brew doctor
brew list --json=v1
brew outdated --json=v1
which brew
```

### `hostname_check`

```text
scutil --get …
```

### `icloud_status`

```text
defaults read '~/Library/Preferences/com.apple.iCloud.plist' ForceSyncEnabled
defaults read MobileMeAccounts Accounts
defaults read com.apple.iCloud.plist Enabled
defaults read com.apple.iCloud.plist iCloudDrive
```

### `icloud_storage`

```text
defaults read com.apple.iCloud.plist DesktopAndDocumentsManagedByiCloud
defaults read com.apple.iCloud.plist MobileMeAccounts
defaults read com.apple.iCloud.plist iCloudDriveEnabled
```

### `icloud_storage_check`

```text
brctl status
```

### `input_devices`

```text
defaults read -g …
defaults read …
system_profiler SPBluetoothDataType
system_profiler SPUSBDataType
```

### `kernel_panic_check`

Runs no external commands; reads files and system APIs only.

### `keychain_health`

```text
security default-keychain
security list-keychains
security show-keychain-info …
```

### `linux_journal_errors`

```text
journalctl --priority=0..4 … --no-pager --quiet
```

### `linux_package_updates`

```text
apt list --upgradable
dnf --quiet check-update
dnf --quiet check-update --security
pacman -Qu
zypper --quiet list-patches --category security
zypper --quiet list-updates
```

### `linux_service_health`

```text
systemctl is-active …
systemctl list-units --failed --no-legend --plain --no-pager
systemctl list-units --type=service --state=running --no-legend --plain --no-pager
systemctl show … --property=NRestarts
```

### `login_keychain_repair`

```text
security default-keychain
security show-keychain-info …
```

### `macos_eol_check`

```text
sw_vers -buildVersion
sw_vers -productVersion
sysctl hw.model
```

### `macos_version_support`

```text
sw_vers -buildVersion
sw_vers -productVersion
sysctl hw.model
system_profiler SPHardwareDataType
uname -m
```

### `mail_config`

```text
defaults read com.apple.mail AutoFetchingEnabled
defaults read com.apple.mail MailAccounts
defaults read com.apple.mail PollInterval
```

### `network_diagnostics`

```text
ifconfig
ping -c 1 -W 1 8.8.8.8
ping -c 1 -W 1 …
scutil --dns
```

### `network_interface_audit`

```text
networksetup -getinfo …
networksetup -listallnetworkservices
networksetup -listnetworkserviceorder
```

### `network_interfaces_check`

```text
networksetup -getdnsservers …
networksetup -getinfo …
networksetup -getipv6 …
networksetup -listallnetworkservices
networksetup -listnetworkserviceorder
```

### `network_proxy_detect`

```text
networksetup -getautoproxyurl …
networksetup -getsecurewebproxy …
networksetup -getsocksfirewallproxy …
networksetup -getwebproxy …
```

### `network_speed_test`

```text
dig google.com +stats
ping -c 5 8.8.8.8
ping -c 5 …
route -n get default
system_profiler SPAirPortDataType
```

### `notifications_config`

```text
defaults read com.apple.controlcenter 'NSStatusItem Visible FocusModes'
defaults read com.apple.ncprefs doNotDisturb
defaults read com.apple.ncprefs focusSchedules
defaults read com.apple.ncprefs show_in_lockscreen
defaults read …
```

### `photos_library_check`

```text
defaults read com.apple.photolibraryd CloudPhotoLibraryDownloadOriginalEnabled
defaults read com.apple.photolibraryd CloudPhotoLibraryOptimizeStorageEnabled
defaults read com.apple.photolibraryd PQLCloudEnabled
```

### `pram_nvram_check`

```text
bless --info --getBoot
nvram -xp
nvram boot-args
```

### `printer_diagnostics`

```text
lpstat -d
lpstat -o
lpstat -p
lpstat -r
```

### `printer_queue`

```text
lpstat -o
lpstat -p
```

### `recovery_partition_check`

```text
diskutil info …
diskutil list
```

### `rosetta_status`

```text
arch -x86_64 /usr/bin/true
sysctl -n machdep.cpu.brand_string
uname -m
```

### `safe_boot_check`

```text
bless --info --getBoot
nvram boot-args
sysctl kern.boottime
sysctl kern.safeboot
```

### `safe_mode_check`

```text
bless --info --getBoot
diskutil info /
nvram boot-args
sysctl -n kern.boottime
sysctl -n kern.safeboot
```

### `screen_time_password`

```text
defaults read com.apple.ScreenTimeAgent ScreenTimePasscodeSet
defaults read com.apple.applicationaccess
defaults read …
dscl . -list /Users
dscl . -read /Groups/admin GroupMembership
dscl . -read … ParentalControls
dscl . -read … UniqueID UserShell IsHidden NFSHomeDirectory
```

### `sleep_wake_issues`

```text
defaults read /Library/Preferences/com.apple.Bluetooth
pmset -g assertions
pmset -g log
pmset -g sched
```

### `smart_status`

```text
diskutil info /
system_profiler SPNVMeDataType
system_profiler SPStorageDataType
```

### `smc_reset_check`

```text
pmset -g batt
pmset -g therm
sysctl -n machdep.cpu.brand_string
system_profiler SPPowerDataType
```

### `smcreset_guide`

```text
powermetrics --samplers smc -n 1
sysctl hw.model
system_profiler SPDisplaysDataType
system_profiler SPHardwareDataType
system_profiler SPPowerDataType
```

### `software_inventory`

```text
system_profiler SPApplicationsDataType -json
```

### `system_age_check`

```text
stat -f %SB /var/db/.AppleSetupDone
sw_vers -buildVersion
sw_vers -productVersion
system_profiler SPHardwareDataType
```

### `system_extensions_check`

```text
systemextensionsctl list
```

### `system_log_errors`


Plus 1 command(s) built at runtime.

### `time_machine_check`

```text
defaults read /Library/Preferences/com.apple.TimeMachine
defaults read /Library/Preferences/com.apple.TimeMachine ExcludeByPath
tmutil destinationinfo
tmutil latestbackup
tmutil status
```

### `time_machine_exclusions`

```text
defaults read /Library/Preferences/com.apple.TimeMachine ExcludeByPath
tmutil isexcluded …
```

### `time_machine_health`

```text
log show --predicate 'subsystem == "com.apple.TimeMachine"' --last 24h --style compact
tmutil destinationinfo
tmutil latestbackup
tmutil status
```

### `time_sync_check`

```text
date
defaults read /Library/Preferences/com.apple.timezone.auto Active
systemsetup -getnetworktimeserver
systemsetup -getusingnetworktime
```

### `update_checker`

```text
brew outdated
softwareupdate -l
```

### `usb_devices_check`

```text
system_profiler SPUSBDataType
```

### `user_account_health`

```text
defaults read …
dscl . -list /Users UniqueID
dscl . -read … NFSHomeDirectory
dscl . -read … UserShell
```

### `wifi_diagnostics`

```text
system_profiler SPAirPortDataType
```

Plus 1 command(s) built at runtime.

### `wifi_password_recovery`

```text
networksetup -listpreferredwirelessnetworks en0
```

Plus 1 command(s) built at runtime.

### `win_activation`

```text
powershell -NoProfile -Command …
```

### `win_activation_check`


Plus 1 command(s) built at runtime.

### `win_audio_check`

```text
powershell -NoProfile -Command …
sc query …
```

### `win_battery`

```text
powershell -NoProfile -Command …
```

### `win_bluetooth_check`

```text
powershell -NoProfile -Command …
sc query bthserv
```

### `win_boot_config_check`

```text
bcdedit /enum
bcdedit /enum '{bootmgr}'
bcdedit /enum '{current}'
powershell -NoProfile -Command Confirm-SecureBootUEFI
powershell -NoProfile -Command …
reagentc /info
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' /v HiberbootEnabled
```

### `win_bsod_analysis`

```text
powershell -NoProfile -Command …
```

### `win_disk_health`

```text
powershell -NoProfile -Command …
```

### `win_dism_health`

```text
Dism.exe /Online /Cleanup-Image /AnalyzeComponentStore
Dism.exe /Online /Cleanup-Image /CheckHealth
powershell -NoProfile -Command …
```

### `win_display_check`

```text
powershell -NoProfile -Command …
```

### `win_dns_config`

```text
powershell -NoProfile -Command 'Get-DnsClientCache | Measure-Object | Select-Object -ExpandProperty Count'
powershell -NoProfile -Command 'Get-DnsClientServerAddress -AddressFamily IPv4 | Select-Object -ExpandProperty ServerAddresses'
powershell -NoProfile -Command 'Measure-Command { Resolve-DnsName google.com } | Select-Object -ExpandProperty TotalMilliseconds'
```

### `win_driver_check`

```text
driverquery
driverquery /v /fo CSV
powershell -NoProfile -Command …
```

### `win_event_errors`


Plus 2 command(s) built at runtime.

### `win_event_log_health`

```text
powershell -NoProfile -Command …
sc query EventLog
```

### `win_memory_diagnostics`

```text
powershell -NoProfile -Command …
```

### `win_network_adapters`

```text
powershell -NoProfile -Command …
```

### `win_network_diag`

```text
ipconfig /all
netsh winhttp show proxy
nslookup google.com
ping -n 1 8.8.8.8
```

### `win_network_reset`

```text
netsh winsock show catalog
powershell -Command 'Get-Service Dhcp | Select-Object Status'
powershell -Command 'Get-Service Dnscache | Select-Object Status'
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Winsock2\\Parameters\\Protocol_Catalog9\\Catalog_Entries'
```

### `win_print_spooler_check`

```text
powershell -NoProfile -Command …
sc query Spooler
```

### `win_printer_check`

```text
powershell -NoProfile -Command …
sc query Spooler
```

### `win_printer_issues`

```text
powershell -NoProfile -Command 'Get-PrintJob | Measure-Object | Select-Object Count'
powershell -NoProfile -Command 'Get-Printer | Select-Object Name, DriverName, PortName, PrinterStatus, Shared | Format-List'
powershell -NoProfile -Command 'Get-Printer | Select-Object Name, PrinterStatus | ConvertTo-Csv -NoTypeInformation'
powershell -NoProfile -Command 'Get-Service Spooler | Select-Object Status'
```

### `win_recovery_options`

```text
powershell -NoProfile -Command …
reagentc /info
vssadmin list shadows
```

### `win_restore_points`

```text
powershell -NoProfile -Command …
vssadmin list shadows
```

### `win_safe_mode_check`

```text
bcdedit /enum '{current}'
bcdedit /enum bootmgr
powershell -NoProfile -Command …
```

### `win_sfc_check`

```text
powershell -NoProfile -Command …
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager' /v PendingFileRenameOperations
```

### `win_shadow_copies_check`

```text
reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\SystemRestore' /v RPSessionInterval
sc qc VSS
sc query VSS
vssadmin list shadows
vssadmin list shadowstorage
```

### `win_startup_repair`

```text
bcdedit /enum
bcdedit /enum '{bootmgr}'
bcdedit /enum '{current}'
bcdedit /enum '{recoverysequence}'
powershell -NoProfile -Command …
```

### `win_update_history`

```text
powershell -NoProfile -Command …
sc query wuauserv
```

### `win_updates`

```text
powershell -NoProfile -Command 'Get-Service -Name wuauserv | ConvertTo-Json'
powershell -NoProfile -Command 'Start-Service -Name wuauserv'
```

### `win_wifi_diagnostics`

```text
netsh wlan show drivers
netsh wlan show interfaces
netsh wlan show profiles
```

### `win_windows_update_status`

```text
powershell -NoProfile -Command …
sc query wuauserv
```

### `win_winsock_check`

```text
netsh winsock show catalog
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters'
```

### `win_wmi_health`

```text
powershell -NoProfile -Command …
sc query winmgmt
winmgmt /verifyrepository
```

## Network

### `arp_spoof_check`

```text
arp -a
arp -a -n
arp -an
ip neigh show
ip route show default
route -n get default
route print -4
```

### `dns_over_https_check`

```text
profiles list
ps aux
scutil --dns
```

### `ethernet_diagnostics`

```text
ifconfig …
netstat -i
networksetup -listallhardwareports
system_profiler SPEthernetDataType
```

### `lan_common`

```text
arp -a
arp -a -n
arp -an
ip neigh show
ip route show default
route -n get default
route print -4
```

### `lan_device_inventory`

```text
arp -a
arp -a -n
arp -an
ip neigh show
ip route show default
route -n get default
route print -4
```

### `network_proxy_check`

```text
networksetup -getautoproxyurl …
networksetup -getproxybypassdomains …
networksetup -getsecurewebproxy …
networksetup -getsocksfirewallproxy …
networksetup -getwebproxy …
networksetup -listallnetworkservices
```

### `router_security_audit`

```text
arp -a
arp -a -n
arp -an
ip neigh show
ip route show default
route -n get default
route print -4
```

Also opens network connections directly from Python (sockets), without an external command.

### `vpn_leak_check`

```text
netstat -rn
scutil --dns
scutil --nc list
scutil --nc status …
```

### `wifi_security_audit`

```text
networksetup -getairportnetwork en0
networksetup -listpreferredwirelessnetworks en0
system_profiler SPAirPortDataType
```

## Performance

### `browser_cache_cleanup`

Runs no external commands; reads files and system APIs only.

### `clamshell_mode`

```text
pmset -g
system_profiler SPDisplaysDataType
```

### `disk_fragmentation_check`

```text
df -b /
diskutil info /
```

### `disk_io_health`

```text
iostat -d 1 2
system_profiler SPNVMeDataType
system_profiler SPSerialATADataType
system_profiler SPStorageDataType
```

### `disk_space`

Runs no external commands; reads files and system APIs only.

### `docker_cleanup`

```text
docker images -f dangling=true -q
docker ps -a -f status=exited -q
docker system df --format '{{json .}}'
which docker
```

### `energy_saver_check`

```text
pmset -g
pmset -g sched
```

### `energy_settings`

```text
pmset -g
```

### `font_cache`

```text
pgrep -f atsutil
```

### `font_cache_repair`

```text
atsutil databases -list
atsutil server -ping
find /private/var/folders -name com.apple.ATS -type d
system_profiler SPFontsDataType
```

### `large_files_finder`


Plus 1 command(s) built at runtime.

### `library_cache_cleanup`

Runs no external commands; reads files and system APIs only.

### `linux_memory_pressure`

Runs no external commands; reads files and system APIs only.

### `login_items_cleanup`


Plus 1 command(s) built at runtime.

### `macos_user_cleanup`

```text
dscl . -list /Users UniqueID
dscl . -read … NFSHomeDirectory
du -sk …
last -t yyyymmddHHmmss …
```

### `mail_attachment_cleanup`

Runs no external commands; reads files and system APIs only.

### `memory_pressure`

```text
sysctl hw.memsize
sysctl vm.swapusage
vm_stat
```

### `memory_pressure_check`

```text
memory_pressure
sysctl hw.memsize
sysctl hw.pagesize
sysctl vm.compressor_mode
sysctl vm.swapusage
vm_stat
```

### `network_quality`

```text
networkQuality -s -v
ping -c 4 -W 2000 8.8.8.8
```

### `notification_center_check`

```text
defaults read …
```

### `power_settings`

```text
pmset -g
```

### `resource_hog_identifier`

Runs no external commands; reads files and system APIs only.

### `screen_resolution_scaling`

```text
system_profiler SPDisplaysDataType
```

### `spotlight_rebuild`

```text
mdutil -s /
ps -eo pid,pcpu,comm
```

### `spotlight_repair`

```text
defaults read com.apple.Spotlight orderedItems
mdutil -s /
ps -eo pid,pcpu,comm
```

### `spotlight_status`

```text
defaults read com.apple.Spotlight orderedItems
mdutil -s /
```

### `startup_optimizer`

```text
launchctl list
```

### `storage_cleanup`

Runs no external commands; reads files and system APIs only.

### `swap_memory_check`

```text
sysctl kern.memorystatus_vm_pressure_level
sysctl vm.swapusage
vm_stat
```

### `swap_usage`

```text
sysctl kern.memorystatus_vm_pressure_level
sysctl vm.compressor_mode
sysctl vm.swapusage
```

### `temp_file_scanner`

Runs no external commands; reads files and system APIs only.

### `thermal_throttle`

```text
pmset -g therm
sysctl hw.cpufrequency
sysctl hw.cpufrequency_max
```

### `thermal_throttle_check`

```text
ioreg -r -n AppleSMC
ioreg -r -n AppleSMCFan
pmset -g thermlog
sudo powermetrics --samplers smc -n 1 -i 100
sysctl hw.cpufrequency
sysctl hw.cpufrequency_max
```

### `trash_cleanup`

Runs no external commands; reads files and system APIs only.

### `user_profile_size`

```text
du -sk …
```

### `win_boot_time`

```text
powershell -NoProfile -Command "$event = Get-WinEvent -FilterHashtable @{LogName='System'; ID=12} -MaxEvents 1 -ErrorAction SilentlyContinue; if ($event) { $event.Properties[0].Value } else { 'N/A' }"
powershell -NoProfile -Command '(Get-CimInstance Win32_OperatingSystem).LastBootUpTime'
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Power' /v HiberbootEnabled
```

### `win_disk_cleanup`


Plus 3 command(s) built at runtime.

### `win_disk_space`

```text
wmic logicaldisk get size,freespace,caption
```

### `win_pagefile`

```text
powershell -NoProfile -Command …
```

### `win_pagefile_check`

```text
powershell -NoProfile -Command …
```

### `win_power_plan`

```text
powercfg /getactivescheme
powercfg /list
```

### `win_power_plan_check`

```text
powercfg /getactivescheme
powercfg /query SCHEME_CURRENT 2a737441-1930-4402-8d77-b2bebba308a3 48e6b7a6-50f5-4782-a5d4-53bb8f07e226
powercfg /query SCHEME_CURRENT SUB_DISK DISKIDLE
powercfg /query SCHEME_CURRENT SUB_PROCESSOR PROCTHROTTLEMAX
powercfg /query SCHEME_CURRENT SUB_SLEEP STANDBYIDLE
```

### `win_search_index`

```text
powershell -Command '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows Search" -Name DataDirectory -ErrorAction SilentlyContinue).DataDirectory'
powershell -Command '(Get-ItemProperty "HKLM:\\SOFTWARE\\Microsoft\\Windows Search\\CrawlScopeManager\\Windows\\SystemIndex" -ErrorAction SilentlyContinue | Select-Object -ExpandProperty ItemCount)'
powershell -Command '(Get-Process SearchIndexer -ErrorAction SilentlyContinue | Select-Object -ExpandProperty CPU)'
powershell -Command 'Get-Service WSearch | Select-Object -ExpandProperty Status'
powershell -Command …
```

### `win_startup`

```text
wmic startup list full
```

### `win_startup_programs_audit`

```text
powershell -NoProfile -Command "$items = @(); $paths = @(  [System.Environment]::GetFolderPath('Startup'),   [System.Environment]::GetFolderPath('CommonStartup') ); foreach ($path in $paths) {   if (Test-Path $path) {     Get-ChildItem $path -ErrorAction SilentlyContinue |     ForEach-Object {       $items += @{         name = $_.Name;         path = $_.FullName;         command = $_.FullName       }     }   } }; ConvertTo-Json $items -AsArray"
powershell -NoProfile -Command '$items = @(); Get-CimInstance Win32_StartupCommand -ErrorAction SilentlyContinue | ForEach-Object {   $items += @{     name = $_.Name;     command = $_.Command;     location = $_.Location;     user = $_.User   } }; ConvertTo-Json $items -AsArray'
reg query …
schtasks /query /fo CSV /v
```

### `win_temp_cleanup`


Plus 2 command(s) built at runtime.

### `win_temp_files`


Plus 2 command(s) built at runtime.

### `win_temp_files_cleanup`


Plus 6 command(s) built at runtime.

### `win_user_profiles`


Plus 3 command(s) built at runtime.

### `win_visual_effects`

```text
reg query 'HKCU\\Control Panel\\Desktop\\WindowMetrics' /v MinAnimate
reg query 'HKCU\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Themes\\Personalize' /v EnableTransparency
reg query 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\VisualEffects' /v VisualFXSetting
```

### `xcode_cleanup`

Runs no external commands; reads files and system APIs only.

## Security

### `accessibility_permissions`

```text
sqlite3 … "SELECT client FROM access WHERE service='kTCCServiceAccessibility' AND auth_value=2"
```

### `ai_threat_indicators`

```text
crontab -l
lsof -i -n -P
ps aux
```

### `ai_worm_filesystem`

Runs no external commands; reads files and system APIs only.

### `ai_worm_git_ssh`

```text
git config --global --unset …
git config --global …
```

### `ai_worm_iocs`

Runs no external commands; reads files and system APIs only.

### `ai_worm_lateral`

```text
lsof -i -n -P
npm whoami
```

### `ai_worm_network`

```text
ps aux
```

Plus 1 command(s) built at runtime.

### `ai_worm_persistence`

```text
launchctl unload …
schtasks /Delete /TN … /F
schtasks /Query /FO CSV /V
systemctl --user disable …
systemctl --user stop …
```

### `airdrop_config`

```text
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState
defaults read com.apple.sharingd DiscoverableMode
networksetup -getairportpower en0
system_profiler SPBluetoothDataType
```

### `airdrop_security_check`

```text
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState
defaults read com.apple.Bluetooth PrefKeyServicesEnabled
defaults read com.apple.sharingd DiscoverableMode
defaults read … ActivityAdvertisingAllowed
networksetup -getairportpower en0
```

### `antivirus_status`

```text
defaults read … CFBundleShortVersionString
ls /Applications
mdfind …
pgrep -i …
```

### `app_permissions`

```text
sqlite3 … 'SELECT client, service, auth_value FROM access WHERE auth_value=2'
```

### `appleid_security_check`

```text
defaults read /Library/Preferences/com.apple.SoftwareUpdate
defaults read com.apple.mail-shared MailPrivacyProtectionEnabled
defaults read … AppleIDAccount
defaults read … ICloudPrivateRelayEnabled
system_profiler SPiCloudDataType
```

### `automatic_updates`

```text
defaults read …
```

### `bluetooth_audit`

```text
defaults read /Library/Preferences/com.apple.Bluetooth ControllerPowerState
defaults read /Library/Preferences/com.apple.Bluetooth DiscoverableState
system_profiler SPBluetoothDataType
```

### `browser_cryptojacking_check`

Runs no external commands; reads files and system APIs only.

### `browser_extension_audit`

```text
pluginkit -mAD -p com.apple.Safari.extension
```

### `browser_hijack_check`

```text
defaults read com.apple.Safari HomePage
defaults read com.apple.Safari SearchProviderIdentifier
```

### `browser_privacy_check`

```text
defaults read com.apple.Safari
security find-internet-password -l ''
```

### `certificate_audit`

```text
openssl x509 -noout -enddate
openssl x509 -noout -issuer -subject
security find-certificate -a -c '' -Z /Library/Keychains/System.keychain
security find-certificate -a -c '' -Z /Library/Keychains/login.keychain-db
security find-certificate -c … -p /Library/Keychains/System.keychain
security find-certificate -c … -p /Library/Keychains/login.keychain-db
```

### `certificate_trust_audit`

```text
openssl x509 -noout -issuer
openssl x509 -noout -subject -dates
security dump-trust-settings …
security find-certificate -a -p /Library/Keychains/System.keychain
```

### `chrome_extensions`

Runs no external commands; reads files and system APIs only.

### `clamav_scanner`

```text
clamscan --version
pgrep clamd
sigtool --info …
which …
```

### `code_signature_audit`

```text
codesign --verify --deep --strict …
powershell -NoProfile -Command …
spctl --assess --type execute …
```

### `cron_jobs_audit`

```text
atq
cat /etc/crontab
cat …
crontab -l
ls -1 /etc/cron.d/
ls -1 …
```

### `crypto_miner_detect`

```text
lsof -i -n -P
ps -eo pid,pcpu,comm
ps aux
```

### `crypto_miner_persistence`

```text
crontab -l
reg query …
schtasks /query /fo csv /v
```

### `cryptojacking_iocs`

Runs no external commands; reads files and system APIs only.

### `disk_encryption_recovery`

```text
dscl . -list /Users
fdesetup hasinstitutionalrecoverykey
fdesetup haspersonalrecoverykey
fdesetup list
fdesetup status
```

### `dns_poisoning_check`

```text
defaults read /Library/Preferences/com.apple.networkd DNSSettings
dig +short …
networksetup -getdnsservers Wi-Fi
route -n get default
scutil --dns
```

### `encryption_check`

```text
fdesetup status
```

### `evidence_bundle`


Plus 1 command(s) built at runtime.

### `filevault_recovery`

```text
dscl . -list /Users
fdesetup hasinstitutionalrecoverykey
fdesetup haspersonalrecoverykey
fdesetup list
fdesetup status
```

### `find_my_mac_check`

```text
defaults read /var/db/locationd/Library/Preferences/ByHost/com.apple.locationd LocationServicesEnabled
defaults read …
system_profiler SPHardwareDataType
```

### `firewall_audit`

```text
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on
/usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on
```

### `firewall_rules_audit`

```text
/usr/libexec/ApplicationFirewall/socketfilterfw --getallowsigned
/usr/libexec/ApplicationFirewall/socketfilterfw --getblockall
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
/usr/libexec/ApplicationFirewall/socketfilterfw --getstealthmode
/usr/libexec/ApplicationFirewall/socketfilterfw --listapps
```

### `firmware_password`

```text
/usr/bin/uname -m
/usr/libexec/firmwarepasswd -check
```

### `gatekeeper_quarantine_check`

```text
/usr/bin/csrutil status
/usr/bin/xattr -p com.apple.quarantine …
/usr/sbin/spctl --assess --type execute --verbose /Applications/Safari.app
/usr/sbin/spctl --status
```

### `guest_account_check`

```text
defaults read /Library/Preferences/SystemConfiguration/com.apple.smb.server AllowGuestAccess
defaults read /Library/Preferences/com.apple.AppleFileServer guestAccess
defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
```

### `hosts_file_check`

Runs no external commands; reads files and system APIs only.

### `kernel_extensions_audit`

```text
kextstat
kmutil showloaded
```

### `kext_audit`

```text
find … -name '*.kext' -type d
kextstat
```

### `keylogger_indicators`

```text
/usr/bin/csreq -r - -t
log show --last 1h --predicate "eventMessage CONTAINS 'CGEventTap' AND processImagePath != '/usr/bin/log'" --style compact
sqlite3 … "SELECT client FROM access WHERE service='kTCCServiceListenEvent' AND auth_value=2"
sqlite3 … "SELECT hex(client), client_type, hex(csreq) FROM access WHERE service='kTCCServiceListenEvent' AND auth_value=2"
```

### `launch_agent_audit`

Runs no external commands; reads files and system APIs only.

### `launchd_persistence_audit`

Runs no external commands; reads files and system APIs only.

### `linux_account_audit`

Runs no external commands; reads files and system APIs only.

### `linux_disk_encryption_check`

```text
fscryptctl get_policy …
lsblk -o NAME,TYPE,FSTYPE,MOUNTPOINT -P
zfs get -H -o value encryption …
```

### `linux_firewall_check`

```text
firewall-cmd --state
iptables -S INPUT
nft list ruleset
ufw status verbose
```

### `linux_persistence_audit`

```text
crontab -l
```

### `linux_ssh_hardening`

```text
sshd -T
systemctl is-active ssh
systemctl is-active sshd
```

### `location_services`

```text
defaults read /Library/Preferences/com.apple.locationmenu.plist
defaults read com.apple.locationd LocationServicesEnabled
defaults read com.apple.locationd SystemServices
defaults read com.apple.locationmenu
sysctl hw.model
system_profiler SPHardwareDataType
```

### `lock_screen_check`

```text
defaults read com.apple.screensaver askForPassword
defaults read com.apple.screensaver askForPasswordDelay
pmset -g
sysadminctl -screenLock status
```

### `login_password_policy`

```text
defaults -currentHost read …
defaults read …
dscl . -read …
systemsetup …
```

### `login_window_settings`

```text
defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint
defaults read /Library/Preferences/com.apple.loginwindow SHOWFULLNAME
defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser
```

### `malware_scan_indicators`

```text
defaults read … Label
find … -name '*.plist' -type f
mdfind …
```

### `mdm_enrollment`

```text
/usr/bin/profiles list -verbose
/usr/bin/profiles status
/usr/bin/profiles status -type enrollment
```

### `mdm_enrollment_check`

```text
profiles list -verbose
profiles status -type bootstraptoken
profiles status -type enrollment
sudo profiles list -verbose
```

### `mvt_spyware_scan`


Plus 1 command(s) built at runtime.

### `network_connections_monitor`

```text
lsof -i -nP
```

### `network_proxy`

```text
networksetup -getautoproxyurl …
networksetup -getproxyautodiscovery …
networksetup -getsecurewebproxy …
networksetup -getsocksfirewallproxy …
networksetup -getwebproxy …
```

### `open_ports_scan`

```text
lsof -iTCP -sTCP:LISTEN -nP
```

### `privacy_audit`

```text
defaults read …
```

### `privacy_permissions_audit`

```text
sqlite3 …
```

### `remote_login_check`

```text
defaults read /Library/Preferences/com.apple.RemoteDesktop
defaults read /Library/Preferences/com.apple.RemoteManagement ARD_AllLocalUsers
launchctl print system/com.apple.AEServer
launchctl print system/com.apple.screensharing
launchctl print system/com.openssh.sshd
systemsetup -getremoteappleevents
systemsetup -getremotelogin
```

### `rootkit_check`

```text
/bin/ps -eo pid
/usr/bin/codesign -v …
/usr/bin/csrutil status
/usr/sbin/kextstat
/usr/sbin/sysctl kern.proc.all
```

### `safari_extensions`

```text
pluginkit -mAD -p com.apple.Safari.content-blocker
pluginkit -mAD -p com.apple.Safari.extension
```

### `scheduled_tasks_audit`

Runs no external commands; reads files and system APIs only.

### `screen_lock_check`

```text
defaults -currentHost read …
defaults read …
```

### `screen_time_audit`

```text
defaults read com.apple.ScreenTimeAgent AppLimits
defaults read com.apple.ScreenTimeAgent CommunicationLimits
defaults read com.apple.ScreenTimeAgent ScreenTimePasscodeSet
defaults read …
```

### `screen_time_parental`

```text
defaults read com.apple.ScreenTimeAgent AppLimits
defaults read com.apple.ScreenTimeAgent AskToBuyEnabled
defaults read com.apple.ScreenTimeAgent CommunicationLimits
defaults read com.apple.ScreenTimeAgent ScreenTimePasscodeSet
defaults read …
dscl . -list /Users
dscl . -read … GeneratedUID
dscl . -read … dsAttrTypeNative:isHiddenUser
```

### `security_baseline_diff`

```text
/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate
csrutil status
fdesetup status
netstat -an
powershell -NoProfile -Command '(Get-MpComputerStatus).RealTimeProtectionEnabled'
schtasks /query /fo csv
```

### `session_revocation_scan`

```text
cmdkey /list
defaults read MobileMeAccounts Accounts
```

### `sharing_preferences_audit`

```text
cupsctl
defaults read com.apple.sharingd DiscoverableMode
launchctl list
launchctl print system/com.apple.screensharing
launchctl print system/com.apple.smbd
launchctl print system/com.openssh.sshd
systemsetup -getremotelogin
```

### `sharing_services`

```text
cupsctl
launchctl list
launchctl print system/com.apple.screensharing
launchctl print system/com.apple.smbd
launchctl print system/com.openssh.sshd
```

### `sip_gatekeeper`

```text
/usr/bin/csrutil status
/usr/sbin/spctl --status
```

### `siri_privacy`

```text
defaults read …
```

### `ssh_key_audit`

```text
ssh-add -l
ssh-keygen -l -f …
```

### `stalkerware_scan`

```text
reg query … /s /v DisplayName
```

### `sudo_config_audit`

```text
cat …
dscl . -read /Users/root AuthenticationAuthority
sudo -V
sudo cat …
```

### `sudo_touchid`

```text
bioutil -rs
defaults read com.apple.ApplePay ApplePayEnabled
system_profiler SPiBridgeDataType
```

### `suspicious_connections`

```text
lsof -i -n -P
```

### `suspicious_processes`

```text
ps aux
```

### `system_extensions`

```text
systemextensionsctl list
```

### `usb_device_audit`

```text
system_profiler SPUSBDataType
```

### `user_account_audit`

```text
defaults read /Library/Preferences/com.apple.loginwindow GuestEnabled
defaults read /Library/Preferences/com.apple.loginwindow autoLoginUser
dscl . -list /Users
dscl . -read /Groups/admin GroupMembership
```

### `vpn_config`

```text
scutil --nc list
scutil --nc status …
systemextensionsctl list
```

### `win_antivirus_status`

```text
powershell -NoProfile -Command 'Get-MpComputerStatus | Select-Object AntivirusSignatureLastUpdated | ConvertTo-Json'
powershell -NoProfile -Command …
```

### `win_autorun`

```text
reg query … /v …
```

### `win_autoruns_audit`

```text
powershell -Command …
reg query … /v '*'
```

### `win_bitlocker`

```text
manage-bde -status
```

### `win_bitlocker_check`

```text
manage-bde -status
```

### `win_cortana_telemetry`

```text
reg query … /v …
```

### `win_credential_guard`

```text
net accounts
powershell -Command 'Get-LocalUser | Where-Object {$_.PasswordNeverExpires -eq $true} | Select-Object -ExpandProperty Name'
reg query 'HKLM\\SOFTWARE\\Microsoft\\PolicyManager\\default\\Settings\\AllowSignInOptions' /v value
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\DeviceGuard' /v EnableVirtualizationBasedSecurity
```

### `win_credential_manager_audit`

```text
cmdkey /list
wmic computersystem get partofdomain
```

### `win_crypto_miner_detect`

```text
netstat -ano
powershell -NoProfile -NonInteractive -Command …
```

### `win_defender`

```text
powershell -NoProfile -Command 'Get-MpComputerStatus | ConvertTo-Json'
powershell -NoProfile -Command …
```

### `win_defender_deep_check`

```text
powershell -NoProfile -Command 'Get-MpComputerStatus | ConvertTo-Json'
powershell -NoProfile -Command 'Get-MpPreference | ConvertTo-Json'
```

### `win_firewall`

```text
netsh advfirewall set … state on
netsh advfirewall show allprofiles
```

### `win_firewall_rules_audit`

```text
powershell -NoProfile -Command 'Get-NetFirewallProfile | Select-Object Name, Enabled, DefaultInboundAction, DefaultOutboundAction | ConvertTo-Json'
powershell -NoProfile -Command 'Get-NetFirewallRule -Direction Inbound -Action Allow -Enabled True | Select-Object DisplayName, Profile, Program | ConvertTo-Json'
```

### `win_group_policy_audit`

```text
auditpol /get '/category:*'
gpresult /r …
net accounts
powershell -NoProfile -Command '(Get-WmiObject Win32_ComputerSystem).PartOfDomain'
powershell -NoProfile -Command 'Get-AppLockerPolicy -Effective -Xml 2>/dev/null | Select-Object -ExpandProperty RuleCollections | Measure-Object | Select-Object -ExpandProperty Count'
powershell -NoProfile -Command …
```

### `win_hosts_file`

```text
powershell -NoProfile -Command 'Get-Content $env:windir\\System32\\drivers\\etc\\hosts'
```

### `win_hosts_file_check`

```text
powershell -NoProfile -Command '(Get-Item $env:windir\\System32\\drivers\\etc\\hosts).GetAccessControl() | Select-Object -ExpandProperty Access'
powershell -NoProfile -Command '(Get-Item $env:windir\\System32\\drivers\\etc\\hosts).Length'
powershell -NoProfile -Command 'Get-Content $env:windir\\System32\\drivers\\etc\\hosts'
```

### `win_local_admin_audit`

```text
net localgroup Administrators
net user …
powershell -Command 'Get-LocalUser -Name Administrator | Select-Object -ExpandProperty Enabled'
powershell -Command 'Get-LocalUser -Name Guest | Select-Object -ExpandProperty Enabled'
```

### `win_malware_indicators`

```text
bcdedit
powershell -NoProfile -Command …
reg query …
```

### `win_network_shares_audit`

```text
net share
powershell -Command 'Get-SmbServerConfiguration | Select-Object -ExpandProperty EnableSMB1Protocol'
powershell -Command …
```

### `win_proxy_detect`

```text
netsh winhttp show proxy
reg query 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' /v AutoConfigURL
reg query 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' /v ProxyEnable
reg query 'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings' /v ProxyServer
```

### `win_rdp_check`

```text
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' /v PortNumber
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server\\WinStations\\RDP-Tcp' /v UserAuthentication
```

### `win_remote_access_audit`

```text
reg query 'HKLM\\SOFTWARE\\AnyDesk'
reg query 'HKLM\\SOFTWARE\\LogMeIn'
reg query 'HKLM\\SOFTWARE\\WOW6432Node\\LogMeIn'
reg query 'HKLM\\SOFTWARE\\WOW6432Node\\TeamViewer'
reg query 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\Terminal Server' /v fDenyTSConnections
tasklist
```

### `win_rootkit_check`

```text
bcdedit /enum
bcdedit /enum '{current}'
powershell -NoProfile -Command "$drivers = @(); driverquery /v 2>$null | Select-Object -Skip 1 | ForEach-Object {   if ($_ -match 'No.*System32') {     $name = ($_ -split '\\s+')[0];     $drivers += $name   } }; ConvertTo-Json $drivers -AsArray"
powershell -NoProfile -Command "$files = @(); Get-Item 'C:\\Windows\\System32\\*.exe' -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ':$DATA'} | Select-Object -ExpandProperty FileName -Unique | ForEach-Object { $files += [System.IO.Path]::GetFileName($_) }; ConvertTo-Json $files -AsArray"
powershell -NoProfile -Command 'Confirm-SecureBootUEFI -ErrorAction SilentlyContinue'
powershell -NoProfile -Command 'Get-Service -ErrorAction SilentlyContinue | Select-Object -ExpandProperty Name | ConvertTo-Json'
sc query state= all
```

### `win_scheduled_tasks`

```text
powershell -NoProfile -Command …
```

### `win_scheduled_tasks_security`

```text
schtasks /query /fo CSV /v
```

### `win_services_audit`

```text
powershell -NoProfile -Command …
```

### `win_services_security_audit`

```text
powershell -Command 'Get-WmiObject Win32_Service | Select-Object Name, DisplayName, PathName, StartMode, State, StartName | ConvertTo-Json'
```

### `win_suspicious_processes`


Plus 2 command(s) built at runtime.

### `win_uac_check`

```text
reg query … /v …
```

### `win_user_accounts`

```text
net accounts
net localgroup Administrators
net user
net user Guest
reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v AutoAdminLogon
reg query 'HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Winlogon' /v DefaultUserName
```

### `xprotect_status`

```text
defaults read … Version
spctl --status
system_profiler SPInstallHistoryDataType
```
