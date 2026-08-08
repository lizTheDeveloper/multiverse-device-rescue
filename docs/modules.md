# Module catalog

!!! info "This page is generated"
    Written by `python scripts/generate_module_catalog.py` from the live
    registry (`rescue.registry.discover_modules`). CI runs the same script with
    `--check`, so this page cannot drift from the modules the tool actually
    ships. Do not edit it by hand.

A **module** is one self-contained check. It declares which platforms it can
run on, how risky its `fix()` is, and roughly how long its `check()` takes, then
returns findings. Modules never run in isolation from the rest of the
system — see [Architecture](architecture.md) for how a scan is assembled, and
[Writing a module](writing-a-module.md) for the authoring contract.

Reading the columns:

- **Platforms** — the module only runs where it declares support. Everywhere
  else it is filtered out before the scan starts, or returns
  `supported=False` with a reason. It never silently reports "no issues".
- **Risk** — the risk level of the module's `fix()`, not of its `check()`.
  Every `check()` is read-only. `safe` fixes are low-impact and reversible;
  `moderate` and `destructive` fixes always require explicit confirmation.
- **Duration** — the author's estimate for `check()`. The orchestrator
  enforces a hard 60-second per-module timeout regardless.

Run any single module directly:

```console
$ rescue run <module_name>
```


## Coverage at a glance

**287 modules** ship in the tree.

| Platform | Modules that run there |
| --- | ---: |
| macOS | 199 |
| Windows | 100 |
| Linux | 26 |

A module can support more than one platform, so these numbers add up to more than the total.

| Category | Modules |
| --- | ---: |
| [bloatware](#bloatware) | 4 |
| [integrity](#integrity) | 106 |
| [network](#network) | 8 |
| [performance](#performance) | 51 |
| [security](#security) | 118 |

## bloatware

Preinstalled and vendor software that consumes resources without being asked for.

4 modules — macOS 3, Windows 2, Linux 1.

| Module | Platforms | Risk | Duration | What it checks |
| --- | --- | --- | --- | --- |
| `login_items` | macOS | safe | 3s | — |
| `process_scanner` | macOS, Windows, Linux | moderate | 5s | — |
| `startup_auditor` | macOS | moderate | 5s | — |
| `win_bloatware` | Windows | safe | 5s | — |

## integrity

Whether the machine's own subsystems are healthy and intact: disks, updates, backups, drivers, logs, keychains, networking stacks.

106 modules — macOS 70, Windows 33, Linux 3.

| Module | Platforms | Risk | Duration | What it checks |
| --- | --- | --- | --- | --- |
| `accessibility_check` | macOS | safe | 5s | — |
| `airport_wifi_scan` | macOS | safe | 5s | — |
| `app_crash_analyzer` | macOS | safe | 10s | — |
| `application_compatibility` | macOS | safe | 10s | — |
| `application_crash_report` | macOS | safe | 10s | — |
| `audio_config` | macOS | safe | 3s | — |
| `audio_troubleshoot` | macOS | safe | 4s | — |
| `backup_status` | macOS | safe | 10s | — |
| `battery_health` | macOS | safe | 5s | — |
| `bluetooth_diagnostics` | macOS | safe | 5s | — |
| `core_services_reset` | macOS | safe | 10s | — |
| `coreaudio_reset` | macOS | safe | 4s | — |
| `crash_log_analyzer` | macOS | safe | 10s | — |
| `default_browser` | macOS | safe | 10s | — |
| `directory_permissions` | macOS | safe | 3s | — |
| `disk_health` | macOS | safe | 10s | — |
| `disk_permissions_repair` | macOS | safe | 5s | — |
| `disk_smart_check` | macOS | safe | 10s | — |
| `disk_utility_firstaid` | macOS | safe | 30s | — |
| `display_config` | macOS | safe | 3s | — |
| `display_issues` | macOS | safe | 3s | — |
| `dns_config` | macOS | safe | 5s | — |
| `filesystem_health_check` | macOS | safe | 10s | — |
| `font_issues` | macOS | safe | 10s | — |
| `gpu_health` | macOS | safe | 5s | — |
| `handoff_continuity` | macOS | safe | 5s | — |
| `homebrew_health` | macOS | safe | 15s | — |
| `hostname_check` | macOS | safe | 10s | — |
| `icloud_status` | macOS | safe | 5s | — |
| `icloud_storage` | macOS | safe | 10s | — |
| `icloud_storage_check` | macOS | safe | 10s | — |
| `input_devices` | macOS | safe | 10s | — |
| `kernel_panic_check` | macOS | safe | 5s | — |
| `keychain_health` | macOS | safe | 5s | — |
| `linux_journal_errors` | Linux | safe | 30s | Read the system journal for the errors that predict hardware failure. |
| `linux_package_updates` | Linux | safe | 45s | Are there security updates waiting, and is this release still getting them? |
| `linux_service_health` | Linux | safe | 20s | What has systemd given up on, and what keeps dying and restarting? |
| `login_keychain_repair` | macOS | safe | 10s | — |
| `macos_eol_check` | macOS | safe | 5s | — |
| `macos_version_support` | macOS | safe | 3s | — |
| `mail_config` | macOS | safe | 5s | — |
| `network_diagnostics` | macOS | safe | 10s | — |
| `network_interface_audit` | macOS | safe | 5s | — |
| `network_interfaces_check` | macOS | safe | 5s | — |
| `network_proxy_detect` | macOS | safe | 2s | — |
| `network_speed_test` | macOS | safe | 15s | — |
| `notifications_config` | macOS | safe | 5s | — |
| `photos_library_check` | macOS | safe | 5s | — |
| `pram_nvram_check` | macOS | safe | 5s | — |
| `printer_diagnostics` | macOS | safe | 10s | — |
| `printer_queue` | macOS | safe | 10s | — |
| `recovery_partition_check` | macOS | safe | 10s | — |
| `rosetta_status` | macOS | safe | 3s | — |
| `safe_boot_check` | macOS | safe | 5s | — |
| `safe_mode_check` | macOS | safe | 10s | — |
| `screen_time_password` | macOS | safe | 5s | — |
| `sleep_wake_issues` | macOS | safe | 3s | — |
| `smart_status` | macOS | safe | 5s | — |
| `smc_reset_check` | macOS | safe | 10s | — |
| `smcreset_guide` | macOS | safe | 3s | — |
| `software_inventory` | macOS | safe | 30s | — |
| `system_age_check` | macOS | safe | 5s | — |
| `system_extensions_check` | macOS | safe | 5s | — |
| `system_log_errors` | macOS | safe | 5s | — |
| `time_machine_check` | macOS | safe | 5s | — |
| `time_machine_exclusions` | macOS | safe | 5s | — |
| `time_machine_health` | macOS | safe | 15s | — |
| `time_sync_check` | macOS | safe | 5s | — |
| `update_checker` | macOS | safe | 30s | — |
| `usb_devices_check` | macOS | safe | 3s | — |
| `user_account_health` | macOS | safe | 10s | — |
| `wifi_diagnostics` | macOS | safe | 5s | — |
| `wifi_password_recovery` | macOS | safe | 3s | — |
| `win_activation` | Windows | safe | 5s | — |
| `win_activation_check` | Windows | safe | 10s | — |
| `win_audio_check` | Windows | safe | 10s | — |
| `win_battery` | Windows | safe | 5s | — |
| `win_bluetooth_check` | Windows | safe | 10s | — |
| `win_boot_config_check` | Windows | safe | 10s | — |
| `win_bsod_analysis` | Windows | safe | 10s | — |
| `win_disk_health` | Windows | safe | 15s | — |
| `win_dism_health` | Windows | safe | 30s | — |
| `win_display_check` | Windows | safe | 10s | — |
| `win_dns_config` | Windows | safe | 5s | — |
| `win_driver_check` | Windows | safe | 20s | — |
| `win_event_errors` | Windows | safe | 10s | — |
| `win_event_log_health` | Windows | safe | 10s | — |
| `win_memory_diagnostics` | Windows | safe | 10s | — |
| `win_network_adapters` | Windows | safe | 15s | — |
| `win_network_diag` | Windows | safe | 10s | — |
| `win_network_reset` | Windows | safe | 15s | — |
| `win_print_spooler_check` | Windows | safe | 20s | — |
| `win_printer_check` | Windows | safe | 10s | — |
| `win_printer_issues` | Windows | safe | 15s | — |
| `win_recovery_options` | Windows | safe | 10s | — |
| `win_restore_points` | Windows | safe | 10s | — |
| `win_safe_mode_check` | Windows | safe | 10s | — |
| `win_sfc_check` | Windows | safe | 30s | — |
| `win_shadow_copies_check` | Windows | safe | 10s | — |
| `win_startup_repair` | Windows | safe | 20s | — |
| `win_update_history` | Windows | safe | 10s | — |
| `win_updates` | Windows | moderate | 10s | — |
| `win_wifi_diagnostics` | Windows | safe | 10s | — |
| `win_windows_update_status` | Windows | safe | 20s | — |
| `win_winsock_check` | Windows | safe | 20s | — |
| `win_wmi_health` | Windows | safe | 20s | — |

## network

The local network and how this machine sits on it: interfaces, neighbours, ports, DNS, and interception.

8 modules — macOS 8, Windows 3, Linux 3.

| Module | Platforms | Risk | Duration | What it checks |
| --- | --- | --- | --- | --- |
| `arp_spoof_check` | macOS, Windows, Linux | safe | 10s | Detect ARP spoofing — someone on the network intercepting your traffic. |
| `dns_over_https_check` | macOS | safe | 5s | — |
| `ethernet_diagnostics` | macOS | safe | 10s | — |
| `lan_device_inventory` | macOS, Windows, Linux | safe | 10s | List every device currently visible on the local network. |
| `network_proxy_check` | macOS | safe | 3s | — |
| `router_security_audit` | macOS, Windows, Linux | safe | 15s | Audit the home router's exposed surface, and give the reclaim procedure. |
| `vpn_leak_check` | macOS | safe | 5s | — |
| `wifi_security_audit` | macOS | safe | 5s | — |

## performance

Why the machine is slow: CPU and memory pressure, thermals, disk space, startup load, and background work.

51 modules — macOS 35, Windows 17, Linux 3.

| Module | Platforms | Risk | Duration | What it checks |
| --- | --- | --- | --- | --- |
| `browser_cache_cleanup` | macOS | safe | 5s | — |
| `clamshell_mode` | macOS | safe | 3s | — |
| `disk_fragmentation_check` | macOS | safe | 5s | — |
| `disk_io_health` | macOS | safe | 5s | — |
| `disk_space` | macOS, Windows, Linux | safe | 5s | — |
| `docker_cleanup` | macOS | safe | 5s | — |
| `energy_saver_check` | macOS | safe | 5s | — |
| `energy_settings` | macOS | safe | 2s | — |
| `font_cache` | macOS | safe | 5s | — |
| `font_cache_repair` | macOS | safe | 5s | — |
| `large_files_finder` | macOS | safe | 30s | — |
| `library_cache_cleanup` | macOS | safe | 10s | — |
| `linux_memory_pressure` | Linux | safe | 5s | Why this Linux machine feels slow: memory, swap, and the kernel's own |
| `login_items_cleanup` | macOS | safe | 5s | — |
| `macos_user_cleanup` | macOS | safe | 10s | — |
| `mail_attachment_cleanup` | macOS | safe | 10s | — |
| `memory_pressure` | macOS | safe | 3s | — |
| `memory_pressure_check` | macOS | safe | 3s | — |
| `network_quality` | macOS | safe | 30s | — |
| `notification_center_check` | macOS | safe | 3s | — |
| `power_settings` | macOS | safe | 2s | — |
| `resource_hog_identifier` | macOS, Windows, Linux | moderate | 5s | — |
| `screen_resolution_scaling` | macOS | safe | 2s | — |
| `spotlight_rebuild` | macOS | safe | 5s | — |
| `spotlight_repair` | macOS | safe | 5s | — |
| `spotlight_status` | macOS | safe | 3s | — |
| `startup_optimizer` | macOS | safe | 5s | — |
| `storage_cleanup` | macOS | safe | 15s | — |
| `swap_memory_check` | macOS | safe | 3s | — |
| `swap_usage` | macOS | safe | 3s | — |
| `temp_file_scanner` | macOS | safe | 10s | — |
| `thermal_throttle` | macOS | safe | 3s | — |
| `thermal_throttle_check` | macOS | safe | 3s | — |
| `trash_cleanup` | macOS | safe | 5s | — |
| `user_profile_size` | macOS | safe | 10s | — |
| `win_boot_time` | Windows | safe | 5s | — |
| `win_disk_cleanup` | Windows | safe | 30s | — |
| `win_disk_space` | Windows | safe | 5s | — |
| `win_pagefile` | Windows | safe | 5s | — |
| `win_pagefile_check` | Windows | safe | 5s | — |
| `win_power_plan` | Windows | safe | 2s | — |
| `win_power_plan_check` | Windows | safe | 3s | — |
| `win_search_index` | Windows | safe | 10s | — |
| `win_startup` | Windows | safe | 5s | — |
| `win_startup_programs_audit` | Windows | safe | 10s | — |
| `win_temp_cleanup` | Windows | safe | 10s | — |
| `win_temp_files` | Windows | safe | 15s | — |
| `win_temp_files_cleanup` | Windows | safe | 30s | — |
| `win_user_profiles` | Windows | safe | 30s | — |
| `win_visual_effects` | Windows | safe | 5s | — |
| `xcode_cleanup` | macOS | safe | 10s | — |

## security

Malware and spyware indicators, persistence, remote access, credential exposure, and system hardening posture.

118 modules — macOS 83, Windows 45, Linux 16.

| Module | Platforms | Risk | Duration | What it checks |
| --- | --- | --- | --- | --- |
| `accessibility_permissions` | macOS | safe | 5s | — |
| `ai_threat_indicators` | macOS | safe | 5s | — |
| `ai_worm_filesystem` | macOS, Windows, Linux | moderate | 10s | — |
| `ai_worm_git_ssh` | macOS, Windows, Linux | moderate | 10s | — |
| `ai_worm_lateral` | macOS, Windows, Linux | moderate | 10s | — |
| `ai_worm_network` | macOS, Windows, Linux | moderate | 10s | — |
| `ai_worm_persistence` | macOS, Windows, Linux | destructive | 10s | — |
| `airdrop_config` | macOS | safe | 5s | — |
| `airdrop_security_check` | macOS | safe | 3s | — |
| `antivirus_status` | macOS | safe | 5s | — |
| `app_permissions` | macOS | safe | 5s | — |
| `appleid_security_check` | macOS | safe | 5s | — |
| `automatic_updates` | macOS | safe | 3s | — |
| `bluetooth_audit` | macOS | safe | 5s | — |
| `browser_cryptojacking_check` | macOS, Windows, Linux | safe | 20s | Detect in-browser cryptojacking (drive-by mining). |
| `browser_extension_audit` | macOS | safe | 5s | — |
| `browser_hijack_check` | macOS | safe | 2s | — |
| `browser_privacy_check` | macOS | safe | 10s | — |
| `certificate_audit` | macOS | safe | 10s | — |
| `certificate_trust_audit` | macOS | safe | 10s | — |
| `chrome_extensions` | macOS | safe | 3s | — |
| `clamav_scanner` | macOS | safe | 2s | — |
| `code_signature_audit` | macOS, Windows | safe | 60s | Check whether installed applications are actually signed by who they claim. |
| `cron_jobs_audit` | macOS | safe | 5s | — |
| `crypto_miner_detect` | macOS | safe | 5s | — |
| `crypto_miner_persistence` | macOS, Windows, Linux | safe | 15s | Detect cryptojacking that has been made to survive a reboot. |
| `disk_encryption_recovery` | macOS | safe | 5s | — |
| `dns_poisoning_check` | macOS | safe | 3s | — |
| `encryption_check` | macOS | safe | 3s | — |
| `evidence_bundle` | macOS, Windows, Linux | safe | 10s | Warn when cleanup is about to destroy the evidence of what happened. |
| `filevault_recovery` | macOS | safe | 5s | — |
| `find_my_mac` | macOS | safe | 2s | — |
| `find_my_mac_check` | macOS | safe | 3s | — |
| `firewall_audit` | macOS | moderate | 5s | — |
| `firewall_rules_audit` | macOS | safe | 5s | — |
| `firmware_password` | macOS | safe | 2s | — |
| `gatekeeper_quarantine_check` | macOS | safe | 8s | — |
| `guest_account_check` | macOS | safe | 5s | — |
| `hosts_file_check` | macOS | safe | 1s | — |
| `kernel_extensions_audit` | macOS | safe | 5s | — |
| `kext_audit` | macOS | safe | 3s | — |
| `keylogger_indicators` | macOS | safe | 10s | — |
| `launch_agent_audit` | macOS | safe | 10s | — |
| `launchd_persistence_audit` | macOS | safe | 10s | — |
| `linux_account_audit` | Linux | safe | 10s | Who can log in to this machine, and who can become root. |
| `linux_disk_encryption_check` | Linux | safe | 15s | Is the data on this machine's disks encrypted at rest? |
| `linux_firewall_check` | Linux | safe | 10s | Is anything actually filtering inbound traffic on this Linux machine? |
| `linux_persistence_audit` | Linux | safe | 20s | Inventory the places on Linux where something can arrange to run again. |
| `linux_ssh_hardening` | Linux | safe | 10s | Read the effective SSH server configuration and flag the settings that turn |
| `location_services` | macOS | safe | 3s | — |
| `lock_screen_check` | macOS | safe | 3s | — |
| `login_password_policy` | macOS | safe | 5s | — |
| `login_window_settings` | macOS | safe | 5s | — |
| `malware_scan_indicators` | macOS | safe | 15s | — |
| `mdm_enrollment` | macOS | safe | 5s | — |
| `mdm_enrollment_check` | macOS | safe | 5s | — |
| `mvt_spyware_scan` | macOS, Windows, Linux | safe | instant by default; 1-10m if backup scanning is enabled | mvt_spyware_scan: wraps Amnesty International's Mobile Verification Toolkit |
| `network_connections_monitor` | macOS | safe | 5s | — |
| `network_proxy` | macOS | safe | 2s | — |
| `open_ports_scan` | macOS | safe | 3s | — |
| `password_manager_check` | macOS, Windows | safe | 10s | Check whether this machine has a password manager, and where passwords live. |
| `privacy_audit` | macOS | safe | 5s | — |
| `privacy_permissions_audit` | macOS | safe | 5s | — |
| `remote_login_check` | macOS | safe | 10s | — |
| `rootkit_check` | macOS | safe | 5s | — |
| `safari_extensions` | macOS | safe | 3s | — |
| `scheduled_tasks_audit` | macOS | safe | 5s | — |
| `screen_lock_check` | macOS | safe | 3s | — |
| `screen_time_audit` | macOS | safe | 5s | — |
| `screen_time_parental` | macOS | safe | 5s | — |
| `security_baseline_diff` | macOS, Windows, Linux | safe | 20s | Record what this machine looks like, then report only what changed. |
| `session_revocation_scan` | macOS, Windows | safe | 15s | Inventory the sign-in surfaces that survive a password change. |
| `sharing_preferences_audit` | macOS | safe | 5s | — |
| `sharing_services` | macOS | safe | 10s | — |
| `sip_gatekeeper` | macOS | safe | 3s | — |
| `siri_privacy` | macOS | safe | 3s | — |
| `ssh_key_audit` | macOS | safe | 10s | — |
| `stalkerware_scan` | macOS, Windows, Linux | safe | 20s | Look for software installed to watch the person using this computer. |
| `sudo_config_audit` | macOS | safe | 3s | — |
| `sudo_touchid` | macOS | safe | 2s | — |
| `suspicious_connections` | macOS | safe | 3s | — |
| `suspicious_processes` | macOS | safe | 3s | — |
| `system_extensions` | macOS | safe | 5s | — |
| `twofa_audit` | macOS, Windows | safe | 10s | Check what two-factor authentication capability exists on this device. |
| `usb_device_audit` | macOS | safe | 5s | — |
| `user_account_audit` | macOS | safe | 5s | — |
| `vpn_config` | macOS | safe | 3s | — |
| `win_antivirus_status` | Windows | moderate | 10s | — |
| `win_autorun` | Windows | safe | 5s | — |
| `win_autoruns_audit` | Windows | safe | 10s | — |
| `win_bitlocker` | Windows | safe | 5s | — |
| `win_bitlocker_check` | Windows | safe | 5s | — |
| `win_cortana_telemetry` | Windows | safe | 5s | — |
| `win_credential_guard` | Windows | safe | 10s | — |
| `win_credential_manager_audit` | Windows | safe | 5s | — |
| `win_crypto_miner_detect` | Windows | safe | 20s | Windows counterpart to the macOS ``crypto_miner_detect`` module. |
| `win_defender` | Windows | moderate | 10s | — |
| `win_defender_deep_check` | Windows | safe | 15s | — |
| `win_firewall` | Windows | moderate | 5s | — |
| `win_firewall_rules_audit` | Windows | safe | 10s | — |
| `win_group_policy_audit` | Windows | safe | 10s | — |
| `win_hosts_file` | Windows | safe | 3s | — |
| `win_hosts_file_check` | Windows | safe | 5s | — |
| `win_local_admin_audit` | Windows | safe | 5s | — |
| `win_malware_indicators` | Windows | safe | 15s | — |
| `win_network_shares_audit` | Windows | safe | 10s | — |
| `win_proxy_detect` | Windows | safe | 5s | — |
| `win_rdp_check` | Windows | safe | 5s | — |
| `win_remote_access_audit` | Windows | safe | 10s | — |
| `win_rootkit_check` | Windows | safe | 30s | — |
| `win_scheduled_tasks` | Windows | safe | 5s | — |
| `win_scheduled_tasks_security` | Windows | safe | 10s | — |
| `win_services_audit` | Windows | safe | 10s | — |
| `win_services_security_audit` | Windows | safe | 10s | — |
| `win_suspicious_processes` | Windows | safe | 10s | — |
| `win_uac_check` | Windows | safe | 3s | — |
| `win_user_accounts` | Windows | safe | 5s | — |
| `xprotect_status` | macOS | safe | 3s | — |

## Reading a module before you run it

Every module is a single `__init__.py` under
`modules/<category>/<module_name>/`. There is no compiled code, no plugin
download, and no dynamic fetch — what is in the tree is what runs. To read one:

```console
$ less modules/security/linux_firewall_check/__init__.py
```

The top of the file is a docstring stating what the check looks at and why, the
class body declares the metadata shown in the tables above, `check()` is the
read-only half, and `fix()` is the half that produces guidance or mutations.
See [Trust and safety](trust-and-safety.md).
