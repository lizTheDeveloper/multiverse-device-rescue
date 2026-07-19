---
title: "Restore Windows Defender protection"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_defender_deep_check.realtime_disabled
  - security.win_defender_deep_check.cloud_protection_off
  - security.win_defender_deep_check.tamper_protection_disabled
  - security.win_defender_deep_check.excessive_exclusions
  - security.win_defender_deep_check.pua_protection_disabled
  - security.win_defender_deep_check.stale_full_scan
  - security.win_defender_deep_check.controlled_folder_access_disabled
  - security.win_defender_deep_check.all_passed
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7]
---

This walkthrough covers everything the `win_defender_deep_check` module can
flag: disabled real-time/cloud/tamper protection, an excessive number of
scan exclusions, disabled PUA (potentially unwanted app) protection, a
stale full-scan date, and disabled controlled folder access. Every setting
here re-enables through Windows Security's GUI or an elevated PowerShell
cmdlet — none require deleting files — but if you find real-time or tamper
protection disabled and you didn't disable it yourself, treat that as a
possible sign of active malware (many families specifically disable
Defender as a first step) rather than a routine misconfiguration.

## Step 1: Real-time protection disabled (critical)

Real-time protection scans files as they're accessed; without it, malware
can execute without being caught at the point of access.

1. Before re-enabling, consider *why* it's off: if you (or an
   administrator/MDM policy) disabled it deliberately — for example to run
   a specific security tool that conflicts with Defender, or during a
   one-time large file operation — confirm that reason no longer applies.
2. If you don't recall disabling it, treat this as a stronger signal:
   check for other findings in this same scan (excessive exclusions,
   tamper protection also disabled) and cross-reference with
   `respond_to_windows_malware_indicators.md` and
   `triage_windows_suspicious_processes.md` — malware commonly disables
   real-time protection right before or after establishing persistence.
3. Re-enable via GUI: Windows Security → Virus & threat protection →
   Manage settings → toggle "Real-time protection" on. (If tamper
   protection was also disabled and re-enabled first per Step 3, this
   toggle may already be locked back on.)
4. If the toggle won't stay on (reverts itself after a few seconds), that's
   a strong indicator something is actively re-disabling it — this points
   to active malware rather than a simple setting change; disconnect from
   the network and run Microsoft Safety Scanner or Windows Defender
   Offline (which runs outside the live OS and can't be interfered with by
   a running process) instead of continuing to fight the toggle.
5. Once it holds, run a Quick Scan to confirm Defender is functioning.

## Step 2: Cloud protection disabled

Cloud-delivered protection (MAPS) improves detection of new/emerging
threats by checking suspicious files against Microsoft's cloud database.

1. Re-enable via GUI: Windows Security → Virus & threat protection →
   Manage settings → toggle "Cloud-delivered protection" on.
2. If you have privacy concerns about cloud submission, you can instead set
   the submission level to "Send safe samples automatically" rather than
   fully automatic, via the same settings page — this is a reasonable
   middle ground, not a finding you need to fully resolve to zero risk.

## Step 3: Tamper protection disabled

Tamper protection prevents other processes (including malware) from
changing Defender settings, such as disabling real-time protection.

1. Re-enable via GUI: Windows Security → Virus & threat protection →
   Manage settings → toggle "Tamper Protection" on. This is a Home/Pro
   consumer toggle; on managed/enterprise devices it may be controlled by
   Intune/Group Policy instead — check with an IT admin if the toggle is
   greyed out.
2. If tamper protection was off and real-time protection was *also* off,
   re-enable tamper protection first, then real-time protection — this
   matches the order malware would have had to disable them in reverse,
   and confirms tamper protection is actually holding before you rely on
   it.

## Step 4: Excessive scan exclusions

More than 10 combined path/extension/process exclusions were found.
Exclusions are sometimes legitimately needed (development tool caches, VM
disk files, certain backup software) but each one is a blind spot malware
can hide in.

1. List current exclusions: `Get-MpPreference | Select-Object
   ExclusionPath, ExclusionExtension, ExclusionProcess` (elevated
   PowerShell).
2. Go through each one and confirm you recognize the reason it was added —
   development tools (Docker, WSL, IDEs), specific backup/AV software
   conflicts, and VM software are common legitimate reasons.
3. For any exclusion you don't recognize or can't explain, especially ones
   pointing to a Temp, AppData, or ProgramData subfolder, remove it:
   `Remove-MpPreference -ExclusionPath "<path>"` (or
   `-ExclusionExtension` / `-ExclusionProcess` as appropriate).
4. After removing unrecognized exclusions, run a full scan (see Step 6) so
   Defender checks the paths that were previously excluded.

## Step 5: PUA protection disabled

Potentially Unwanted Application protection catches adware, bundled
toolbars, and similarly unwanted-but-not-quite-malware software.

1. Re-enable via GUI: Windows Security → App & browser control → Reputation
   -based protection settings → toggle "Potentially unwanted app blocking"
   on (or via `Set-MpPreference -PUAProtection Enabled` elevated).
2. This is a low-risk toggle to re-enable — it has no destructive effect,
   it just adds detection coverage.

## Step 6: Stale full scan

More than 30 days have passed since the last full system scan. Quick scans
(which run more frequently by default) only check common malware
locations; a full scan checks all files.

1. Run a full scan: Windows Security → Virus & threat protection → Scan
   options → select "Full scan" → "Scan now". This can take a significant
   amount of time (potentially hours depending on disk size) and will use
   noticeable CPU/disk — a good candidate to run overnight or during idle
   time rather than mid-work.
2. If the scan finds threats, follow Defender's built-in remediation
   prompts (quarantine/remove) — Defender handles this itself once threats
   are identified.
3. Consider scheduling a recurring full scan (Task Scheduler, or via
   `Set-MpPreference -ScanScheduleQuickScanTime`) if this keeps recurring —
   though a monthly cadence via the default Windows Update maintenance
   window is usually sufficient for most home use.

## Step 7: Controlled folder access disabled

Controlled folder access blocks unrecognized applications from modifying
files in protected folders (Documents, Pictures, Desktop, etc. by default)
— it's specifically a ransomware mitigation.

1. Re-enable via GUI: Windows Security → Virus & threat protection →
   Ransomware protection → toggle "Controlled folder access" on.
2. If it was disabled because a legitimate app you use was being blocked
   from saving files, re-enable the feature and then allow that specific
   app: Ransomware protection → "Allow an app through Controlled folder
   access" → add the app, rather than leaving the whole feature off.

## No issues found

If the scan reports only the `all_passed` INFO finding, all deep Defender
checks passed — real-time, cloud, and tamper protection are on, exclusions
are reasonable, PUA and controlled folder access protection are on, and the
last full scan was recent. No action is needed.
