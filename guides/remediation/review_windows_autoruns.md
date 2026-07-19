---
title: "Review Windows AutoRun and AutoPlay settings"
estimated_time: "10 minutes"
platforms: [windows]
remediates:
  - security.win_autorun.autorun_enabled
  - security.win_autorun.autorun_disabled_full
  - security.win_autorun.autorun_partial
  - security.win_autorun.autoplay_enabled
  - security.win_autorun.autoplay_disabled
automatable_steps: []
human_only_steps: [1, 2]
---

This walkthrough covers the `win_autorun` module, which checks the
system-wide AutoRun policy (`NoDriveTypeAutoRun`) and the AutoPlay handler
setting (`DisableAutoplay`) — both classic vectors for USB-borne malware
that executes automatically when removable media is connected. Both
settings are simple registry toggles; there's nothing to inspect-before-
delete here since no files are touched, just policy values.

## Step 1: AutoRun enabled or only partially disabled for removable drives

If the finding reports AutoRun is enabled, or only partially disabled
(a `NoDriveTypeAutoRun` value other than `0x91`), removable USB drives can
trigger automatic code execution when connected — a technique historically
used by worms like Conficker and Stuxnet, and still relevant for targeted
USB-drop attacks.

1. Confirm you don't rely on AutoRun for a specific legitimate purpose
   (rare on modern systems — most software installers today don't depend
   on it).
2. Set the policy to fully disable AutoRun for all drive types via an
   elevated prompt: `reg add
   "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v
   NoDriveTypeAutoRun /t REG_DWORD /d 0x91 /f`.
3. Alternatively via Group Policy Editor (`gpedit.msc`, Windows Pro/
   Enterprise only): Computer Configuration → Administrative Templates →
   Windows Components → AutoPlay Policies → "Turn off AutoPlay" → Enabled,
   "All drives".
4. Re-run the scan to confirm the policy now reports as fully disabled
   (`0x91`).

## Step 2: AutoPlay enabled for removable media

AutoPlay (distinct from AutoRun) controls whether Windows automatically
offers to open a handler — like File Explorer or a media app — when
removable media is connected. It's a lower-severity vector than AutoRun
itself since it typically requires a user click to proceed, but it still
increases attack surface and can be used for social-engineering-driven
malware execution (e.g. a disguised "Open folder to view files" prompt).

1. Disable via Settings: Settings → Bluetooth & devices → AutoPlay → toggle
   "Use AutoPlay for all media and devices" off.
2. Or via elevated registry edit: `reg add
   "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers"
   /v DisableAutoplay /t REG_DWORD /d 1 /f`.
3. Re-run the scan to confirm AutoPlay now reports as disabled.

## Already secure

If the scan reports AutoRun fully disabled (`0x91`) and/or AutoPlay
disabled, no action is needed for those settings — that's the secure
baseline this walkthrough aims for.
