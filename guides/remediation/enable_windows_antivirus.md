---
title: "Enable and restore Windows antivirus protection"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_antivirus_status.no_av_product
  - security.win_antivirus_status.realtime_protection_disabled
  - security.win_antivirus_status.stale_definitions
  - security.win_antivirus_status.multiple_av_products
  - security.win_antivirus_status.registered_products
  - security.win_defender.antivirus_enabled
  - security.win_defender.realtime_protection
  - security.win_defender.signature_age
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `win_antivirus_status` (Security
Center-wide AV inventory) and `win_defender` (Defender-specific status)
modules can flag: no antivirus registered at all, real-time protection
disabled, stale definitions, and conflicting multiple AV products. If you
find protection disabled and you didn't disable it yourself, treat that as a
possible sign of active malware — many families of malware specifically
disable antivirus as a first step — rather than assuming it's a routine
misconfiguration. Nothing here requires deleting files; every fix re-enables
a setting or updates definitions.

## Step 1: No antivirus product registered (critical)

Windows Security Center reports no antivirus product registered at all, or
Windows Defender itself reports as disabled.

1. Confirm current state: open Windows Security → Virus & threat protection,
   or run `Get-MpComputerStatus` in an elevated PowerShell prompt and check
   `AntivirusEnabled`.
2. If a third-party antivirus was installed and later uninstalled without
   Windows Defender re-enabling itself, the safest path is to re-enable
   Defender: Windows Security → Virus & threat protection → Manage settings
   → toggle "Real-time protection" on. If it's greyed out, check Group
   Policy / Settings app → "Turn off Microsoft Defender Antivirus" is not
   set, then reboot.
3. If you intend to install a different reputable antivirus product instead,
   do that now — Windows Defender will typically stand down automatically
   once another registered AV product with real-time protection is active,
   rather than leaving the machine with neither. Don't leave the system with
   no active AV in the interim.

## Step 2: Real-time protection disabled

Real-time protection scans files as they're accessed; without it, malware
can execute without being caught at the point of access.

1. Before re-enabling, consider *why* it's off — a deliberate, temporary
   disable for a specific compatibility reason is different from finding it
   off unexpectedly. If you don't recall disabling it, treat this as a
   stronger signal and cross-reference with
   `respond_to_windows_malware_indicators.md` and
   `triage_windows_suspicious_processes.md`.
2. Re-enable via GUI: Windows Security → Virus & threat protection → Manage
   settings → toggle "Real-time protection" on. Equivalently, elevated
   PowerShell: `Set-MpPreference -DisableRealtimeMonitoring $false`.
3. If the toggle won't stay on, disconnect from the network and run
   Microsoft Safety Scanner or Windows Defender Offline instead of
   continuing to fight the toggle — a setting that reverts itself points to
   something actively re-disabling it.
4. If a non-Microsoft antivirus product is registered instead, re-enable
   real-time protection through that product's own settings UI — Defender's
   PowerShell cmdlets only control Defender itself.

## Step 3: Stale antivirus definitions

More than 7 days have passed since the last definition update. Outdated
definitions miss newer threats.

1. Confirm you have network connectivity, since updates are pulled online.
2. Update Defender definitions: elevated PowerShell `Update-MpSignature`, or
   GUI: Windows Security → Virus & threat protection → Check for updates.
3. If a non-Microsoft antivirus product reported the stale definitions,
   update it through its own update mechanism instead — it will usually
   have its own scheduled update task; confirm that task hasn't been
   disabled.

## Step 4: Multiple antivirus products registered

More than one antivirus product is registered with Windows Security Center.
Running two real-time scanners simultaneously commonly causes conflicts,
performance problems, and can paradoxically reduce protection (each product
may exclude the other's files, or file-locking conflicts can suppress
scans).

1. List the registered products (shown in the finding's `products` data, or
   re-run: `Get-CimInstance -Namespace root/SecurityCenter2 -ClassName
   AntiVirusProduct`).
2. Decide which one you actually want as your primary AV — usually whichever
   one you intentionally installed and are paying for/maintaining, or
   Windows Defender if none.
3. Uninstall the other product(s) through Settings → Apps, or their own
   uninstaller, rather than just disabling them — a disabled-but-installed
   AV can still interfere. Confirm the one you're keeping resumes real-time
   protection afterward (Step 2).

## Step 5: Review registered products (informational)

The `registered_products` / `antivirus_enabled` findings without an
associated problem are informational — they list what's currently
registered so you can confirm it matches what you expect. No action is
needed unless the list contains a product you don't recognize, in which case
treat it the same as Step 4: confirm intent before removing it, since it
could be legitimate software bundled by your PC manufacturer.

## No issues found

If the scan reports only informational findings (registered products with
real-time protection on and recent definitions), no action is needed — that
is the secure baseline this walkthrough aims for.
