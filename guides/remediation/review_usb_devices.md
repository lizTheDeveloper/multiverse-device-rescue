---
title: "Review connected USB devices"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.usb_device_audit.usb_devices
  - security.usb_device_audit.no_vendor_devices
  - security.usb_device_audit.storage_devices
  - security.usb_device_audit.usb_hubs
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `usb_device_audit` module can
flag: the full inventory of connected USB devices, devices missing
vendor/manufacturer information, connected USB storage devices, and USB
hub topology. This is a physical-inspection task — the fix is
recognizing and, where appropriate, physically disconnecting hardware,
not editing any file or setting.

## Step 1: Review the full USB device inventory

`usb_devices` lists everything currently connected.

1. Go through the listed devices and confirm you recognize each one —
   keyboard, mouse, webcam, dock, hub, external drive, etc.
2. This is the baseline for the more specific findings below; if
   everything here is familiar, the rest of this guide may not require
   any action.

## Step 2: Confirm devices with unknown vendor before restricting anything

`no_vendor_devices` flags devices where `system_profiler` couldn't
report vendor/manufacturer information. This is often benign (some
generic or older peripherals simply don't populate this field), but it's
also a pattern seen with some low-quality clone hardware and, more
rarely, malicious USB devices (e.g. keystroke-injection tools disguised
as flash drives).

1. **Confirm before restricting**: identify the physical device by
   matching the reported name/serial number against what's actually
   plugged in — check each USB port. Don't assume the flagged device is
   the last thing you plugged in without verifying.
2. If you recognize the physical device (e.g. a generic USB hub or an
   older peripheral you own) and its behavior looks normal, no action is
   needed — missing vendor info alone is weak signal.
3. If you don't recognize the device, or it appeared without you
   plugging anything in, or it's misbehaving (unexpected keystrokes,
   unexpected network activity), disconnect it immediately and don't
   reconnect it until you've identified its origin. Treat unexplained
   HID (keyboard/mouse-emulating) devices with particular caution — see
   `keylogger_indicators`-related findings if you suspect input
   injection.

## Step 3: Verify USB storage devices are from trusted sources

`storage_devices` lists connected external storage.

1. Confirm each storage device is one you own and trust — external
   drives from unknown sources are a classic malware vector.
2. If you don't recognize a listed storage device, disconnect it before
   opening/mounting any of its contents, rather than after.
3. As general hygiene, ensure FileVault is enabled on this Mac (see
   `filevault_recovery` / `encryption_check` module guidance) so that if
   an untrusted drive is ever mistakenly trusted, your own data stays
   protected at rest.

## Step 4: Review USB hub topology

`usb_hubs` is informational — it reports how many hubs are in the chain.

1. No security action is required for hubs themselves; this finding is
   about stability, not security. Multiple daisy-chained (hub connected
   to hub) configurations can cause power/connectivity issues, especially
   on older Macs with lower USB port power budgets.
2. If you're experiencing connectivity or performance issues, consider
   consolidating to a single powered hub rather than chaining several
   together.
