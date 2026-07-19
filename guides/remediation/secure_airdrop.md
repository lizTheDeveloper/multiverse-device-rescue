---
title: "Secure AirDrop and related sharing settings"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.airdrop_config.airdrop_everyone
  - security.airdrop_config.airdrop_contacts_only
  - security.airdrop_config.airdrop_off
  - security.airdrop_config.bluetooth_disabled
  - security.airdrop_config.wifi_disabled
  - security.airdrop_security_check.airdrop_mode_everyone
  - security.airdrop_security_check.bluetooth_sharing_enabled
  - security.airdrop_security_check.sharing_config
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `airdrop_config` and
`airdrop_security_check` modules flag: AirDrop discoverability, the
Bluetooth/Wi-Fi radios AirDrop depends on, Bluetooth file-sharing, and the
general sharing-configuration inventory. All changes here are toggles you
control from System Settings — nothing destructive — but they can affect
whether you can share files with people nearby, so confirm you don't rely on
the current setting before changing it.

## Step 1: Set AirDrop discoverability to Contacts Only

If either module flagged AirDrop as set to "Everyone", that means anyone
nearby (not just people in your contacts) can send you unsolicited files —
this has been used for harassment ("cyberflashing") in public places.

1. Open System Settings > General > AirDrop.
2. Set "Allow me to be discovered by" to **Contacts Only**.
3. If you don't use AirDrop at all, you can instead choose **Receiving Off**
   (also called "No One") — this is safe and simply disables the feature.
4. If the scan reports AirDrop already set to Contacts Only or Off, no
   action is needed — that's the secure baseline.

## Step 2: Review Bluetooth sharing

If `airdrop_security_check` flagged Bluetooth sharing as enabled, files can
be pushed to this Mac over Bluetooth outside of AirDrop.

1. Open System Settings > General > AirDrop & Handoff (or Sharing on older
   macOS) and check whether "Bluetooth Sharing" is listed/enabled.
2. If you don't actively use Bluetooth file transfers, disable it.
3. If you do rely on it (e.g. transferring files from a non-Apple Bluetooth
   device), leave it enabled but periodically review which devices are
   paired — see `review_bluetooth.md`.

## Step 3: Review Bluetooth/Wi-Fi radio status and the sharing summary

These are informational findings — they tell you the current state of the
radios AirDrop needs, and a general summary of your sharing configuration.
Nothing here is inherently insecure.

1. If Bluetooth or Wi-Fi was reported as disabled, that's expected if you
   don't use AirDrop or nearby-device features — no action needed unless
   you want AirDrop to work, in which case enable the radio in System
   Settings.
2. Review the sharing-configuration summary (AirDrop mode, Bluetooth,
   Wi-Fi, Handoff, Bluetooth sharing) and confirm each item matches what you
   expect for this device. Nothing needs to change if the summary matches
   your intent.
