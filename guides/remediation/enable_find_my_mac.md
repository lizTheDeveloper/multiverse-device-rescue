---
title: "Enable and verify Find My Mac"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.find_my_mac.find_my_mac_disabled
  - security.find_my_mac.send_last_location_disabled
  - security.find_my_mac.activation_lock_unknown
  - security.find_my_mac.configured_ok
  - security.find_my_mac_check.find_my_mac_disabled
  - security.find_my_mac_check.location_services_disabled
  - security.find_my_mac_check.icloud_not_signed_in
  - security.find_my_mac_check.configured_ok
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything both the `find_my_mac` and
`find_my_mac_check` modules can flag — they check overlapping but not
identical things (the `_check` variant also verifies Location Services and
iCloud sign-in as prerequisites). All changes here go through System
Settings and require entering your Apple ID credentials, so nothing is
auto-applied.

## Step 1: Sign in to iCloud, if not already

If `icloud_not_signed_in` was reported, Find My Mac cannot function without
an active Apple ID.

1. Open System Settings > [Your Name] at the top of the sidebar.
2. If not signed in, click **Sign in** and enter your Apple ID email and
   password, then complete the two-factor authentication prompt on a
   trusted device.
3. Use an Apple ID you personally control and trust — Find My ties device
   recovery/lock/erase capability to whoever owns that account.

## Step 2: Enable Location Services

If `location_services_disabled` was reported, Find My Mac cannot determine
or report the device's location even if the feature itself is turned on.

1. Open System Settings > Privacy & Security > Location Services.
2. Toggle **Location Services** ON at the top of the list.
3. Scroll down and confirm **Find My** has location access enabled in the
   per-app list below.

## Step 3: Enable Find My Mac and Send Last Location

If `find_my_mac_disabled` was reported (critical — a lost/stolen device
cannot be located, locked, or wiped without this):

1. Open System Settings > [Your Name] > iCloud.
2. Scroll to **Find My Mac** and toggle it ON. You may be prompted to
   confirm with your Apple ID password.
3. If `send_last_location_disabled` was also reported, open the Find My
   settings (click into "Find My" under iCloud) and enable **Send Last
   Location** so the Mac reports its final known position before the
   battery dies.
4. This also enables **Activation Lock**, which ties the device to your
   Apple ID so it can't be erased and reactivated by someone else without
   your credentials — do not disable Find My later without first removing
   Activation Lock through the same iCloud settings, or a future owner
   (including you, after a factory reset) may get locked out.

## Step 4: Review informational findings

`activation_lock_unknown` and `configured_ok` are informational.

1. If Activation Lock status is unknown, it typically just means the check
   couldn't confirm it — Find My being enabled implies Activation Lock is
   generally active, but if you specifically need to confirm, check
   System Settings > [Your Name] > iCloud > Find My for the current state.
2. If `configured_ok` was reported, everything required is already in
   place — no action needed.
