---
title: "Secure Apple ID and iCloud account settings"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.appleid_security_check.appleid_signin
  - security.appleid_security_check.icloud_keychain
  - security.appleid_security_check.autoupdate_disabled
  - security.appleid_security_check.appleid_summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `appleid_security_check` module can
flag: no Apple ID signed in, iCloud Keychain disabled, automatic updates
disabled, and the informational account-security summary. Signing in to an
Apple ID and enabling Keychain both require entering account credentials and
completing two-factor authentication, so these are human-only steps —
nothing here is auto-applied.

## Step 1: Sign in to Apple ID, if not already

If `appleid_signin` was reported, iCloud services (backup, Find My,
Keychain) are inactive on this Mac.

1. Open System Settings > [Your Name] at the top of the sidebar.
2. Click **Sign in with your Apple ID**, using an account you personally
   control and trust.
3. Enter your Apple ID email and password, then complete the two-factor
   authentication prompt on a trusted device.
4. Once signed in, review which iCloud features you want enabled (Find My,
   iCloud Drive, Photos, Keychain, etc.) rather than turning everything on
   by default.

## Step 2: Enable iCloud Keychain

If `icloud_keychain` was reported, saved passwords and payment info aren't
being synced/backed up via iCloud, so they're at greater risk of being lost
if this device is lost, stolen, or wiped.

1. Open System Settings > [Your Name] > iCloud.
2. Find **Passwords and Keychain** (or "Passwords" depending on macOS
   version) and toggle it ON.
3. Confirm with your Apple ID password and two-factor authentication when
   prompted.
4. This encrypts and syncs your saved passwords/payment methods across your
   Apple devices — verify on another device (if you have one) that sync is
   working as expected.

## Step 3: Enable automatic software updates

If `autoupdate_disabled` was reported, this Mac isn't automatically
receiving security patches, which increases exposure time for known
vulnerabilities. See `enable_automatic_updates.md` for the full walkthrough
on turning this on and choosing which update categories to automate — this
finding overlaps with checks that module also performs.

## Step 4: Review the full Apple ID security summary

`appleid_summary` is an informational finding — it reports sign-in status,
two-factor authentication, Keychain, Private Relay, Mail Privacy
Protection, device count, and auto-update status all in one place.

1. Visit https://appleid.apple.com/account/ and sign in to review your
   account directly (this is more authoritative than what a local Mac can
   detect).
2. Confirm **Two-Factor Authentication** is enabled — this is the single
   most important Apple ID security control and can't be reliably verified
   from a local machine check.
3. Review **Trusted Phone Numbers** and update any that are stale, unused,
   or no longer accessible to you.
4. Review the **Devices** list and remove any device you don't recognize or
   no longer own — this immediately signs it out of iCloud on that device.
5. If you don't recognize a device or activity in your account, change your
   Apple ID password immediately from that same page before doing anything
   else.
