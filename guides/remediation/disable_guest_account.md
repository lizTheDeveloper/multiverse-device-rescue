---
title: "Disable the Guest account and Guest file-sharing access"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.guest_account_check.guest_enabled
  - security.guest_account_check.guest_afp_access
  - security.guest_account_check.guest_smb_access
  - security.guest_account_check.guest_disabled
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers what `guest_account_check` flags: the Guest account
itself being enabled, and Guest access to shared folders over AFP and SMB.
Confirm nobody relies on Guest login or Guest file sharing before disabling
it — some households or small offices intentionally leave Guest access on
for visitors.

## Step 1: Confirm nobody needs Guest login, then disable it

1. Check whether you or anyone with physical access to this Mac has used the
   Guest account recently — if you're unsure, ask before disabling.
2. Disable it: System Settings > General > Users & Groups > click the lock
   icon and authenticate > select "Guest User" > turn off "Allow guests to
   log in to this computer".
   Command-line alternative (requires sudo): `sudo defaults write
   /Library/Preferences/com.apple.loginwindow GuestEnabled -bool false`.
3. Re-run the scan to confirm `guest_enabled` no longer appears.

## Step 2: Disable Guest access to AFP file sharing

Guest AFP access lets anyone on the network read shared folders with no
authentication.

1. Confirm File Sharing over AFP is even something you use — if File Sharing
   itself is off, this setting has no practical effect but is still worth
   correcting.
2. System Settings > General > Sharing > File Sharing > Options, and turn
   off "Share files and folders using AFP" if you don't need it, or ensure
   Guest access specifically is unchecked for any shared folder.
   Command-line alternative: `sudo defaults write
   /Library/Preferences/com.apple.AppleFileServer guestAccess -bool false`.
3. Re-run the scan to confirm `guest_afp_access` no longer appears.

## Step 3: Disable Guest access to SMB file sharing

Same risk as AFP, but for Windows-compatible SMB sharing — commonly the
default protocol now, so review this even if you don't think you use AFP.

1. Confirm which shared folders you actually use over SMB before changing
   settings, so you don't disrupt shares you rely on.
2. System Settings > General > Sharing > File Sharing > Options, and ensure
   guest access is unchecked for each share.
   Command-line alternative: `sudo defaults write
   /Library/Preferences/SystemConfiguration/com.apple.smb.server
   AllowGuestAccess -bool false`.
3. Re-run the scan to confirm `guest_smb_access` no longer appears.

## Step 4: Confirm the secure baseline

If the scan instead reports `guest_disabled`, the Guest account and Guest
file-sharing access are already off — this is the informational "all clear"
finding and no action is needed. Re-check it after making any of the changes
above to confirm you've reached this state.
