---
title: "Review user accounts, admin privileges, Guest, and auto-login"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.user_account_audit.guest_enabled
  - security.user_account_audit.auto_login
  - security.user_account_audit.admin_accounts
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers what `user_account_audit` flags: the Guest account
being enabled, automatic login being configured, and multiple accounts
holding admin privileges. All three are account/access changes, so confirm
current usage before touching anything — removing admin rights from an
account someone actively relies on will break their ability to install
software or change system settings until it's restored.

## Step 1: Review and disable the Guest account if unused

1. Confirm nobody uses Guest login on this Mac before disabling it.
2. Disable via System Settings > General > Users & Groups > unlock > select
   Guest User > turn off "Allow guests to log in to this computer", or run
   `sudo defaults write /Library/Preferences/com.apple.loginwindow
   GuestEnabled -bool false`.
3. Re-run the scan to confirm the finding clears.

## Step 2: Review and disable automatic login if unused

1. Confirm the reported auto-login user (`user` field on the finding) is
   expected — if this Mac is intentionally set up as a kiosk or single-user
   auto-login device, weigh that convenience against the risk before
   changing anything.
2. Disable via System Settings > General > Login Items & Extensions > Login
   Options (unlock first) > uncheck "Automatically log in as", or run `sudo
   defaults delete /Library/Preferences/com.apple.loginwindow autoLoginUser`.
3. Restart and confirm the login screen now requires a password.

## Step 3: Review accounts with admin privileges

Multiple admin accounts aren't automatically wrong, but every admin account
is a full privilege-escalation path if compromised, so it's worth
confirming each one is still needed.

1. Read the list of admin accounts in the finding (`users` field) and, for
   each one, confirm you recognize the person/purpose and that they still
   need to install software, change system settings, and manage other
   users.
2. For any account that no longer needs admin rights but should keep using
   the Mac, demote it to a standard account rather than deleting it:
   System Settings > Users & Groups > unlock > select the user > uncheck
   "Allow user to administer this computer".
   Command-line alternative (confirm the username first — this changes
   group membership immediately): `sudo dscl . -delete /Groups/admin
   GroupMembers <username>`.
3. For any account you don't recognize at all, investigate further before
   touching it — do not delete an unfamiliar account without confirming
   with whoever manages this Mac first, since deleting an account can
   remove its home directory and data.
4. Re-run the scan to confirm only the expected accounts remain flagged (or
   the finding clears if you're down to one admin).
