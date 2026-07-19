---
title: "Harden login and password policy settings"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.login_password_policy.auto_login
  - security.login_password_policy.ask_password
  - security.login_password_policy.password_delay
  - security.login_password_policy.guest_account_enabled
  - security.login_password_policy.login_window_display
  - security.login_password_policy.screensaver_timeout
  - security.login_password_policy.remote_login_enabled
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `login_password_policy` module can
flag: auto-login, screensaver password requirements and delay, the Guest
account, login window display mode, screensaver timeout, and Remote Login
(SSH). Every change here touches how you or another account holder gets into
this Mac, so confirm current usage before changing anything and make each
change through System Settings where possible rather than raw `defaults`
writes, so you can see the effect immediately.

## Step 1: Disable auto-login (critical)

Auto-login lets anyone who opens the lid get straight to the desktop with no
credential check.

1. Confirm who the finding says is auto-logging in (`user` field) and whether
   you rely on it (e.g. a kiosk or a single-user home machine you've
   deliberately configured this way). If you rely on it, weigh that
   convenience against the risk before continuing.
2. Open System Settings > General > Login Items & Extensions > Login Options
   (may require unlocking with your password) and uncheck "Automatically log
   in as".
3. Restart and confirm the login screen now appears and requires a password.

## Step 2: Require a password after the screensaver, and remove any delay

1. If `ask_password` was flagged: System Settings > Lock Screen > enable
   "Require password after screen saver begins or display is turned off".
2. If `password_delay` was flagged (delay > 5 seconds): in the same Lock
   Screen pane, set the password requirement to "Immediately" (0 seconds) or
   as short as the picker allows.
3. Lock the screen (Control+Command+Q) and verify a password prompt appears
   right away.

## Step 3: Review the Guest account

1. Confirm whether you or anyone else actually uses Guest login on this
   Mac — check System Settings > General > Sharing for any guest-dependent
   sharing settings before disabling.
2. If unused: System Settings > General > Login Items & Extensions > Login
   Options (unlock first) and uncheck "Allow guests to log in".
3. If your organization or household intentionally uses Guest access, leave
   it and note that as an accepted risk instead of disabling it blindly.

## Step 4: Review login window display and screensaver timeout

1. `login_window_display` is informational — it reports whether the login
   screen shows a user list or a name+password field. A user list reveals
   account names to anyone with physical access; if you'd rather it not,
   switch to "Name and password" in System Settings > General > Login Items
   & Extensions > Login Options > "Display login window as".
2. If `screensaver_timeout` was flagged (screensaver disabled, or timeout
   over 10 minutes): System Settings > Lock Screen > set "Start Screen Saver
   when inactive" to 10 minutes or less.
3. Re-run the scan to confirm the new timeout is reported.

## Step 5: Review Remote Login (SSH)

This is informational — Remote Login is often intentional (e.g. you SSH into
this Mac from another device).

1. Confirm whether you actually use SSH to reach this Mac before touching
   anything — check for existing sessions or scheduled remote access
   workflows.
2. If you don't need inbound SSH: System Settings > General > Sharing >
   toggle off "Remote Login".
3. If you do need it, leave it enabled and instead review
   `guides/remediation/harden_ssh_keys.md` for hardening the SSH
   configuration itself (key permissions, `sshd_config` settings).
