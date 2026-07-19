---
title: "Harden login window display and hint settings"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.login_window_settings.auto_login
  - security.login_window_settings.show_user_list
  - security.login_window_settings.password_hints
  - security.login_window_settings.login_settings_info
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers what `login_window_settings` flags: auto-login,
whether the login screen shows a user list or a name+password prompt,
password hints after failed attempts, and an overall INFO summary of the
current configuration. As with any login-screen change, confirm how you
actually use this Mac before changing the defaults — these settings affect
how you (and anyone else with a local account) get past the lock screen.

## Step 1: Disable auto-login (critical)

1. Confirm this Mac isn't intentionally configured as a kiosk or
   single-purpose auto-login device before changing anything.
2. System Settings > General > Login Items & Extensions > Login Options
   (unlock first) and uncheck "Automatically log in as".
3. Restart and confirm the login screen requires a password.

## Step 2: Switch the login window away from a user list

A visible user list discloses account names to anyone at the keyboard.

1. Confirm you don't rely on the user-list picker for a specific workflow
   (e.g. quick account switching on a shared family Mac) before changing it.
2. System Settings > General > Login Items & Extensions > Login Options >
   "Display login window as" > select "Name and password".
3. Restart or lock the screen to confirm the new prompt appears.

## Step 3: Disable password hints

Password hints shown after repeated failed attempts can leak information
useful to an attacker guessing the password.

1. Back up current value first if you want to be able to restore it:
   `defaults read /Library/Preferences/com.apple.loginwindow RetriesUntilHint`.
2. Disable hints: `sudo defaults write
   /Library/Preferences/com.apple.loginwindow RetriesUntilHint -int 0`.
3. Confirm the finding no longer appears on the next scan.

## Step 4: Review the overall login window summary

The `login_settings_info` finding is a always-emitted INFO summary combining
the three settings above (auto-login state, login window display mode,
password-hint state) in one place.

1. Read through the summary and confirm it matches what you expect after
   completing Steps 1-3.
2. If anything is still unexpected, re-check the individual `defaults`
   values reported in the finding rather than guessing — they are the
   ground truth this module reads from.
