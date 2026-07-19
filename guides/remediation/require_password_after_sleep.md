---
title: "Require a password after sleep or screen saver"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.screen_lock_check.screen_lock_required
  - security.screen_lock_check.automatic_login
  - security.screen_lock_check.screen_lock_delay
  - security.screen_lock_check.screensaver_idle_time
  - security.screen_lock_check.password_hint
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `screen_lock_check` module inventories:
whether a password is required after sleep/screen saver, automatic login,
the delay before the lock screen demands a password, how long the Mac sits
idle before the screen saver kicks in, and whether a password hint is shown
after failed attempts. All of these are System Settings toggles — nothing
here is auto-applied, since getting the timing wrong on a machine you use
regularly is mostly an annoyance you should decide on yourself.

## Step 1: Require a password immediately after sleep or screen saver

1. Open System Settings > Lock Screen.
2. Set "Require password after screen saver begins or display is turned
   off" to **Immediately**.
3. If the finding reported this as already enabled, no action is needed —
   confirm the setting still shows "Immediately" and move on.

## Step 2: Disable automatic login (critical)

Automatic login skips the password prompt entirely at boot — physical
access to the machine is equivalent to being logged in as that user.

1. Open System Settings > General > Login Items & Extensions, or System
   Settings > Users & Groups depending on macOS version, and look for the
   automatic login setting for the flagged account.
2. Set automatic login to **Off**.
3. Confirm you know the account password before disabling this — you'll
   need to type it at every subsequent boot.

## Step 3: Reduce the screen lock delay

A delay longer than a few seconds means someone with brief physical access
after the display sleeps can still get in before the lock engages.

1. Open System Settings > Lock Screen and check "Require password after
   screen saver begins or display is turned off."
2. If it's set to anything other than Immediately or a few seconds, reduce
   it — Immediately is safest; up to 5 seconds is a reasonable compromise
   if you find "Immediately" too aggressive for normal use.

## Step 4: Set a reasonable screen saver / display-off idle time

An idle time of 0 (disabled) or longer than 10 minutes leaves an unattended
Mac unlocked for longer than necessary.

1. Open System Settings > Lock Screen.
2. Set "Turn display off on power adapter when inactive" (and the battery
   equivalent) to 10 minutes or less. This also drives when the screen
   saver/lock engages given Step 1's setting.
3. If the finding reported idle time as "not configured," set an explicit
   value rather than leaving it at the system default.

## Step 5: Review password hint visibility

This is informational, not urgent — a password hint shown after repeated
failed attempts can leak information about your password to anyone
attempting to guess it (including someone who picked up the machine).

1. Open System Settings > Users & Groups, select your account, and check
   whether a password hint is configured.
2. If you don't need it, clear the hint field. If you want to keep a hint,
   make sure it doesn't reveal the password itself or make it substantially
   easier to guess.
