---
title: "Enforce lock screen: require password promptly, keep display auto-sleep on"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.lock_screen_check.screensaver_password
  - security.lock_screen_check.screensaver_delay
  - security.lock_screen_check.display_sleep
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers what `lock_screen_check` flags: whether a password
is required after the screen saver/lock, how long the grace period is
before that password is required, and whether the display is set to sleep
at all. These findings are distinct from (but related to) the broader
`login_password_policy` module — this one focuses specifically on the
screen-lock behavior. All changes are made through System Settings, so
there's no file to back up, but confirm you won't be inconvenienced (e.g. on
a Mac used for unattended presentations) before tightening these.

## Step 1: Require a password after the screen saver/lock screen

1. Confirm this Mac isn't intentionally left unlocked for a specific reason
   (e.g. a dedicated kiosk display) before changing this.
2. System Settings > Lock Screen > enable "Require password after screen
   saver begins or display is turned off".
3. Lock the screen (Control+Command+Q) and confirm a password prompt
   appears.

## Step 2: Shorten the password delay

A delay over 60 seconds after the screen locks before a password is
actually required gives a real window for unauthorized access during a
brief absence.

1. In the same Lock Screen pane, set the delay to "Immediately" or the
   shortest available option.
2. Re-run the scan to confirm `screensaver_delay` no longer appears.

## Step 3: Enable display auto-sleep

A display that never sleeps (`displaysleep` set to 0 via `pmset`) leaves
content visible indefinitely to anyone nearby, and also means the
screen-lock delay above never gets triggered by inactivity in the way you'd
expect.

1. Confirm you don't have a deliberate reason for disabling display sleep
   (e.g. a monitoring dashboard Mac) before changing it.
2. System Settings > Lock Screen (or Displays, depending on macOS version) >
   set "Turn display off on battery/power when inactive" to a reasonable
   value such as 5-15 minutes.
3. Verify with `pmset -g | grep displaysleep` that the value is no longer 0.
