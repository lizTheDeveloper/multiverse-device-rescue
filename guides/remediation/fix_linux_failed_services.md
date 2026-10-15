---
title: "Fix a stopped or crashing background service"
estimated_time: "20 minutes"
platforms: [linux]
remediates:
  - integrity.linux_service_health.failed_unit
  - integrity.linux_service_health.failed_backup_unit
  - integrity.linux_service_health.restart_loop
  - integrity.linux_service_health.time_sync_inactive
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Some programs run quietly in the background: backups, networking, the clock.
One of them has stopped or keeps crashing, so whatever it does is not
happening. The most serious case is a failed backup: it looks like backups are
being made, but nothing is being saved. A clock that is off also breaks secure
websites and sign-in codes in confusing ways.

## Step 1: Find out which service it is

The finding names it (for example `backup.service`). Write the name down.

## Step 2: Look at why it failed

In a terminal, run `systemctl status NAME` (replace NAME with the service name)
and read the last few lines. The reason is usually plain: a drive that isn't
plugged in, a full disk, a changed password, or a missing file.

## Step 3: Fix the cause, then start it again

1. Plug the drive back in, free up disk space, or fix the setting the message
   complains about.
2. Run `sudo systemctl restart NAME` and check that `systemctl status NAME`
   says **active (running)**.
3. If it is a backup service, confirm that a new backup now appears in your
   backup folder or app.

If you can't work out the cause, search for the message in the log, or ask in
your distribution's help forum. Leave out anything private.

## Step 4: Turn the clock sync back on

If the finding was about the clock, open **Settings > Date & Time** and turn on
**Automatic Date & Time**. Optional, from a terminal: `sudo timedatectl set-ntp true`.
