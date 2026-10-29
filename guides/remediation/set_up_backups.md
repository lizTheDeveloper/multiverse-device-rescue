---
title: "Make sure your files are backed up"
platforms: [macos]
remediates:
  - integrity.time_machine_check.no_backup
  - integrity.time_machine_check.sync_only
  - integrity.time_machine_check.other_backup_tool
steps_for:
  integrity.time_machine_check.no_backup: [1, 3]
  integrity.time_machine_check.sync_only: [1, 2, 3]
  integrity.time_machine_check.other_backup_tool: [2, 3]
automatable_steps: []
human_only_steps: [1, 2, 3]
---

A backup is a second copy of your files, kept somewhere else, that you can go
back to. Time Machine is the one built into your Mac, but it is not the only
kind. If you use another backup tool (Arq, Backblaze, Carbon Copy Cloner,
SuperDuper!, CrashPlan, restic, borg and others), that counts: you don't need
Time Machine as well. The checkup can see that such a tool is installed, but
not whether its last backup finished, so step 2 is yours to check.

Sync is different. Dropbox, Google Drive, OneDrive and iCloud Drive keep the
same files on every device. Delete a file, or have it damaged or scrambled,
and that change is copied everywhere. Some keep deleted files for a while, but
not forever.

## Step 1: Turn on Time Machine

If the checkup found no backup, or only sync:

1. Plug in an external drive with more space than the files on your Mac.
2. Open System Settings > General > Time Machine.
3. Click **Add Backup Disk** and choose the drive. If it asks to erase the
   drive, only say yes if nothing on it needs keeping.
4. Leave the drive plugged in until the first backup finishes. After that,
   plug it in now and then; Time Machine catches up on its own.

Prefer an online backup service instead, or as well? Any of the backup tools
above works. Having two copies in two places (a drive at home and an online
service) is the safest.

## Step 2: If you back up another way, check it is still working

1. Open your backup app.
2. Find the date of the last backup that finished. If it is more than a week
   old, or it shows errors, follow the app's own steps to fix it.
3. Check that the folders you care about (Documents, Desktop, Pictures,
   Photos) are included.

If the checkup said "No backup found, only sync" and you do back up another
way it can't see (a script of your own, a network drive), choose **I back up
another way** on that warning. It stays on the list, marked as your answer, so
anyone helping you can see it. If Time Machine or a backup app turns up later,
the answer is removed on its own.

## Step 3: Try getting one file back

A backup you have never restored from may not work when you need it.

1. Pick a file you don't need, and note its name.
2. Open Time Machine (or your backup app) and restore an older copy of it
   next to the original.
3. Open the restored copy. If it opens, your backup works.
