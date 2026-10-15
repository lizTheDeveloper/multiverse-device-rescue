---
title: "Check what starts automatically on your Linux computer"
estimated_time: "30 minutes"
platforms: [linux]
remediates:
  - security.linux_persistence_audit.ld_preload_set
  - security.linux_persistence_audit.suspicious_content
  - security.linux_persistence_audit.volatile_path_execution
  - security.linux_persistence_audit.world_writable_unit
  - security.linux_persistence_audit.inventory
steps_for:
  security.linux_persistence_audit.world_writable_unit: [1, 2, 4]
  security.linux_persistence_audit.inventory: [1, 2]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Software that wants to survive a restart arranges to start itself again at
every boot or login. Most of those entries are ordinary programs. Some are not:
a startup entry that downloads and runs code from the internet each time, or
runs a program from a temporary folder, is how a break-in stays in place, and a
startup file that any account can rewrite is an open invitation to do it.

**Before you remove or change anything:** if someone you know may be monitoring
you, removing their software can alert that person. Talk to an advocate first
(US National DV Hotline: 1-800-799-7233, or text START to 88788). Don't delete
the entry or the files it points to. They are evidence of what happened.

## Step 1: Write down what was flagged

Copy the file path shown in the finding and a few words about what it said.
Take a photo of the screen as well.

## Step 2: Check if you installed this program

Developer tools, sync apps and desktop helpers do add startup entries. Open the
file in a text editor (read only) and see if the name and the commands match
something you installed on purpose. If you do recognise it, you're done with
that entry.

## Step 3: Stop using this computer for important accounts

If the finding is about a preloaded library (`/etc/ld.so.preload`) or a startup
entry you can't explain, treat the computer as no longer private. Stop signing
in to email, banking and other important accounts on it. Use a different,
clean device for that, and change those passwords from there.

## Step 4: Back up files and get help to fix the system

Back up your documents (not programs) to an external drive, then ask a
trusted technical person, a local computer-repair shop, or an advocate to help
you reinstall the system. Reinstalling is more reliable than trying to remove
a hidden entry by hand.

For an entry that is only a file anyone can change, you or a technical
helper can fix the permissions: `sudo chmod go-w PATH` (replace `PATH` with
the file path from the finding).
