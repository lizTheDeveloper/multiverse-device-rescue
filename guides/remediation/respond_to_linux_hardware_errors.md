---
title: "Back up now: your drive or memory is reporting errors"
estimated_time: "30 minutes"
platforms: [linux]
remediates:
  - integrity.linux_journal_errors.storage_io_error
  - integrity.linux_journal_errors.smart_failure
  - integrity.linux_journal_errors.memory_error
  - integrity.linux_journal_errors.filesystem_error
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Your computer's own log says a part of it is failing: the storage drive, the
memory (RAM), or the way files are saved. Parts that start doing this often
keep working for a while and then stop, and files can be lost or damaged
without any warning. This is a hardware problem, not a sign that someone has
broken in. The most useful thing you can do is copy your important files to
somewhere else while the computer still reads them.

## Step 1: Copy your important files somewhere else

Plug in an external drive, or use a cloud storage service you already trust.
Open your file manager, then drag your Documents, Pictures and anything else
you can't replace onto that drive.

Do the backup before anything else. Don't run repair tools on a drive that is
reporting errors until your files are safe.

## Step 2: Check the drive's health

Open the **Disks** app (GNOME Disks on many systems). Select your main drive and
choose **SMART Data & Self-Tests**. If it says the drive is failing, treat it
as already lost.

Optional, from a terminal: `sudo smartctl -a /dev/sda` (change `sda` to your
drive name; `lsblk` lists it).

## Step 3: Test the memory if the errors mention memory

Restart the computer. At the boot menu choose **Memory Test** (memtest86+) if
your system offers it, and let it run through at least one full pass. Any error
it reports means a memory stick needs replacing.

## Step 4: Replace the failing part

- A failing drive: replace it, then restore your files onto the new one.
- Failing memory: replace the memory sticks, or take the computer to a repair
  shop and show them this result.
- Filesystem errors on a healthy drive: a repair shop can run a filesystem
  check from a rescue USB stick. Don't force it yourself if you aren't sure.

Don't keep using the computer for work you can't afford to lose until the part
has been replaced.
