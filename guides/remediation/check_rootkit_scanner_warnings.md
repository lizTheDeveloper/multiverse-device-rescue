---
title: "Understand rootkit scanner warnings (rkhunter, chkrootkit)"
platforms: [linux, macos]
remediates:
  - security.rootkit_scanners.possible_rootkit
  - security.rootkit_scanners.scanner_warning
  - security.rootkit_scanners.known_false_alarms
  - security.rootkit_scanners.ran_clean
  - security.rootkit_scanners.not_run
  - security.rootkit_scanners.not_installed
  - security.rootkit_scanners.needs_admin
  - security.rootkit_scanners.could_not_check
steps_for:
  security.rootkit_scanners.possible_rootkit: [1, 2, 3]
  security.rootkit_scanners.scanner_warning: [1, 2]
  security.rootkit_scanners.known_false_alarms: [4]
  security.rootkit_scanners.ran_clean: [5]
  security.rootkit_scanners.not_run: [6]
  security.rootkit_scanners.not_installed: [6]
  security.rootkit_scanners.needs_admin: [6]
  security.rootkit_scanners.could_not_check: [6]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

rkhunter and chkrootkit are two free, long-standing tools that look for
rootkits: malware that hides itself and gives someone else control of a
computer. They work by looking for files, settings and behaviour that known
rootkits leave behind. They are also known for false alarms, so Reclaim City
explains the common harmless ones and only raises what's left. Nothing is
changed by this check.

## Step 1: Before you change anything

Stop and read this before removing anything. It matters most if someone close
to you (a partner, an ex, a housemate, an employer) may have put monitoring
software on this computer. Removing it can tell whoever installed it that they have
been found out, and that can make things less safe for you. Talk to someone who
supports people in your situation before you remove anything you didn't
install.

In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text
START to 88788. The Coalition Against Stalkerware (stopstalkerware.org) lists
services in other countries.

Copy the warning lines from the finding into a note. They are what a helper
needs to see.

## Step 2: Look at what the warning names

1. Read the file paths in the warning. Search for the file name together with
   your distribution's name (for example "Ubuntu").
2. Check whether the file belongs to an installed package:
   `dpkg -S /path/to/file` (Debian, Ubuntu) or `rpm -qf /path/to/file`
   (Fedora, openSUSE). A file that belongs to a package and passes
   `sudo debsums -c` or `sudo rpm -Va` is the package's own.
3. A warning about hidden processes can be a coincidence of timing. Run the
   check again; if it shows again, take it seriously.
4. If you can't explain it, ask someone who helps with Linux or computer
   security, and show them the lines.

## Step 3: If it really looks like a rootkit

A rootkit runs with full control, so nothing on this computer can be fully
trusted, including the tools you'd use to check it.

1. Change important passwords (email first, then banking) from a different
   device you trust.
2. Copy off the personal files you need (documents and photos, not programs).
3. Reinstall the operating system from a fresh download. That is the only
   reliable way to get rid of a rootkit. Scan the copied files before you open
   them on the new system.

## Step 4: The warnings that are usually false alarms

Each one in the finding comes with its explanation. The common ones are a
command your distribution ships as a script, files changed by ordinary
updates since rkhunter took its snapshot, hidden files packages leave in
system folders, network-setup programs that open low-level connections,
shared memory used by desktop programs, and SSH settings. If something in
that list doesn't fit the explanation (a program name you don't recognise,
say), treat it as in Step 2.

To make rkhunter's file comparison useful, take its snapshot right after a
fresh install or a known-clean update: `sudo rkhunter --propupd`. Reclaim City
never does this for you: a snapshot of a computer that may already be
infected would make the infection look normal.

## Step 5: Nothing found

That lowers the odds of a rootkit without ruling one out. These scanners
recognise rootkits that have been written about; a new or custom one can be
missed. On a Mac they look at very little; the Mac's own checks and the deep
startup check (KnockKnock) look much further.

## Step 6: If the scanners didn't run

- **Not part of this checkup.** They read a lot of files and need
  administrator rights, so they run only when chosen:
  `sudo rescue scan --profile deep_startup_check`.
- **Not installed.** `sudo apt install rkhunter chkrootkit` (Debian, Ubuntu)
  or `sudo dnf install rkhunter chkrootkit` (Fedora).
- **Needs administrator rights.** Run the checkup with `sudo`.
- **Installed where anyone can change it.** Reclaim City won't run such a copy
  with administrator rights (common with Homebrew on a Mac). Install it from
  your system's package manager instead.
- **Timed out or stopped with an error.** Run it again. If it keeps failing,
  run the tool yourself (`sudo rkhunter --check --sk --rwo`, `sudo chkrootkit -q`)
  to see its own message.

A check that didn't run tells you nothing either way.
