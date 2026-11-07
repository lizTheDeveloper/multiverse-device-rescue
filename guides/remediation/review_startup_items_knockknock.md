---
title: "Look over what starts on its own (KnockKnock)"
platforms: [macos]
remediates:
  - security.knockknock_scan.unsigned_autostart
  - security.knockknock_scan.broken_signature
  - security.knockknock_scan.unreadable_autostart
  - security.knockknock_scan.rare_autostart_place
  - security.knockknock_scan.signed_inventory
  - security.knockknock_scan.not_run
  - security.knockknock_scan.could_not_check
  - security.knockknock_scan.changed_during_run
steps_for:
  security.knockknock_scan.unsigned_autostart: [1, 2]
  security.knockknock_scan.broken_signature: [1, 3]
  security.knockknock_scan.unreadable_autostart: [1, 2]
  security.knockknock_scan.rare_autostart_place: [1, 4]
  security.knockknock_scan.signed_inventory: [5]
  security.knockknock_scan.not_run: [6]
  security.knockknock_scan.could_not_check: [6]
  security.knockknock_scan.changed_during_run: [7]
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7]
---

Malware that wants to stay on a Mac has to arrange to start again after a
restart. KnockKnock, a free tool from Objective-See, lists every place macOS
starts things from, and checks who signed each program. Reclaim City leaves
out what is part of macOS and shows you the rest. Most of what it shows is
ordinary: apps, their helpers and updaters. Nothing here is removed for you.

## Step 1: Before you remove anything

Stop and read this before removing anything. It matters most if someone close
to you (a partner, an ex, a housemate, an employer) may have put monitoring
software on this Mac. Removing it can tell whoever installed it that they have
been found out, and that can make things less safe for you. Talk to someone who
supports people in your situation before you remove anything you didn't
install.

In the US, the National Domestic Violence Hotline is 1-800-799-7233, or text
START to 88788. The Coalition Against Stalkerware (stopstalkerware.org) lists
services in other countries.

Write down the name and the file paths in the finding first, so you or a
helper can look them up later.

## Step 2: A program with no signature, or one that couldn't be read

A signature says who made a program. Apps from the App Store and from known
developers have one; macOS checks it. The finding says this program has
none (or only an "ad-hoc" one, which doesn't name a maker).

1. Read the name and the folder. A program in Homebrew's folder
   (`/opt/homebrew/`) was installed with Homebrew, a tool developers use. A
   script in your own projects folder is usually something you or a helper
   wrote. Those are normal on a computer someone develops software on.
2. If you don't recognise it, search for the name together with "Mac".
3. Still unsure? Ask someone who helps you with computers, and show them
   the finding.
4. To stop it starting, follow the launch agent steps in the other startup
   findings for the same settings file (the "Started by" line), or remove the
   app it came with. Don't delete files you can't identify.

If the finding says the program couldn't be read, that usually means only the
system account can open it. Most of these belong to an app you installed
(the name often starts with the maker's name, for example `com.docker`).

## Step 3: A signature that doesn't check out

The file was changed after its maker signed it.

1. Update the app from its maker's website or the App Store, or reinstall it.
2. Run the deep startup check again.
3. If it still doesn't check out, or you don't know which app it belongs to,
   ask someone who helps you with computers before you remove it.

## Step 4: Something in a rarely used place

Library inserts, login and logout hooks, authorization plugins (the login
and password prompts), directory services plugins, event rules, and startup
or periodic scripts are places very few genuine apps use. Some put code
inside other programs or the login window, where it can see what you type.

1. On a work or school Mac, ask its IT team first; security and management
   tools sometimes use these places.
2. If you didn't install a security, VPN or remote-support tool, treat this as
   serious: keep using a different device for passwords and banking for now,
   and get help from someone who knows Macs.
3. Read Step 1 before you remove anything.

## Step 5: The list of signed items

This is a list, not a problem. Signed means the maker is known, not that
the program is safe or wanted. Read it for anything you don't remember
installing. Remote-access and monitoring tools are signed too.

## Step 6: If the check didn't run

The finding says why:

- **Not part of this checkup.** The deep startup check reads a lot of files,
  so it only runs when chosen: `rescue scan --profile deep_startup_check`.
- **Full Disk Access.** KnockKnock needs it to see everything. Open System
  Settings > Privacy & Security > Full Disk Access, turn on Reclaim City (or
  Terminal, if you ran the checkup from there), quit and reopen it, and run
  the check again. You can turn it off again afterwards.
- **Downloads are off, or the computer is offline.** The first run downloads
  KnockKnock (2.5 MB) from Objective-See's page on GitHub. You can also
  install it yourself from <https://objective-see.org>; a copy in
  Applications is used when it's genuine.
- **The download or the copy wasn't genuine.** Reclaim City only runs a
  KnockKnock signed by Objective-See and checked by Apple. Try again later,
  on another network if it keeps happening.
- **Administrator rights.** Run the checkup the normal way, without `sudo`.

A check that didn't run tells you nothing either way.

## Step 7: If the checker's files changed while it was running

Reclaim City checks KnockKnock's signature right before and right after it
runs. This time it no longer checked out afterwards, which a genuine copy
can't do. Another program may have swapped in its own code.

1. Don't start deleting things. Write down the date and time.
2. Run the checkup again and look at everything set to start on its own.
3. If it happens again, treat this Mac as possibly compromised: change
   important passwords from a different device, and get help.
