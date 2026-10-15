---
title: "Review what changed on your computer since the last check"
estimated_time: "20 minutes"
platforms: [macos, windows, linux]
remediates:
  - security.security_baseline_diff.new_persistence
  - security.security_baseline_diff.new_listening_port
  - security.security_baseline_diff.new_browser_extension
  - security.security_baseline_diff.protection_disabled
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

The first time it ran, this tool wrote down what normally starts up, what
listens for connections, which browser extensions are installed and which
protections are on. This time something is different. Installing new software
causes changes like this too, so the question to ask is simple: did I install
something around then? If you didn't, something else may have.

**Before you remove anything:** if someone you know may be monitoring you,
removing what they installed can alert that person. Talk to an advocate first
(US National DV Hotline: 1-800-799-7233, or text START to 88788). Take a photo
of the finding so you have a record.

## Step 1: Turn protections back on if any were switched off

If a protection was turned off and you didn't do it, treat it as the most
important item here.

- **Mac:** open **System Settings > Privacy & Security** and check FileVault,
  and **System Settings > Network > Firewall** to turn the firewall on.
- **Windows:** open **Windows Security** from the Start menu and fix anything
  marked with a red or yellow icon.
- **Linux:** turn your firewall back on (see "Turn on your firewall").

## Step 2: Check new startup items

- **Mac:** **System Settings > General > Login Items & Extensions**.
- **Windows:** **Settings > Apps > Startup**.

Look for names you don't recognise. Switching an item off is gentler than
deleting it and can be undone. Read the note above first.

## Step 3: Check new browser extensions

Open your browser's extensions page: in Chrome, the three-dot menu > **Extensions >
Manage Extensions**; in Safari, **Safari > Settings > Extensions**; in Firefox,
the menu > **Add-ons and themes**. Switch off any you don't remember adding.

## Step 4: Check for new network listeners

A new "listening port" means a program is waiting for incoming connections. If
you recently installed something that shares files, plays media or lets you
connect remotely, that's the likely reason. If not, make sure your firewall is on
(Step 1) and look for unfamiliar apps in your startup list (Step 2).
