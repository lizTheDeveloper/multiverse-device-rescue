---
title: "Review Accessibility permission grants"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.accessibility_permissions.accessibility_access
  - security.accessibility_permissions.suspicious_accessibility
  - security.accessibility_permissions.excessive_accessibility
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `accessibility_permissions` module
can flag: the full inventory of apps granted macOS Accessibility access,
apps in that list that aren't recognized system tools or well-known
developer/utility apps, and simply having too many apps with this
permission. Accessibility access is powerful — it lets an app observe and
control other apps' UI, simulate keystrokes, and read screen content, which
is exactly the capability malware (and legitimate automation tools) both
want. Confirm the app before revoking, and confirm it's actually unwanted
before revoking — some of these are tools you rely on daily (window
managers, automation scripts, remote-control software).

## Step 1: Review the full Accessibility access inventory

Informational — lists every app with this permission currently granted,
combining both the system and per-user TCC databases.

1. Read the list and cross-check it against what you expect: window
   managers (Rectangle, Magnet), automation tools (Hammerspoon, Keyboard
   Maestro), remote-support apps (TeamViewer, AnyDesk), and IDEs that use
   Accessibility for certain features are all normal entries if you use
   them.
2. Open System Settings > Privacy & Security > Accessibility yourself to
   see the same list with friendlier app names and toggle switches.
3. For anything you don't recognize, move to Step 2 rather than acting
   immediately here.

## Step 2: Investigate suspicious Accessibility grants

Flagged for apps that aren't Apple system components and aren't on the
built-in list of well-known developer tools, terminals, and automation
apps. This is a coarse allowlist, so plenty of legitimate apps (niche
utilities, apps installed outside the well-known set) will land here too —
treat it as "worth checking," not "confirmed bad."

1. Note the bundle identifier(s) listed.
2. Identify what app the bundle ID belongs to: `mdfind
   "kMDItemCFBundleIdentifier == '<bundle-id>'"` will usually locate the
   app on disk, or check System Settings > Privacy & Security >
   Accessibility where entries show the app's icon and display name.
3. If you recognize and use the app, and it plausibly needs Accessibility
   (an automation tool, a window manager, a screen reader/dictation aid,
   remote support software you initiated), no action is needed.
4. If you don't recognize the app, or it's something you don't remember
   granting this permission to, revoke it: System Settings > Privacy &
   Security > Accessibility, find the app, and toggle it off (or select it
   and click the minus button to remove it entirely).
5. If revoking reveals the app breaks in a way that makes you suspicious
   (it immediately re-requests the permission via a dialog, or another
   process tries to re-grant it), treat that as a stronger signal of
   unwanted software and investigate further — check
   `~/Library/LaunchAgents` and `/Library/LaunchAgents` for a persistence
   mechanism tied to that app before removing the app itself.

## Step 3: Reduce excessive Accessibility grants

Flagged when more than 10 apps hold this permission. Even if every single
one is legitimate, a large Accessibility allowlist is a larger attack
surface — any one of those apps being compromised gives the attacker
Accessibility-level control.

1. Open System Settings > Privacy & Security > Accessibility.
2. For each app, ask whether it's actively in use; toggle off (or remove)
   entries for apps you've stopped using or that no longer need this level
   of access.
3. Re-run the scan afterward to confirm the count has dropped below the
   threshold.
