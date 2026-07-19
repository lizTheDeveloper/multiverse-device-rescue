---
title: "Review app permissions (TCC grants)"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.app_permissions.accessibility_access
  - security.app_permissions.full_disk_access
  - security.app_permissions.screen_recording
  - security.app_permissions.camera_access
  - security.app_permissions.microphone_access
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers every macOS privacy permission (TCC) grant the
`app_permissions` module inventories: Accessibility, Full Disk Access,
Screen Recording, Camera, and Microphone. Each finding just lists which
apps currently hold a given permission — none of it is inherently a sign
of compromise, since you (or an app's install flow) granted these
deliberately at some point. The value here is periodic review: confirm you
still recognize and need every app on each list, and revoke anything you
don't.

## Step 1: Review Accessibility access

Accessibility lets an app observe and control other apps' UI and simulate
input — the same capability legitimate automation tools and malicious
keyloggers/RATs both rely on.

1. Read the listed apps. If the count exceeds 10 the finding is WARNING
   rather than INFO — treat that as a nudge to prune, not an emergency.
2. For each app you don't immediately recognize, identify it (System
   Settings > Privacy & Security > Accessibility shows friendlier names and
   icons than the raw bundle IDs in the finding).
3. Revoke access for anything you don't use or don't recognize: toggle it
   off, or select it and click the minus button to remove the entry
   entirely.

## Step 2: Review Full Disk Access

Full Disk Access lets an app read (and often write) any file on the
system, including other apps' data, Mail, Messages, and Time Machine
backups — one of the broadest grants macOS offers.

1. Read the listed apps and confirm each is something that legitimately
   needs whole-disk read access: backup tools, disk utilities, terminal
   emulators, antivirus/EDR software, and some IDEs are typical.
2. For anything unexpected, revoke it: System Settings > Privacy &
   Security > Full Disk Access, find the app, toggle off (or remove via the
   minus button).
3. If you revoke access from an app you actually use, it will likely
   re-prompt for the permission next time it needs it — that's expected and
   fine; only re-grant if you decide you do want it after all.

## Step 3: Review Screen Recording access

Screen Recording lets an app capture the contents of your screen —
malware uses this for surveillance; legitimate uses include screen-share
tools, recording software, and some accessibility aids.

1. Read the listed apps and confirm each is a tool you actively use for
   screen sharing, recording, or streaming (Zoom, OBS, QuickTime, remote
   support tools you initiated).
2. Revoke anything unrecognized: System Settings > Privacy & Security >
   Screen Recording, find the app, toggle off.
3. If an unfamiliar app has this permission alongside Accessibility and/or
   Microphone from the other findings here, treat that combination as a
   stronger signal worth investigating further (that combination matches
   common spyware/stalkerware capability sets) — check when and how the app
   was installed before deciding whether to remove it entirely.

## Step 4: Review Camera access

1. Read the listed apps and confirm each is something you've deliberately
   used for video (video call apps, camera utilities, browsers that
   requested it for a site you use).
2. Revoke anything unrecognized: System Settings > Privacy & Security >
   Camera, find the app, toggle off.

## Step 5: Review Microphone access

1. Read the listed apps and confirm each is something you've deliberately
   used for audio input (call apps, voice recorders, dictation/transcription
   tools, browsers for sites you use).
2. Revoke anything unrecognized: System Settings > Privacy & Security >
   Microphone, find the app, toggle off.
3. As with Step 3, an unrecognized app holding both Camera and Microphone
   access (or all three of Accessibility/Screen Recording/Microphone)
   deserves closer investigation before you conclude it's benign.
