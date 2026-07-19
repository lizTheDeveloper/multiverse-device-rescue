---
title: "Tighten Siri privacy settings"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.siri_privacy.siri_enabled
  - security.siri_privacy.hey_siri
  - security.siri_privacy.siri_suggestions
  - security.siri_privacy.siri_analytics
  - security.siri_privacy.lockscreen_siri
  - security.siri_privacy.siri_config_status
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers what the `siri_privacy` module inventories: whether
Siri is enabled, whether "Hey Siri" always-on listening is active, Siri
Suggestions in Spotlight, Siri analytics/data sharing with Apple, and —the
one genuine security concern here — whether Siri can be invoked from the
lock screen without authentication. Siri itself is a legitimate,
deliberately-installed feature, so most of this is preference review, not a
problem to fix. Nothing is auto-applied since disabling Siri outright is a
significant workflow change you should decide on yourself.

## Step 1: Disable Siri access from the lock screen (do this first if flagged)

This is the one finding here that's a real security exposure rather than a
preference trade-off: anyone with physical access to a locked Mac can talk
to Siri and potentially extract information (read notifications, send
messages, query calendar/reminders) without ever unlocking the device.

1. Open System Settings > Siri & Spotlight (or Lock Screen, depending on
   macOS version).
2. Disable "Allow Siri When Locked" (sometimes labeled "Siri" under Lock
   Screen options).
3. Confirm by locking the screen and attempting to invoke Siri — it should
   be unavailable until the device is unlocked.

## Step 2: Decide whether Siri should be enabled at all

1. Open System Settings > Siri & Spotlight.
2. If you don't use voice commands, turn off "Enable Ask Siri" (or the
   equivalent top-level toggle). This is a convenience trade-off, not a
   security requirement.

## Step 3: Review "Hey Siri" always-on listening

"Hey Siri" requires the microphone to listen continuously for the wake
phrase.

1. In System Settings > Siri & Spotlight, review "Listen for 'Hey Siri'."
2. If you'd rather not have always-on listening, disable it — you can still
   invoke Siri via keyboard shortcut or the menu bar icon.

## Step 4: Review Siri Suggestions

1. In System Settings > Siri & Spotlight, review the Suggestions section
   (Spotlight, Lock Screen, Share Sheet).
2. Disable any suggestion source you don't find useful — this only affects
   what Apple analyzes to power those suggestions, not core Siri
   functionality.

## Step 5: Review Siri analytics and data sharing

1. In System Settings > Siri & Spotlight, scroll to the bottom for "Siri &
   Dictation Analytics" (or a similar sharing toggle).
2. Uncheck it if you don't want usage data sent to Apple. If the scan
   instead reported a general "Siri privacy configuration" status finding
   (no specific setting was enabled/detectable), use this walkthrough as a
   checklist to confirm your intended configuration across Steps 1-4 rather
   than assuming anything needs to change.
