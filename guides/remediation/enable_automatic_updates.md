---
title: "Enable automatic software updates"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.automatic_updates.automatic_check
  - security.automatic_updates.automatic_download
  - security.automatic_updates.auto_install_macos
  - security.automatic_updates.critical_update
  - security.automatic_updates.config_data
  - security.automatic_updates.app_store_auto
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `automatic_updates` module can
flag: any of the six independent Software Update automation toggles being
disabled (checking for updates, downloading them, installing macOS
updates, installing critical security updates, installing configuration
data like XProtect/Gatekeeper definitions, and App Store app updates).
All six live in one settings pane, so it's efficient to review them
together, but confirm your intent for each before flipping it — some
users deliberately disable auto-install on machines where they want to
control update timing (e.g. before a demo or a long build).

## Step 1: Open Software Update automation settings

1. Open System Settings > General > Software Update.
2. Click the "i" (info) button next to "Automatic updates" to see the
   individual toggles — this expanded view maps directly to the findings
   below.

## Step 2: Enable the flagged toggles

Match each finding to its toggle and enable it, unless you have a
specific reason not to:

- `automatic_check` → "Check for updates"
- `automatic_download` → "Download new updates when available"
- `auto_install_macos` → "Install macOS updates"
- `critical_update` (critical severity) → "Install Security Responses and
  system files" — this is the most important one to enable, since it
  covers XProtect, Gatekeeper, and other rapid-response security patches
  that ship independently of full macOS version updates.
- `config_data` → also covered by "Install Security Responses and system
  files" on current macOS versions (older versions may show this as a
  separate "Install system data files and security updates" toggle).
- `app_store_auto` → "Automatically update apps from the App Store."

For each toggle you enable, confirm it actually took by re-opening the
panel after toggling — some environments (MDM-managed machines) lock
these settings, in which case check with your IT/MDM administrator rather
than fighting the UI.

## Step 3: Confirm on managed/MDM devices

If this Mac is enrolled in an MDM (see `mdm_enrollment` module
findings), your organization may intentionally control update timing
centrally, and some toggles may appear greyed out. In that case, this is
expected and not something to override locally — updates are likely
still being applied on a schedule set by IT.
