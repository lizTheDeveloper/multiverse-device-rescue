---
title: "Enroll Touch ID and enable it for sudo authentication"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.sudo_touchid.touchid_status
  - security.sudo_touchid.no_fingerprints
  - security.sudo_touchid.sudo_not_enabled
  - security.sudo_touchid.applepay_enabled
  - security.sudo_touchid.no_hardware
automatable_steps: []
human_only_steps: [1, 2]
---

This walkthrough covers what `sudo_touchid` flags: whether Touch ID hardware
exists, whether fingerprints are enrolled, and whether Touch ID is wired up
for `sudo`. Enabling Touch ID for sudo means editing a PAM configuration
file (`/etc/pam.d/sudo`) — back it up first and test in the same terminal
session before closing it, exactly as with any other sudo-adjacent change.

## Step 1: Enroll fingerprints (if hardware exists but none enrolled)

Only relevant if `no_fingerprints` was flagged — this means Touch ID
hardware is present but nothing is enrolled yet.

1. Open System Settings > Face ID & Passcode (or Touch ID & Password on
   older macOS).
2. Click "Add Fingerprint" and follow the on-screen prompts.
3. Re-run the scan to confirm `touchid_status` now reports at least one
   fingerprint enrolled.

## Step 2: Enable Touch ID for sudo

Only relevant if `sudo_not_enabled` was flagged. This is optional — sudo
already works fine with a password; Touch ID just adds a biometric option.

1. Confirm at least one fingerprint is enrolled (Step 1) before proceeding.
2. Back up the current PAM config: `sudo cp /etc/pam.d/sudo
   /etc/pam.d/sudo.bak`.
3. Edit `/etc/pam.d/sudo` (e.g. `sudo nano /etc/pam.d/sudo`) and add this
   line as the **first** `auth` line, before any existing `auth` entries:
   `auth       sufficient     pam_tid.so`
4. Save and, in the **same terminal session** (don't close it), run a
   throwaway `sudo -k && sudo true` to confirm you're prompted for Touch ID
   and that it succeeds.
5. If something goes wrong and sudo stops working entirely, restore the
   backup: `sudo cp /etc/pam.d/sudo.bak /etc/pam.d/sudo` (you may need
   physical/recovery access if sudo itself is broken — this is why testing
   in the same session before closing it matters).

## Step 3: Review informational findings

`touchid_status`, `applepay_enabled`, and `no_hardware` are purely
informational — no action is needed. `no_hardware` in particular means this
Mac doesn't support Touch ID at all (older Intel Macs, some Mac minis/Mac
Pros without a Magic Keyboard with Touch ID), so Steps 1-2 don't apply.
