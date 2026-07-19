---
title: "Update XProtect definitions and restore Gatekeeper"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.xprotect_status.gatekeeper_disabled
  - security.xprotect_status.gatekeeper_status
  - security.xprotect_status.xprotect_missing
  - security.xprotect_status.xprotect_version
  - security.xprotect_status.xprotect_outdated
  - security.xprotect_status.xprotect_old
  - security.xprotect_status.mrt_version
  - security.xprotect_status.mrt_outdated
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `xprotect_status` module can flag:
Gatekeeper being disabled, XProtect malware definitions being missing,
outdated, or stale, and MRT (Malware Removal Tool) being outdated. All
fixes go through System Settings or Software Update — nothing here is
auto-applied, and re-enabling Gatekeeper in particular should be done
deliberately since it affects what software you're allowed to run.

## Step 1: Re-enable Gatekeeper (critical)

`gatekeeper_disabled` means macOS is not verifying that apps are signed
and notarized before running them — a significant reduction in
protection against malicious or tampered software.

1. Before re-enabling, consider *why* it might be disabled: some
   developers intentionally disable Gatekeeper for local testing of
   unsigned builds. If that's you, re-enable it when you're done testing
   rather than leaving it off long-term.
2. Open System Settings > Privacy & Security and set "Allow applications
   downloaded from:" to "App Store" or "App Store and identified
   developers."
3. Alternatively from Terminal: `sudo spctl --master-enable`. Verify with
   `spctl --status` — it should report `assessments enabled`.

## Step 2: Restore or update XProtect definitions

`xprotect_missing` (critical), `xprotect_outdated`, and `xprotect_old`
all mean XProtect's malware signature database is absent, below the
recommended version floor, or hasn't been refreshed recently.

1. Run Software Update: System Settings > General > Software Update.
   XProtect definitions update independently of full macOS version
   upgrades, so this is usually a quick background update rather than a
   full OS install.
2. If `xprotect_missing` was reported (the bundle itself is unreadable,
   not just outdated), this may indicate a corrupted system installation
   rather than a simple staleness issue. If Software Update doesn't
   restore it, consider running the built-in "Reinstall macOS" recovery
   path (Recovery Mode), which repairs system files without erasing user
   data — back up first via Time Machine regardless.
3. Confirm `automatic_updates` findings aren't also flagging
   `ConfigDataInstall` as disabled (see `enable_automatic_updates.md`) —
   that setting controls whether XProtect updates apply automatically
   going forward, preventing this from recurring.

## Step 3: Update MRT (Malware Removal Tool)

`mrt_outdated` means the tool responsible for detecting and removing
already-known malware families hasn't been refreshed recently.

1. Run Software Update the same way as Step 2 — MRT updates ship through
   the same channel as XProtect.
2. MRT runs automatically in the background after malware definitions
   update; no manual scan trigger is needed once it's current.

## Step 4: Review informational status

`gatekeeper_status`, `xprotect_version`, and `mrt_version` are
informational confirmations of current state. No action is required
when these appear — they exist so you can see what's currently
installed alongside any warnings above.
