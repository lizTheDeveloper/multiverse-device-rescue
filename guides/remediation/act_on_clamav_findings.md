---
title: "Act on ClamAV scanner findings"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.clamav_scanner.clamav_not_installed
  - security.clamav_scanner.clamav_version
  - security.clamav_scanner.freshclam_not_installed
  - security.clamav_scanner.clamav_definitions
  - security.clamav_scanner.clamav_outdated_definitions
  - security.clamav_scanner.clamd_not_running
  - security.clamav_scanner.clamd_running
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `clamav_scanner` module can flag:
whether ClamAV (an optional, free/open-source antivirus engine) and its
`freshclam` definition updater are installed, how old the virus
definitions are, and whether the `clamd` on-access scanning daemon is
running. ClamAV is complementary to Apple's built-in protections
(see `enable_antivirus.md` and `update_xprotect.md`) — it is not required,
but if you've chosen to run it, these findings keep it effective.

## Step 1: Install ClamAV (if you want it, and it's missing)

`clamav_not_installed` and `freshclam_not_installed` mean ClamAV or its
updater isn't present.

1. Decide whether you actually want an on-disk scanning engine — many
   users rely solely on Apple's built-in XProtect/Gatekeeper/MRT
   protections and never need this. If you don't have a specific reason to
   run ClamAV, no action is required.
2. If you do want it, install via Homebrew: `brew install clamav`. This
   installs both `clamscan`/`clamd` and `freshclam` together.
3. Verify the install: `clamscan --version` and `freshclam --version`
   should both report a version.

## Step 2: Update outdated virus definitions (critical)

`clamav_outdated_definitions` (definitions older than 30 days) means
ClamAV is present but effectively providing a false sense of security —
it won't catch recent malware.

1. Back up nothing is needed here (definitions are a public signature
   database, not user data), but do confirm you're running this from a
   trusted network before pulling updates.
2. Run `freshclam` manually to pull the latest signatures.
3. If `freshclam` fails with a permissions or lock error, check whether a
   `clamd` process is mid-update; wait for it to finish rather than killing
   it.
4. Consider setting up a recurring update (e.g. `brew services start
   clamav` runs `freshclam` on a schedule as part of the Homebrew
   service, or add your own `launchd` job) so this doesn't go stale again.

## Step 3: Start the clamd on-access daemon

`clamd_not_running` means the daemon that would provide on-access
scanning isn't active. `clamd_running` is the informational
confirmation that it is.

1. Confirm you actually want on-access scanning running continuously in
   the background — it has a real CPU/memory cost. If you'd rather run
   occasional manual scans with `clamscan` instead, no daemon is needed.
2. To start it: `brew services start clamav`.
3. Confirm it's active: `pgrep clamd` should return a PID.

## Step 4: Review inventory findings

`clamav_version` and `clamav_definitions` are informational — they report
the installed engine and signature database versions. No action is
required beyond periodically confirming the definition age stays low
(see Step 2) if you're relying on ClamAV for protection.
