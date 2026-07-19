---
title: "Enable and maintain antivirus protection"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.antivirus_status.xprotect_remediator
  - security.antivirus_status.mrt
  - security.antivirus_status.third_party_av
  - security.antivirus_status.av_not_running
  - security.antivirus_status.no_third_party_av
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers everything the `antivirus_status` module can flag:
the presence of Apple's built-in malware tools (XProtect Remediator, MRT),
detection of installed third-party antivirus software, and whether that
third-party software is actually running. All of these findings are
informational inventory or require enabling protection through the
respective vendor's app or System Settings — nothing here is auto-applied.

## Step 1: Confirm Apple's built-in malware protection is present

`xprotect_remediator` and `mrt` findings report on Apple's built-in tools.

1. If either was reported as "Not found," this may indicate a corrupted
   system installation. Run Software Update (System Settings > General >
   Software Update) to restore these components.
2. If both are present, no action is needed — these run automatically in
   the background and don't require manual scans.
3. For a deeper, versioned check of XProtect specifically (including
   staleness), see `update_xprotect.md`.

## Step 2: Start a detected but non-running third-party AV (warning)

A `av_not_running` finding means the module found an installed third-party
antivirus (Malwarebytes, Norton, Avast, Sophos, CrowdStrike, or
SentinelOne) whose process isn't currently active — meaning you likely
have no real-time protection from it despite believing you do.

1. Confirm you still intend to use this product; if not, consider fully
   uninstalling it instead of leaving a dormant, unpatched agent on disk.
2. If you want it active, open the application directly (e.g. from
   Applications) and verify it launches and shows real-time protection as
   enabled.
3. Check System Settings > General > Login Items & Extensions and confirm
   the AV's login item / background extension is enabled so it starts
   automatically at boot.
4. Re-run the scan to confirm the process is now detected as running.

## Step 3: Review installed third-party AV inventory

`third_party_av` and `no_third_party_av` are informational inventory
findings.

1. If third-party AV is installed, confirm it's a product you deliberately
   chose and still want — unexpected or unrecognized AV software can
   itself be a red flag (some malware/adware bundles impersonate security
   tools). If you don't recognize the product, investigate before trusting
   it: check `Applications`, verify the vendor via their official website,
   and consider a manual malware sweep before removing it.
2. If no third-party AV is installed, macOS's built-in protections
   (XProtect + MRT + Gatekeeper) are still active — this is a normal and
   supported configuration and doesn't require installing anything. If you
   want an additional open-source scanning layer, see
   `act_on_clamav_findings.md`.
