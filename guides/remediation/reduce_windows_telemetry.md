---
title: "Reduce Windows telemetry and privacy exposure"
estimated_time: "15 minutes"
platforms: [windows]
remediates:
  - security.win_cortana_telemetry.telemetry_level
  - security.win_cortana_telemetry.cortana_enabled
  - security.win_cortana_telemetry.advertising_id
  - security.win_cortana_telemetry.activity_feed
  - security.win_cortana_telemetry.location_services
  - security.win_cortana_telemetry.optimized
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

Everything the `win_cortana_telemetry` module flags is a privacy setting,
not a security vulnerability — Cortana, telemetry level, advertising ID,
activity history, and location services are all legitimate features some
people use daily (voice search, personalized experiences, "find my apps"
style location features). Nothing here is urgent the way a disabled
antivirus is; treat these as opt-in privacy hardening, not something to
change without knowing what you're giving up. All changes are made through
Settings (GUI) rather than deleting or editing files, so there's no
destructive-edit risk, but confirm you don't rely on a feature before
turning it off.

## Step 1: Telemetry level (Enhanced or Full)

Windows telemetry sends diagnostic data to Microsoft. Enhanced/Full levels
send more detailed usage data than Basic/Minimal.

1. Confirm current state: Settings → Privacy & Security → Diagnostics &
   feedback → Diagnostic data, or `reg query
   "HKLM\SOFTWARE\Policies\Microsoft\Windows\DataCollection" /v
   AllowTelemetry`.
2. If you don't specifically need enhanced diagnostics (e.g. for
   troubleshooting with Microsoft support), reduce it: Settings → Privacy &
   Security → Diagnostics & feedback → select "Required diagnostic data
   (minimal)" or "Optional diagnostic data (basic)".
3. Note that on Windows Home editions, the minimum available level may
   still be "Required diagnostic data" — this is a Microsoft-imposed floor,
   not a bug in this check.

## Step 2: Cortana enabled

Cortana enabled means voice, search, and activity data may be collected to
power its features.

1. If you don't use Cortana/voice activation, disable it: Settings →
   Privacy & Security → Voice activation → toggle off "Let Cortana respond
   to Voice activation" and any wake-word settings.
2. If you do use voice activation features, it's fine to leave this
   enabled — this is an informational finding, not a security risk.

## Step 3: Advertising ID enabled

The Advertising ID lets apps show personalized ads by correlating your
activity across apps.

1. Disable via Settings → Privacy & Security → General → toggle off "Let
   apps show me personalized ads by using my advertising ID".
2. This has no functional downside for most users beyond seeing less
   targeted ads — safe to disable if you have no reason to keep it.

## Step 4: Activity History enabled

Activity History tracks recently used apps, documents, and websites,
optionally syncing them via your Microsoft account for Timeline/handoff
features.

1. If you don't use cross-device activity handoff, disable it: Settings →
   Privacy & Security → Activity history → uncheck "Store my activity
   history on this device" (and "Send my activity history to Microsoft" if
   present).
2. If you rely on picking up activity across multiple devices signed into
   the same Microsoft account, you can leave this on — again informational,
   not a vulnerability.

## Step 5: Location services enabled

Location services let apps request the device's physical location.

1. Review which specific apps have location access: Settings → Privacy &
   Security → Location → scroll to see per-app permissions.
2. If you don't need location features generally, disable the master
   toggle: Settings → Privacy & Security → Location → toggle "Location
   services" off.
3. A more surgical alternative that preserves useful location features
   (maps, weather) while cutting others is to leave the master toggle on
   but disable location per-app for anything you don't recognize or trust,
   rather than disabling location services wholesale.

## No issues found

If the scan reports the `optimized` INFO finding, telemetry is already at
Basic/Minimal, and Cortana, Advertising ID, Activity History, and Location
services are all disabled — no action is needed.
