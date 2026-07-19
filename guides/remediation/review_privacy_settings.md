---
title: "Review privacy settings"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.privacy_audit.location_services
  - security.privacy_audit.personalized_ads
  - security.privacy_audit.analytics
  - security.privacy_audit.significant_locations
  - security.privacy_audit.siri_suggestions
  - security.privacy_permissions_audit.camera_access
  - security.privacy_permissions_audit.microphone_access
  - security.privacy_permissions_audit.screen_recording_access
  - security.privacy_permissions_audit.accessibility_access
  - security.privacy_permissions_audit.full_disk_access
  - security.privacy_permissions_audit.contacts_access
  - security.privacy_permissions_audit.excessive_camera
  - security.privacy_permissions_audit.excessive_microphone
  - security.privacy_permissions_audit.camera_microphone_combo
  - security.privacy_permissions_audit.screen_accessibility_combo
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7]
---

This walkthrough covers what the `privacy_audit` and `privacy_permissions_audit`
modules inventory: system-wide privacy toggles for Location Services,
Personalized Ads, Analytics (diagnostics & usage data sharing), Significant
Locations, and Siri Suggestions data collection, plus (for
`privacy_permissions_audit`) which apps hold TCC permission grants —
Camera, Microphone, Screen Recording, Accessibility, Full Disk Access, and
Contacts — and dangerous combinations of those grants. Each of these is a
deliberate Apple feature with legitimate uses — Location Services powers
Find My Mac and Maps, Analytics helps Apple fix bugs, Siri Suggestions
makes Spotlight more useful, and per-app permissions are how apps get to
use the camera or read your files at all. None of it is inherently a
problem; the point is to confirm each toggle and grant matches what you
actually want, and turn off/revoke anything you don't need. Nothing here is
auto-applied since these are personal preference trade-offs and revoking an
app's access is a judgment call only you can make.

(`privacy_permissions_audit` inventories the same TCC categories that
`review_app_permissions.md` covers for the `app_permissions` module —
Accessibility, Full Disk Access, Screen Recording, Camera, Microphone — plus
Contacts and cross-permission combination checks that `app_permissions`
doesn't flag. If both modules are enabled you may see two findings for the
same underlying grant; follow either walkthrough's steps, they lead to the
same System Settings panes.)

## Step 1: Review Location Services

1. Open System Settings > Privacy & Security > Location Services.
2. If you don't use location-dependent features (Find My Mac, Maps,
   location-aware apps), consider disabling it entirely with the top-level
   toggle.
3. If you want to keep it on, scroll the per-app list and disable location
   access for individual apps that don't need it — this is often a better
   middle ground than an all-or-nothing toggle.

## Step 2: Review Personalized Ads

1. Open System Settings > Privacy & Security > Apple Advertising.
2. Toggle "Personalized Ads" off if you don't want your App Store/Apple
   News/Stocks activity used to target ads to you. This doesn't reduce the
   number of ads shown, only how targeted they are.

## Step 3: Review Analytics & Improvements (diagnostics/usage sharing)

1. Open System Settings > Privacy & Security > Analytics & Improvements.
2. Uncheck "Share Mac Analytics" (and related app-developer sharing
   options) if you'd rather not send diagnostic/usage data to Apple or
   third-party developers. This has no functional impact on the device —
   it only affects what gets reported.

## Step 4: Review Significant Locations

Significant Locations builds a private, on-device history of places you
visit frequently, used for Maps/Calendar suggestions and time-based
reminders.

1. Open System Settings > Privacy & Security > Location Services > System
   Services (scroll to the bottom) > Significant Locations.
2. Review the history it has already built if you're curious what it's
   collected, then disable the toggle if you don't want this on-device
   location history kept.

## Step 5: Review Siri Suggestions data collection

1. Open System Settings > Siri & Spotlight.
2. Review "Learn from this Mac" (or the app-specific suggestion sources)
   and disable it if you don't want Apple analyzing app/activity usage to
   power Spotlight and Siri suggestions.

## Step 6: Review per-app TCC permission grants

For each category the scan reported apps under (Camera, Microphone, Screen
Recording, Accessibility, Full Disk Access, Contacts):

1. Read the listed apps for that category and confirm you recognize and
   still use every one of them — the finding lists exactly which apps
   currently hold the grant.
2. Open System Settings > Privacy & Security > [category] for anything
   unrecognized or no longer needed, and toggle it off (or remove the entry
   with the minus button).
3. If you revoke access from an app you actually use, expect it to
   re-prompt for the permission next time it needs it — that's normal; only
   re-grant if you decide you want it after all.
4. Full Disk Access and Accessibility are the broadest grants (whole-disk
   read/write, and simulating input/observing other apps respectively) —
   scrutinize those lists most closely. Contacts access is narrower but
   still worth confirming: it's an easy way for a rogue app to exfiltrate
   your address book.

## Step 7: Investigate flagged high-risk combinations

The scan separately flags apps holding more than one sensitive permission
at once, and cases where more than 10 apps hold camera or microphone
access — these are stronger signals than any single grant on its own.

1. **Excessive camera/microphone access (>10 apps)**: treat this as a
   prompt to prune, not an emergency — review the full list from Step 6 and
   revoke access for apps that don't need it day-to-day.
2. **Camera + Microphone on the same app**: verify each listed app is a
   legitimate video/call tool you use (Zoom, FaceTime, browsers for sites
   you use). This combination is also what stalkerware/spyware typically
   requests, so anything you don't recognize deserves closer investigation
   before you conclude it's benign — check when and how it was installed.
3. **Screen Recording + Accessibility on the same app (highest risk)**:
   this combination gives an app the ability to see everything on your
   screen and simulate all input — effectively full remote-control
   capability. Only trusted software (screen-share tools, remote support
   you initiated, legitimate automation/accessibility utilities, security
   software) should hold both. Investigate and revoke immediately for
   anything you don't fully recognize and trust.
