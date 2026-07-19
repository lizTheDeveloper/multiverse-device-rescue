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
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers what the `privacy_audit` module inventories: system-
wide privacy toggles for Location Services, Personalized Ads, Analytics
(diagnostics & usage data sharing), Significant Locations, and Siri
Suggestions data collection. Each of these is a deliberate Apple feature
with legitimate uses — Location Services powers Find My Mac and Maps,
Analytics helps Apple fix bugs, Siri Suggestions makes Spotlight more
useful. None of it is inherently a problem; the point is to confirm each
toggle matches what you actually want, and turn off anything you don't need.
Nothing here is auto-applied since these are personal preference trade-offs
between convenience and data sharing.

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
