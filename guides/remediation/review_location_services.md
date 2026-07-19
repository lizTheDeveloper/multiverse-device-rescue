---
title: "Review Location Services"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.location_services.location_services_enabled
  - security.location_services.location_system_services
  - security.location_services.location_desktop_find_my_only
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers what the `location_services` module inventories:
whether Location Services is enabled system-wide, which system services
(Find My Mac, Setting Time Zone, Emergency Services, etc.) currently use
it, and a specific nudge for desktops where it's enabled only for Find My
Mac. Location Services has clear legitimate uses — Find My Mac, Maps,
weather, automatic time zone — so nothing here is auto-applied; the value
is confirming the services using it are ones you actually want.

## Step 1: Decide whether Location Services should be on at all

1. Open System Settings > Privacy & Security > Location Services.
2. If you don't use any location-dependent feature (Find My Mac, Maps,
   location-aware apps, automatic time zone), you can disable the top-level
   toggle entirely.
3. If you're not sure, move to Step 2 and review what's actually using it
   before deciding.

## Step 2: Review which system services use location

1. In the same Location Services pane, scroll to "System Services" at the
   bottom of the list.
2. Review each service the scan reported (e.g., Find My Mac, Setting Time
   Zone, Emergency Services) and disable any you don't need. Setting Time
   Zone and Emergency Services are usually safe to leave on for laptops
   that travel; Find My Mac is worth keeping if you rely on it to locate a
   lost or stolen device.

## Step 3: Reconsider Location Services on desktops used only for Find My Mac

If the scan flagged this: Location Services is enabled on a desktop
computer (Mac mini, iMac, Mac Studio, Mac Pro) solely for Find My Mac.

1. Ask whether you actually rely on Find My Mac for this machine — desktops
   don't move, so the "find a lost device" use case is much weaker than for
   a laptop.
2. If you don't use it, disable Location Services entirely (System Settings
   > Privacy & Security > Location Services > toggle off) for a small
   privacy improvement with no functional loss.
3. If you do want to keep the ability to remotely locate/lock/wipe this Mac,
   you can leave Location Services on for just Find My Mac — that feature
   also works through iCloud.com without Location Services being enabled
   system-wide in some configurations, so re-check whether disabling it
   actually removes the capability you want to keep before turning it off.
