---
title: "Review Bluetooth discoverability and paired devices"
estimated_time: "10 minutes"
platforms: [macos]
remediates:
  - security.bluetooth_audit.paired_devices
  - security.bluetooth_audit.discoverable_state
automatable_steps: []
human_only_steps: [1, 2]
---

Bluetooth is a feature you likely rely on for a mouse, keyboard, headphones,
or other accessories. Nothing here should be disabled outright without
confirming you don't need it — this walkthrough is about tightening
discoverability and pruning stale pairings, not turning Bluetooth off.

## Step 1: Disable Bluetooth discoverability if flagged

If the scan reports this Mac as discoverable, nearby devices can see and
attempt to pair with it without you initiating the connection.

1. Open System Settings > Bluetooth.
2. Confirm you don't currently need this Mac to be discoverable (e.g. you're
   not in the middle of pairing a new device).
3. Discoverability on macOS is normally automatic only while the Bluetooth
   pane is open; if the scan still reports it as persistently on, close the
   Bluetooth settings pane after use rather than leaving it open, and verify
   via: `defaults read /Library/Preferences/com.apple.Bluetooth
   DiscoverableState`.
4. Re-run the scan to confirm the finding clears once the pane is closed.

## Step 2: Review paired devices

This is an inventory finding — it lists every device currently paired with
this Mac so you can confirm you recognize all of them.

1. Open System Settings > Bluetooth and review the list of paired devices
   against the list reported by the scan.
2. For any device you don't recognize or no longer use, click the "i" info
   button next to it and choose "Forget This Device" (or the (X)/minus
   control, depending on macOS version).
3. Keep devices you actively use (mouse, keyboard, headphones, etc.) — this
   finding is informational, not a signal that something is wrong.
