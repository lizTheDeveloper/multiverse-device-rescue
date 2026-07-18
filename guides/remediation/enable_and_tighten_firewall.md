---
title: "Enable and tighten the macOS Application Firewall"
estimated_time: "5 minutes"
platforms: [macos]
remediates:
  - security.firewall_audit.global_state
  - security.firewall_audit.stealth_mode
automatable_steps: []
human_only_steps: [1, 2]
---

The macOS Application Firewall blocks unsolicited incoming connections.
Turning it on (or turning on stealth mode) is very low-risk for a typical
home user — it does not affect outgoing connections or normal browsing —
but it can occasionally interfere with local network services you
intentionally run (file sharing, a local dev server reachable from other
devices, screen sharing, printer discovery, etc.). Confirm you're not
mid-way through something that depends on inbound connections before
enabling stealth mode, since a probe-invisible Mac can be harder to
discover from other devices on your LAN for legitimate reasons too (e.g.
some file-sharing discovery flows).

## Step 1: Enable the firewall (critical)

If the scan reports the firewall as disabled, this is the higher-priority
fix — with it off, nothing is filtering inbound connection attempts.

1. Check current state yourself first:
   `/usr/libexec/ApplicationFirewall/socketfilterfw --getglobalstate`.
2. Enable it via GUI: System Settings → Network → Firewall → toggle on.
3. Or via CLI (requires sudo):
   `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setglobalstate on`.
4. If you run any service that needs to accept inbound connections from
   other devices (e.g. file sharing, a local web server you access from
   your phone), macOS will prompt to allow that specific app through the
   firewall the next time it tries to accept a connection — allow those
   individually rather than disabling the firewall again.
5. Re-run the scan to confirm the firewall now reports as enabled.

## Step 2: Enable stealth mode

Stealth mode makes the Mac not respond to unsolicited probes (like `ping`)
from the network, making it harder for an attacker doing network
reconnaissance to even notice the machine exists.

1. Check current state: `/usr/libexec/ApplicationFirewall/socketfilterfw
   --getstealthmode`.
2. If you don't rely on other devices on your LAN discovering this Mac via
   ICMP/ping-based tools, enable it:
   `sudo /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on`.
3. Re-run the scan to confirm stealth mode now reports as enabled.
4. If you notice a local tool that specifically relies on ping/ICMP
   reachability to find this Mac stops working, that's an expected
   trade-off of stealth mode — you can revert with `--setstealthmode off`
   if it's more disruptive than the security benefit is worth for your
   setup.
