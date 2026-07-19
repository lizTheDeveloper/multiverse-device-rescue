---
title: "Verify and re-enable SIP and Gatekeeper"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.sip_gatekeeper.sip_status
  - security.sip_gatekeeper.gatekeeper_status
automatable_steps: []
human_only_steps: [1, 2]
---

This walkthrough covers `sip_gatekeeper`, which checks System Integrity
Protection (`csrutil status`) and Gatekeeper (`spctl --status`).

**Important: both SIP and Gatekeeper are core macOS security protections.**
Disabling either one reduces your system's defenses — SIP stops even root
from modifying protected system files and code-injecting into system
processes, and Gatekeeper verifies code signatures before running
downloaded apps. If you (or a previous owner of this machine) disabled
either intentionally for development work, weigh that need against the
security cost before re-enabling. If you did *not* knowingly disable them,
treat a disabled state as a red flag: it's a common step in malware
persistence chains, since a lot of malicious payloads and installers
disable these to keep working undetected.

## Step 1: Confirm intent and re-enable SIP if disabled

`sip_status` (WARNING) fires when `csrutil status` doesn't report
"enabled".

1. Before touching anything, think about whether you (or a trusted admin)
   disabled SIP deliberately — for example, for kernel-level debugging,
   hackintosh compatibility, or a development toolchain that needs to
   patch system frameworks. If yes and you still need that capability,
   you may choose to leave SIP disabled — that's a legitimate but
   security-reducing tradeoff, and it's your call to make consciously,
   not by default.
2. If you don't recognize the reason it's disabled, treat it as
   suspicious and re-enable it:
   - Reboot into Recovery Mode (Intel: hold Cmd+R at startup; Apple
     Silicon: hold the power button until "Loading startup options"
     appears, then choose Options).
   - Open **Terminal** from the Utilities menu.
   - Run: `csrutil enable`
   - Reboot normally.
3. Confirm: `csrutil status` should report
   "System Integrity Protection status: enabled."

## Step 2: Confirm intent and re-enable Gatekeeper if disabled

`gatekeeper_status` (WARNING) fires when `spctl --status` doesn't report
"assessments enabled".

1. Same reasoning as Step 1: if you deliberately disabled Gatekeeper to
   run a specific unsigned/internal tool, prefer allow-listing that one
   app over leaving Gatekeeper off globally — `sudo spctl --add --label
   'Approved App' /path/to/app` lets you keep protection on for
   everything else.
2. To re-enable Gatekeeper globally: `sudo spctl --master-enable`
3. Confirm: `spctl --status` should report "assessments enabled."
