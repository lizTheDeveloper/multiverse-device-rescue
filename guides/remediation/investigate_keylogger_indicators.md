---
title: "Investigate keylogger indicators"
estimated_time: "25 minutes"
platforms: [macos]
remediates:
  - security.keylogger_indicators.input_monitoring_access
  - security.keylogger_indicators.known_keyloggers
  - security.keylogger_indicators.suspicious_input_monitoring
  - security.keylogger_indicators.keyboard_hooks
  - security.keylogger_indicators.cgeventtap_usage
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `keylogger_indicators` module can
flag: the full inventory of apps with Input Monitoring access, apps matching
known commercial keylogger names, unrecognized apps with that same access,
raw keyboard event hooks, and processes using `CGEventTap` to capture input
programmatically. Input Monitoring is a legitimate macOS permission used by
many trusted apps (terminals, window managers, some IDEs) — the goal here is
distinguishing that from a keylogger, not treating every hit as malicious.

If a **known keylogger** was flagged, treat this as an active-compromise
scenario: assume your keystrokes (including passwords) may already have been
captured, and jump straight to Step 2.

## Step 1: Review general Input Monitoring access

This is an inventory finding — it lists every app with the permission, not
just suspicious ones.

1. Open System Settings > Privacy & Security > Input Monitoring.
2. Cross-reference the full list against the finding's app list.
3. For each entry, ask: do I recognize this app, and does it plausibly need
   to see keyboard/mouse events (terminal emulators, window managers like
   Hammerspoon/Rectangle, remote-access tools, accessibility software)?
4. Toggle off access for anything you don't recognize or no longer use —
   this doesn't uninstall the app, just revokes the permission, so it's safe
   to be liberal about turning things off and re-enabling later if something
   breaks.

## Step 2: Remove known keyloggers immediately (critical)

The scan matched an app name against a list of known commercial/malicious
keylogger products (e.g. Aobo, Spyrix, mSpy, Ardamax). These are built
specifically to exfiltrate everything you type, often including passwords
and banking details already captured.

1. **Disconnect from the network first** (turn off Wi-Fi / unplug Ethernet)
   to stop any further exfiltration while you work.
2. Do not log into anything sensitive from this machine until it's clean —
   assume credentials typed recently are already compromised.
3. Identify the app bundle from the finding and quarantine it rather than
   deleting outright: move it to a dated folder
   (`~/Desktop/quarantine-YYYYMMDD/`) so you retain it as evidence if you
   need to report this (e.g. to an employer's IT/security team, or if this
   was installed without your consent by another person with device
   access).
4. Revoke its Input Monitoring (and any other) permission in System
   Settings > Privacy & Security.
5. Check for a companion LaunchAgent/LaunchDaemon that restarts it:
   `ls ~/Library/LaunchAgents /Library/LaunchAgents /Library/LaunchDaemons`
   and look for a plist referencing the same product name; quarantine that
   too (`launchctl unload <path>` before moving it).
6. Reconnect to the network only after confirming the process no longer
   appears in Activity Monitor and doesn't relaunch after a reboot.
7. From a **separate, known-clean device**, change passwords for any
   accounts you may have typed credentials into on this machine recently,
   starting with email and financial accounts.
8. If this was installed without your knowledge or consent — including by
   someone with physical access to the device — consider this a personal
   safety and legal matter, not just a technical one; document what you
   found (screenshots of the finding, the app's install date and location)
   before removing it.

## Step 3: Investigate suspicious (unrecognized) Input Monitoring access

Distinct from Step 2 — this is for apps that aren't on the known-keylogger
list but also aren't a recognized system app or common developer tool.

1. Look up the app's bundle identifier and name; check its install location
   (`/Applications`, `~/Applications`, or somewhere unusual like `/tmp` or
   `~/Library/Application Support`).
2. Search the exact bundle ID / name online for reports of it being
   adware, spyware, or a "stalkerware" product (these are often disguised as
   parental-control or "find my phone" apps).
3. If you can't establish it's legitimate, revoke its Input Monitoring
   access in System Settings > Privacy & Security, then quarantine the app
   the same way as Step 2 rather than deleting immediately.
4. If revoking access breaks functionality you actually rely on, that's a
   signal it may be legitimate — restore access and move on, but keep a
   note of what it was for future reference.

## Step 4: Investigate keyboard event hooks

Raw `HIDKeyboard`/`KeyboardEventTap` entries in `ioreg` are lower-level and
harder to attribute to a specific app than TCC permissions.

1. Use Activity Monitor to look for any unfamiliar processes running around
   the same time as the scan.
2. Search the exact hook name/string reported by the finding online — some
   are generic system framework internals and not evidence of anything by
   themselves.
3. If you can correlate a hook to a specific unfamiliar app, follow the
   quarantine steps in Step 3.
4. If you can't attribute the hook to anything and it persists across scans
   with no obvious source, consider a deeper scan with a reputable
   anti-malware tool (e.g. Malwarebytes for Mac) before concluding it's
   benign.

## Step 5: Investigate CGEventTap usage

`CGEventTap` is a legitimate macOS API (used by hotkey managers, remapping
tools, accessibility software) but is also the exact mechanism a keylogger
would use to capture keystrokes programmatically.

1. Note the process name(s) from the finding and check whether they belong
   to software you intentionally installed for exactly this purpose (e.g.
   Karabiner-Elements, BetterTouchTool, Hammerspoon).
2. For anything unrecognized, check System Settings > Privacy & Security >
   Input Monitoring and Accessibility — a legitimate CGEventTap user will
   almost always also be listed there, giving you another point of
   correlation.
3. If the process can't be explained, quarantine it following Step 2/3's
   approach, and treat any credentials typed while it was running as
   potentially exposed.
