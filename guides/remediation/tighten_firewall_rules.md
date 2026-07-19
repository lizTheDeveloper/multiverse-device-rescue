---
title: "Tighten Application Layer Firewall rules"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.firewall_rules_audit.alf_disabled
  - security.firewall_rules_audit.stealth_disabled
  - security.firewall_rules_audit.too_many_apps
  - security.firewall_rules_audit.allow_signed_enabled
  - security.firewall_rules_audit.firewall_summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `firewall_rules_audit` module can
flag: the Application Layer Firewall (ALF) being off, stealth mode being
off, an excessive number of apps allowed through the firewall, the overly
permissive "automatically allow signed software" setting, and the general
configuration summary. This module inspects the same underlying firewall as
`firewall_audit`, but goes further into per-app exceptions and default
policy. As with any firewall change, confirm you're not mid-way through
something that relies on inbound connections (file sharing, a local server
reachable from your phone, screen sharing) before tightening settings.

## Step 1: Enable the firewall if disabled (CRITICAL)

With ALF off, nothing on this Mac is filtering unsolicited inbound
connections.

1. Check current state yourself: `defaults read
   /Library/Preferences/com.apple.alf globalstate`.
2. Enable via System Settings → Network → Firewall → toggle on, or via CLI
   (requires sudo): `sudo /usr/libexec/ApplicationFirewall/socketfilterfw
   --setglobalstate on`.
3. If you run services that need inbound connections, macOS will prompt to
   allow specific apps the next time they try to accept a connection —
   allow those individually rather than disabling the firewall again.
4. Re-run the scan to confirm ALF now reports as enabled.

## Step 2: Enable stealth mode (WARNING)

With stealth mode off, this Mac responds to network probes like `ping`,
making it easier for something scanning the network to notice it exists.

1. Check current state: `defaults read /Library/Preferences/com.apple.alf
   stealthenabled`.
2. If you don't rely on other devices discovering this Mac via ICMP/ping,
   enable it: System Settings → Network → Firewall → Options → Enable
   Stealth Mode, or `sudo
   /usr/libexec/ApplicationFirewall/socketfilterfw --setstealthmode on`.
3. Re-run the scan to confirm.

## Step 3: Review an excessive number of firewall exceptions (WARNING)

More than 30 applications allowed through the firewall widens the attack
surface — each exception is a potential accepted inbound connection path,
and a long, unreviewed list makes it easy to miss something that shouldn't
be there.

1. Review the listed apps from the finding: System Settings → Network →
   Firewall → Options.
2. For each app you don't recognize or no longer use, remove it from the
   list with the minus (–) button — this doesn't uninstall the app, it
   only stops the firewall from automatically allowing its inbound
   connections; if it needs one later, macOS will prompt again.
3. Keep exceptions for apps you actively use that need inbound access
   (file sharing, screen sharing, a local dev/game server reached from
   other devices).
4. Re-run the scan to confirm the count has dropped, and periodically
   re-review as you install new software.

## Step 4: Disable "automatically allow signed software" (WARNING)

This setting lets any validly code-signed application accept inbound
connections without asking you first. It's convenient, but it means a
compromised or unexpectedly-behaving-but-signed app can open a listening
port without you ever seeing a prompt — a valid signature only proves who
built it, not that it's behaving as expected.

1. Check current state: `/usr/libexec/ApplicationFirewall/socketfilterfw
   --getallowsigned`.
2. Open System Settings → Network → Firewall → Options and uncheck
   "Automatically allow built-in software to receive incoming
   connections" / "Automatically allow downloaded signed software to
   receive incoming connections" (exact wording varies by macOS version).
3. Expect to see more firewall prompts going forward as apps ask for
   inbound access — allow the ones you recognize and expect, and treat an
   unexpected prompt from an app you don't associate with network services
   as worth investigating before allowing.
4. Re-run the scan to confirm.

## Step 5: Review the configuration summary (INFO)

The summary finding is informational — a snapshot of ALF status, stealth
mode, block-all-incoming, allow-signed-software, and the current app
exception count. Use it to confirm the changes above took effect and as a
baseline for future scans; no separate action is needed beyond what Steps
1-4 already cover.
