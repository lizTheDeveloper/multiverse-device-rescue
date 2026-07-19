---
title: "Review installed remote-access tools (TeamViewer, AnyDesk, VNC, LogMeIn, RDP)"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_remote_access_audit.teamviewer_installed
  - security.win_remote_access_audit.anydesk_installed
  - security.win_remote_access_audit.vnc_installed
  - security.win_remote_access_audit.logmein_installed
  - security.win_remote_access_audit.chrome_remote_desktop
  - security.win_remote_access_audit.rdp_enabled
  - security.win_remote_access_audit.multiple_tools
  - security.win_remote_access_audit.tools_summary
  - security.win_remote_access_audit.no_tools_found
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

This walkthrough covers `win_remote_access_audit`, which inventories
third-party remote-access software (TeamViewer, AnyDesk, VNC, LogMeIn,
Chrome Remote Desktop) and Windows' built-in RDP. Every one of these tools
is legitimate software that IT support, family members, or you yourself may
use intentionally — the module flags installation, not misuse. **Before
uninstalling anything, confirm you (or whoever manages this machine)
actually use it.** The pattern this module is specifically designed to
catch — several different remote-access tools installed together — is a
well-known hallmark of tech-support scams, where a scammer walks a victim
through installing "verification" software and layers on a second or third
tool to maintain access even if the first is removed. If you don't
recognize why a tool is installed, or if you recently received an
unsolicited call/pop-up telling you to install remote-access software,
treat this as a likely active-scam situation rather than routine cleanup.

## Step 1: Multiple remote-access tools installed (critical — likely scam)

Two or more remote-access tools were found installed simultaneously.

1. Stop here before doing anything else: if you're currently on a call with
   someone who told you to install this software, hang up. Legitimate
   support (your bank, Microsoft, your ISP) does not cold-call you asking
   you to install remote-access software.
2. Disconnect this machine from the network (unplug ethernet / turn off
   Wi-Fi) if you suspect an active session is in progress, to cut off any
   live remote connection.
3. Review each tool listed in the finding's `tools` data one at a time
   using Steps 2-7 below, confirming with anyone else who uses this machine
   whether they installed it intentionally.
4. After removing unauthorized tools, run a full antivirus scan (see
   `enable_windows_antivirus.md`) and change passwords for any accounts
   that may have been accessed during a scam session (banking, email),
   from a different, trusted device.

## Step 2: TeamViewer installed

1. Confirm: does anyone with legitimate reason to remotely support this
   machine (family IT help, a business you work with) use TeamViewer? If
   yes, no action needed.
2. If unrecognized or no longer needed, uninstall via Settings → Apps →
   Apps and features → search "TeamViewer" → Uninstall, then restart.

## Step 3: AnyDesk installed

1. Same check as Step 2 — confirm intentional use before removing.
2. If unrecognized, uninstall via Settings → Apps → Apps and features →
   search "AnyDesk" → Uninstall, then restart.

## Step 4: VNC server installed

A VNC server process was detected (WinVNC, UltraVNC, TightVNC, or similar).
Unlike the commercial tools above, a VNC server usually requires more
deliberate setup, making it less likely to be a scam artifact and more
likely something you or a previous owner configured — but still worth
confirming.

1. Confirm you (or a prior legitimate user of this machine) set up VNC
   access intentionally.
2. If unrecognized, uninstall the VNC software via Settings → Apps → Apps
   and features (search for the specific product name reported, e.g.
   "UltraVNC" or "TightVNC"), then restart.
3. If you do use VNC intentionally, confirm it's password-protected and, if
   possible, only reachable over a VPN rather than directly exposed to the
   internet — an unauthenticated VNC server is a serious exposure.

## Step 5: LogMeIn installed

1. Confirm intentional use (common in small-business IT support contexts).
2. If unrecognized, uninstall via Settings → Apps → Apps and features →
   search "LogMeIn" → Uninstall, then restart.

## Step 6: Chrome Remote Desktop running

1. Confirm you set this up yourself (a common legitimate use is accessing
   your own home PC from elsewhere) or that whoever manages your Google
   account access needs it.
2. If unrecognized, remove it: open Chrome, go to
   `chrome://apps`, find "Chrome Remote Desktop", right-click and remove
   it, or uninstall the Chrome extension from the Extensions page.

## Step 7: RDP enabled

RDP was found enabled during this scan. This module's RDP check overlaps
with the dedicated `win_rdp_check` module (see
`disable_unwanted_remote_access.md` for NLA-specific guidance) — treat that
walkthrough as the deeper reference for hardening RDP if you need to keep
it enabled, and use this step only to decide whether to disable it.

1. Confirm you actively need RDP (e.g. for remote work access to this
   machine).
2. If not needed, disable it: Settings → System → Remote Desktop → toggle
   off, or right-click "This PC" → Properties → Remote settings → uncheck
   "Allow remote assistance connections to this computer".
3. If you do need RDP, follow `disable_unwanted_remote_access.md`'s Step 3
   to confirm Network Level Authentication is enabled rather than leaving
   RDP exposed without it.

## No issues found

If the scan reports only the `no_tools_found` INFO finding, none of the
common remote-access tools this module checks for were detected — no
action is needed. If it reports `tools_summary` alongside recognized,
intentionally-installed tools, no action is needed either; that finding is
just an inventory for your awareness.
