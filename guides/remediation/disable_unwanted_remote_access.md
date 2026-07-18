---
title: "Disable unwanted remote access (SSH, Screen Sharing, ARD, RDP)"
estimated_time: "15 minutes"
platforms: [macos, windows]
remediates:
  - security.remote_login_check.ssh_enabled
  - security.remote_login_check.screen_sharing_enabled
  - security.remote_login_check.remote_management_enabled
  - security.remote_login_check.remote_apple_events_enabled
  - security.remote_login_check.all_disabled
  - security.win_rdp_check.rdp_enabled_no_nla
  - security.win_rdp_check.rdp_enabled_with_nla
  - security.win_rdp_check.rdp_disabled
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Every remote-access service covered here — SSH (Remote Login), Screen
Sharing, Remote Management (ARD), and Remote Apple Events on macOS; RDP on
Windows — is a legitimate feature some people rely on daily. Disabling one
you actually use will lock you out of remote access to this machine. Before
touching anything: **confirm you (or someone else) isn't currently depending
on the flagged service** — check whether you use it to access this machine
from elsewhere, whether a family member/IT admin manages it remotely, or
whether a screen-sharing/remote-support session is scheduled. If in doubt,
leave it enabled and just note it for later review rather than disabling it.

## Step 1: macOS — Remote Login (SSH)

If flagged, SSH is currently enabled, allowing remote command-line access.

1. Confirm current state: `sudo systemsetup -getremotelogin`.
2. If you don't use SSH to reach this Mac remotely, disable it:
   - GUI: System Settings → General → Sharing → toggle off "Remote Login".
   - CLI: `sudo systemsetup -setremotelogin off`.
3. If you *do* use SSH, leave it enabled but review
   `harden_ssh_keys.md` to make sure the configuration (key permissions,
   `PermitRootLogin`, `PasswordAuthentication`) is tightened rather than
   disabling the service outright.

## Step 2: macOS — Screen Sharing, Remote Management, Remote Apple Events

These three are independent toggles; handle each on its own merits.

1. Open System Settings → General → Sharing and look at "Screen Sharing"
   and "Remote Management" — for each one flagged, confirm whether you (or
   an MDM profile, if this is a managed device) actually use it.
2. If unused, uncheck it in the Sharing pane. Remote Management specifically
   is often turned on by MDM enrollment (e.g. for a managed work Mac) — if
   this device is enrolled in an MDM, check with your IT admin before
   disabling it, since it may be centrally required.
3. For Remote Apple Events, disable via CLI if unused:
   `sudo systemsetup -setremoteappleevents off`. This is a less common
   feature (used by AppleScript automation targeting this Mac remotely);
   most home users don't need it.
4. Re-run the scan (`remote_login_check`) to confirm the services you
   disabled no longer appear as findings, and that any services you
   intentionally kept still show up (as an informational reminder, not a
   secure/insecure judgment).

## Step 3: Windows — RDP without Network Level Authentication (critical)

If RDP is enabled but NLA is off, this is the highest-priority item here:
RDP without NLA is directly exploitable by brute-force/credential-stuffing
attacks against the login screen before any authentication happens.

1. Confirm current state: `reg query
   "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp"
   /v UserAuthentication`.
2. If you need RDP, enable NLA rather than leaving it exposed:
   `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal
   Server\WinStations\RDP-Tcp" /v UserAuthentication /t REG_DWORD /d 1 /f`
   — run this from an elevated (Administrator) prompt, then sign out and
   back in to confirm you can still connect with NLA required.
3. If you don't need RDP at all, disable it entirely instead (see Step 4) —
   that's a stronger fix than just adding NLA.

## Step 4: Windows — RDP enabled (with NLA) but not needed

RDP enabled with NLA is not urgent, but it's still attack surface most home
PCs don't need.

1. Confirm you don't rely on remote-desktop access to this machine (e.g.
   from work, or to help a family member remotely).
2. If unneeded, disable RDP entirely from an elevated prompt:
   `reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v
   fDenyTSConnections /t REG_DWORD /d 1 /f`.
3. Alternatively use the GUI: Settings → System → Remote Desktop → toggle
   off.
4. Re-run the scan (`win_rdp_check`) to confirm it now reports RDP as
   disabled (informational, secure state).

If the scan already reports RDP or all macOS remote-access services as
disabled, no action is needed for those — that's the secure baseline this
walkthrough aims for.
