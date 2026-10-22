---
title: "Check Windows Remote Desktop (RDP)"
estimated_time: "5 minutes"
platforms: [windows]
remediates:
  - security.win_remote_access_audit.rdp_enabled
  - security.win_remote_access_audit.no_tools_found
steps_for:
  security.win_remote_access_audit.rdp_enabled: [1]
automatable_steps: []
human_only_steps: [1]
monitoring_risk: true
---

This walkthrough covers `win_remote_access_audit`, which checks whether
Windows' built-in Remote Desktop (RDP) is turned on. Third-party
remote-access tools (TeamViewer, AnyDesk, VNC, LogMeIn, Chrome Remote
Desktop and others) are checked by `remote_access_tools`; see
`review_remote_access_tools.md`.

## Step 1: Check if you use Remote Desktop

RDP was found turned on during this scan. This overlaps with the dedicated
`win_rdp_check` module (see `disable_unwanted_remote_access.md` for
NLA-specific guidance). Treat that walkthrough as the deeper reference for
hardening RDP if you need to keep it on, and use this step only to decide
whether to turn it off.

1. Confirm you actively need RDP (for example, for remote work access to
   this machine).
2. If not needed, turn it off: Settings → System → Remote Desktop → Off.
3. If you do need RDP, follow `disable_unwanted_remote_access.md`'s Step 3
   to confirm Network Level Authentication is on rather than leaving RDP
   exposed without it.

## No issues found

If the scan reports only the `no_tools_found` INFO finding ("RDP is off"),
Remote Desktop is turned off and no action is needed.
