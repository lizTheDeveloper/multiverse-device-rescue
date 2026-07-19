---
title: "Review and disable unneeded sharing services"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.sharing_preferences_audit.screen_sharing
  - security.sharing_preferences_audit.file_sharing
  - security.sharing_preferences_audit.remote_login
  - security.sharing_preferences_audit.remote_management
  - security.sharing_preferences_audit.printer_sharing
  - security.sharing_preferences_audit.airdrop_everyone
  - security.sharing_preferences_audit.config_secure
  - security.sharing_preferences_audit.config_summary
  - security.sharing_services.screen_sharing
  - security.sharing_services.file_sharing
  - security.sharing_services.remote_login
  - security.sharing_services.remote_management
  - security.sharing_services.printer_sharing
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

Both `sharing_preferences_audit` and `sharing_services` scan the same set of
macOS Sharing preferences (Screen Sharing, File Sharing, Remote Login,
Remote Management, Printer Sharing) plus AirDrop discoverability, and report
overlapping findings. Every one of these is a legitimate feature some people
rely on — **confirm you (or another person/admin) isn't currently using the
flagged service before disabling it.** If this is a managed device, Remote
Management in particular may be required by an MDM profile; check with your
IT admin first (see `verify_mdm_enrollment.md`).

## Step 1: Screen Sharing

1. Confirm you don't use Screen Sharing (VNC) to access this Mac remotely,
   and no one else does (e.g. a family member helping you troubleshoot).
2. If unused, open System Settings > General > Sharing and toggle "Screen
   Sharing" off.
3. If you do use it, leave it enabled but make sure the Mac isn't reachable
   from untrusted networks (e.g. it's behind a firewall/NAT, not
   port-forwarded to the internet).

## Step 2: File Sharing (SMB)

1. Confirm you don't rely on File Sharing to access files on this Mac from
   another device on your network.
2. If unused, open System Settings > General > Sharing and toggle "File
   Sharing" off.
3. If you do use it, review which folders are shared (System Settings >
   General > Sharing > File Sharing > Options) and remove any you no longer
   need to share.

## Step 3: Remote Login (SSH)

1. Confirm you don't SSH into this Mac from elsewhere.
2. If unused, open System Settings > General > Sharing and toggle "Remote
   Login" off, or run `sudo systemsetup -setremotelogin off`.
3. If you do use SSH, leave it enabled but review `harden_ssh_keys.md` to
   make sure the configuration is tightened (key permissions,
   `PermitRootLogin`, `PasswordAuthentication`).

## Step 4: Remote Management (ARD) and Printer Sharing

1. Remote Management is often turned on by MDM enrollment on managed
   devices — if this Mac is enrolled in an MDM, verify with IT before
   disabling it, since it may be centrally required and removal could
   conflict with organizational policy.
2. If this is a personal, unmanaged device and you don't use Apple Remote
   Desktop, open System Settings > General > Sharing and toggle "Remote
   Management" off.
3. For Printer Sharing, confirm no one else on your network prints through
   this Mac's shared printers; if unused, toggle "Printer Sharing" off (or
   run `cupsctl --no-share-printers`).

## Step 5: AirDrop discoverability

If `sharing_preferences_audit` flagged AirDrop as set to "Everyone", see
`secure_airdrop.md` for the full walkthrough — in short, change it to
"Contacts Only" in System Settings > General > AirDrop unless you have a
specific reason to accept files from anyone nearby.

## Step 6: Review the summary/secure-baseline findings

The `config_secure` and `config_summary` findings from
`sharing_preferences_audit` are informational — they report either "nothing
is enabled, you're at the secure baseline" or a summary list of what's
currently on. After working through Steps 1–5, re-run the scan and confirm
the summary now matches what you intend to keep enabled.
