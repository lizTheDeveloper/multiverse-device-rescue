---
title: "Review Windows network shares"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_network_shares_audit.smb1_enabled
  - security.win_network_shares_audit.enumeration_failed
  - security.win_network_shares_audit.everyone_write_access
  - security.win_network_shares_audit.everyone_read_access
  - security.win_network_shares_audit.sensitive_directory
  - security.win_network_shares_audit.shares_enumerated
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Network shares let other devices on your network read/write files on this
machine — useful for legitimate file sharing between your own devices, but
each share is also a potential path for another compromised or unauthorized
device on the network to reach your files. **Confirm you (or another device
you own) actually use a share before removing or restricting it** — check
whether another computer, a media player/smart TV, a NAS backup job, or a
family member's device connects to it before changing permissions.

## Step 1: SMBv1 protocol enabled (CRITICAL)

SMBv1 is a deprecated, decades-old protocol version with severe known
vulnerabilities — most notably EternalBlue/WannaCry (CVE-2017-0144), which
let attackers achieve remote code execution with no authentication over
SMBv1. There is essentially no legitimate reason to keep it enabled on a
modern Windows machine unless you have very old hardware (e.g. an
early-2000s NAS or printer) that only speaks SMBv1.

1. Confirm current state: `Get-SmbServerConfiguration | Select
   EnableSMB1Protocol` (PowerShell).
2. Check whether anything on your network actually requires SMBv1 — very
   old NAS devices, some legacy printers/scanners, or old Linux Samba
   installs are the main cases. If you're unsure, disabling SMBv1 first and
   seeing what breaks is the safer default, since SMBv1's risk profile
   outweighs most home use cases.
3. Disable it from an elevated PowerShell prompt: `Disable-
   WindowsOptionalFeature -Online -FeatureName SMB1Protocol`. This
   requires a reboot to take effect.
4. If a specific old device stops connecting afterward, that device is the
   thing that needs to be replaced/updated — re-enabling SMBv1 to
   accommodate it reintroduces a severe, actively-exploited vulnerability
   class.
5. Re-run the scan after rebooting to confirm SMBv1 now reports disabled.

## Step 2: Unable to enumerate network shares (INFO)

The scan couldn't retrieve the share list — usually a permissions issue
running `net share`/`Get-SmbShare`, not itself a security problem.

1. Re-run the scan from an elevated (Administrator) context.
2. If it still fails, verify the Server service is running (`Get-Service
   LanmanServer`) — required for file sharing to function at all; if it's
   stopped and you don't use file sharing, that's actually fine (no shares
   exist to audit).

## Step 3: Share accessible to Everyone with write access (WARNING)

A share grants the built-in "Everyone" group Change or Full Control
permissions — any device that can reach this machine on the network,
authenticated or not (depending on network sharing settings), can read
*and modify* files in that share. This is the highest-risk share
misconfiguration.

1. Note the share name and path from the finding.
2. Confirm current state: `Get-SmbShareAccess -Name "<share_name>"`.
3. Decide whether Everyone-write access is actually needed — it usually
   isn't; most home file-sharing use cases work fine with access limited to
   specific user accounts.
4. Restrict via `Computer Management` (`compmgmt.msc`) → System Tools →
   Shared Folders → Shares → right-click the share → Properties → Share
   Permissions: remove Everyone, add the specific user account(s) that need
   access with the minimum permission level (Read vs Change) they actually
   need.
5. Re-run the scan to confirm.

## Step 4: Share accessible to Everyone with read access (INFO)

Lower risk than write access, but still exposes the share's contents to
any device that can reach it, which may include devices you don't fully
trust on a shared network (guest Wi-Fi, roommates, smart-home devices on
the same subnet).

1. Note the share name and path from the finding.
2. If the content is genuinely meant to be broadly readable (e.g. a shared
   media folder for a smart TV), no action is needed.
3. If not, restrict via Computer Management as in Step 3, but grant Read
   access to specific accounts instead of Everyone.

## Step 5: Share points to a sensitive directory (WARNING)

A non-default share exposes a directory like Documents, Desktop, Downloads,
or a user's profile folder — sharing these can expose personal files,
saved passwords/browser data, or other sensitive content well beyond what
most file-sharing use cases need.

1. Note the share name and path from the finding.
2. Confirm whether you set this up intentionally (e.g. syncing Documents
   to another device you own) or whether you don't recognize it.
3. If unintentional or unrecognized, remove the share: `net share
   "<share_name>" /delete` (only removes the share, not the underlying
   files/directory).
4. If you do need to share something from that location, create a
   dedicated subfolder with only the specific files meant to be shared,
   rather than sharing the whole sensitive directory, and restrict
   permissions to specific accounts as in Step 3.
5. Re-run the scan to confirm.

## Step 6: Network shares enumerated (INFO)

Summarizes total share count and non-default share count — use it as a
baseline while working through Steps 3-5 and to confirm changes took
effect on re-scan.
