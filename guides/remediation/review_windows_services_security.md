---
title: "Review Windows service security hardening findings"
estimated_time: "25 minutes"
platforms: [windows]
remediates:
  - security.win_services_security_audit.unquoted_path
  - security.win_services_security_audit.user_writable_dir
  - security.win_services_security_audit.overprivileged
  - security.win_services_security_audit.stopped_auto_start
  - security.win_services_security_audit.summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

`win_services_security_audit` goes deeper than `win_services_audit` (see
`review_windows_services.md` for that module) into privilege-escalation
patterns: unquoted service paths, services running from user-writable
directories, services running with more privilege than they may need, and
stopped auto-start services. Verify a service's real purpose with
`services.msc` (Dependencies and Log On tabs) before changing anything —
some of these findings (like LocalSystem) describe patterns that are
correct and necessary for legitimate core services too.

## Step 1: Unquoted service path with spaces (CRITICAL)

A service's binary path contains spaces and isn't wrapped in quotes — a
classic Windows privilege-escalation bug. Windows tries each
space-delimited segment as a candidate executable path in order, so
`C:\Program Files\My App\service.exe` unquoted lets an attacker who can
write to `C:\Program.exe` or `C:\Program Files\My.exe` have it launched
with the service's privileges (frequently LocalSystem) instead of the
real binary.

1. Note the service name and full path from the finding.
2. Confirm current state: `sc qc "<service_name>"` and look at BINARY_PATH_NAME.
3. Check who can write to each directory in the path chain — `icacls
   "C:\"` etc. — to gauge actual exploitability on this specific machine
   (this is usually not exploitable without another vulnerability giving
   local write access to those directories, but should still be fixed).
4. Fix by quoting the path in the service's ImagePath. From an elevated
   prompt: back up the current value first (`reg export
   "HKLM\SYSTEM\CurrentControlSet\Services\<service_name>"
   backup.reg`), then correct it via `sc config "<service_name>"
   binPath= "\"C:\Program Files\My App\service.exe\""` (note the exact
   quoting) or via Registry Editor on the ImagePath value under
   `HKLM\SYSTEM\CurrentControlSet\Services\<service_name>`.
5. Restart the service (`sc stop`/`sc start`, or via `services.msc`) and
   confirm it starts normally with the corrected path.
6. Re-run the scan to confirm.

## Step 2: Service running from a user-writable directory (WARNING)

The service binary lives under AppData, Temp, Downloads, or Documents —
directories a standard (non-admin) user account can write to. If the
service runs with elevated privileges, anyone who can write to that binary
can plant a replacement that runs with the service's privilege level.

1. Note the service name and path from the finding.
2. Check who the service runs as (`sc qc "<service_name>"`, look at
   SERVICE_START_NAME) — the risk is highest if it runs as LocalSystem or
   another privileged account.
3. Identify what installed it — legitimate software occasionally does
   install a helper service under a user profile path, but system-level
   services should not live there.
4. If attributable to trusted software, no urgent action, but consider
   flagging it to the vendor or checking for an update that fixes the
   install location.
5. If unrecognized, treat this like a suspicious-path finding: don't
   assume malicious without checking (Digital Signatures tab on the file),
   but if it's unsigned/unattributable, cross-check
   `respond_to_windows_malware_indicators.md` before stopping/disabling it.
6. To remediate long-term, the fix is moving the binary to a
   system-protected location (`C:\Program Files`) and updating the
   service's ImagePath — this typically requires reinstalling the
   software rather than manually moving files.

## Step 3: Third-party service running as LocalSystem (WARNING)

A non-Microsoft service runs with LocalSystem privileges — the highest
local privilege level. This is legitimate for some software (backup
agents, security tools, hardware utilities) but is worth confirming rather
than assuming, since it's also a common target for privilege-escalation
attacks against the service itself.

1. Note the service name from the finding.
2. Check the binary's publisher (Digital Signatures tab) and confirm it
   matches software you recognize as installed and trust.
3. If recognized and trusted, no action is needed — many legitimate
   services (device drivers services, backup/sync agents) require
   LocalSystem for what they do.
4. If unrecognized, investigate before changing anything: check the file
   hash against a malware scanner, review when the service was created
   (`Get-WmiObject Win32_Service` doesn't include install date directly;
   check the binary's file creation date), and cross-check other findings
   on the same binary/path.
5. Changing a service's Log On account (Properties → Log On tab in
   `services.msc`) to a lower-privileged account is possible but can break
   the service if it genuinely needs LocalSystem access to specific
   resources — test in a way you can revert, and don't do this for a
   service you can't fully account for.

## Step 4: Auto-start service stopped (WARNING)

An Automatic or Automatic (Delayed Start) service is currently not
running — could indicate a crash, missing dependency, corrupted install, or
(less commonly) something having disabled it to hide its presence.

1. Note the service name from the finding.
2. Check the System Event Log for related errors (Event Viewer → Windows
   Logs → System, filter by the service name).
3. Try starting it manually and observe the result/error code.
4. If tied to hardware/software no longer present, safe to leave stopped
   or change to Manual/Disabled once confirmed unneeded.
5. If it's a core Windows or security-relevant service (anything related
   to Windows Defender, Update, or the Security Center) that's stopped
   unexpectedly, treat this more seriously — cross-check
   `restore_windows_defender.md` and `respond_to_windows_malware_indicators.md`,
   since disabling security services is a common step in an active
   compromise.

## Step 5: Services audit summary (INFO)

The summary finding reports total service count grouped by state and start
mode — use it as a baseline snapshot and to confirm changes from Steps 1-4
took effect on re-scan.
