---
title: "Review Windows services"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_services_audit.suspicious_path
  - security.win_services_audit.excessive_autostart
  - security.win_services_audit.stopped_autostart
  - security.win_services_audit.bloatware_detected
  - security.win_services_audit.non_microsoft_autostart
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers what `win_services_audit` can flag: an auto-start
service running from a suspicious path, an excessive number of auto-start
services, auto-start services that are stopped, known manufacturer
bloatware, and non-Microsoft auto-start services generally. **Some services
are required for Windows or hardware to function** — always verify a
service's purpose before disabling it, since disabling the wrong one can
break networking, audio, printing, or Windows Update. Use `services.msc`
to check a service's dependencies (right-click → Properties → Dependencies
tab) before changing its startup type.

## Step 1: Service running from a suspicious path (WARNING)

An auto-start service points to an executable in a temp, AppData, Downloads,
or user profile directory — locations malware commonly uses because they're
writable without admin rights, unlike `C:\Windows\System32` or
`C:\Program Files`.

1. Note the service name and path from the finding.
2. Check the file's properties (right-click → Properties → Digital
   Signatures tab) for a recognizable, valid publisher signature.
3. If unsigned or from an unrecognized publisher, do not disable it as your
   first move — instead preserve evidence (note the path, hash the file if
   you can) and cross-check `audit_windows_autoruns.md` and
   `respond_to_windows_malware_indicators.md`, since a suspicious-path
   service is often paired with other persistence mechanisms.
4. If you can attribute it to software you deliberately installed (some
   legitimate installers do run helper services from AppData), no action
   is needed.
5. If confirmed unwanted, stop it first (`services.msc` → right-click →
   Stop) and verify nothing breaks before setting Startup type to
   Disabled — don't delete the underlying file until you've confirmed the
   service disable didn't cause other issues.

## Step 2: Excessive auto-start services (WARNING)

More than 40 services set to auto-start slows boot time and makes it harder
to notice one that shouldn't be there.

1. Review the listed services from the finding.
2. Group them by publisher/purpose using `services.msc`'s Description
   column, or `Get-Service | Select Name, DisplayName, StartType`.
3. For services tied to hardware or software you no longer use, change
   Startup type to Manual (not Disabled) as a first step — Manual still
   lets Windows start it if something else genuinely needs it, while
   avoiding an unconditional start at boot. Confirm nothing broke over a
   few reboots before considering Disabled for ones you're confident about.
4. Leave anything you're unsure about alone rather than guessing — a
   trimmed-down but broken system is a worse outcome than a slightly slower
   boot.
5. Re-run the scan to confirm the count has dropped.

## Step 3: Stopped services set to auto-start (WARNING)

A service configured to start automatically but currently stopped may
indicate a crash, missing dependency, or corrupted install — not
necessarily malicious, but worth investigating since silently-broken
services can point to a bigger problem.

1. Note the service name from the finding.
2. Check the System Event Log for errors related to that service: Event
   Viewer → Windows Logs → System, filter by Source matching the service
   name or "Service Control Manager".
3. Try starting it manually (`services.msc` → right-click → Start) and see
   whether it stays running or fails immediately — a failure with an error
   code narrows down the cause (missing file, permission issue, dependency
   not running).
4. If it's tied to hardware you no longer have or software you've
   uninstalled, it's safe to leave stopped, or change Startup type to
   Manual/Disabled once you've confirmed it's not needed.
5. If it's a core Windows service failing to start, investigate further
   (System File Checker: `sfc /scannow`) rather than just disabling it.

## Step 4: Known bloatware service detected (INFO)

The service matches a known manufacturer or third-party bloatware pattern
(HP/Dell/Lenovo utility services, some AV vendor helper services) — low
security risk on its own, but consumes resources without adding
functionality most users need.

1. Confirm you recognize the vendor and don't rely on the specific feature
   it provides (e.g. some laptop vendor services do handle real hardware
   functions like fan control or battery management — check before
   disabling).
2. If unneeded, disable via `services.msc`: find the service, Properties,
   set Startup type to Disabled, then Stop it.
3. This doesn't uninstall the parent software — if you want it fully gone,
   uninstall the manufacturer utility from Settings → Apps instead.

## Step 5: Non-Microsoft auto-start service (INFO)

A general inventory of third-party services set to auto-start, reported
when no bloatware match was found. This is informational — most machines
legitimately run several non-Microsoft services (GPU drivers, printer
software, backup clients).

1. Skim the list from the finding for anything you don't recognize at all.
2. For unrecognized entries, look up the service name/path before assuming
   anything is wrong — many are legitimate driver or utility services with
   unfamiliar internal names.
3. No action is required for services you can attribute to software you
   use; treat this as a periodic checklist rather than something to clear
   to zero.
