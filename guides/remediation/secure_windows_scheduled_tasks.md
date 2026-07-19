---
title: "Secure Windows scheduled tasks"
estimated_time: "30 minutes"
platforms: [windows]
remediates:
  - security.win_scheduled_tasks_security.enumeration_failed
  - security.win_scheduled_tasks_security.encoded_powershell
  - security.win_scheduled_tasks_security.temp_path_system
  - security.win_scheduled_tasks_security.non_microsoft_system
  - security.win_scheduled_tasks_security.frequent_schedule
  - security.win_scheduled_tasks_security.recent_boot_logon
  - security.win_scheduled_tasks_security.hidden_attributes
  - security.win_scheduled_tasks_security.inventory
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6, 7]
---

This walkthrough covers everything the `win_scheduled_tasks_security`
module can flag: encoded PowerShell commands in a task, SYSTEM-privileged
tasks running from a temp directory, other non-Microsoft SYSTEM tasks,
suspiciously frequent (1-5 minute) schedules that look like malware
beaconing, recently-created boot/logon-triggered tasks, hidden task
attributes, and a full inventory. Task Scheduler is one of the most common
Windows persistence mechanisms — go through each flagged task individually
rather than mass-deleting, since legitimate software (backup tools, cloud
sync clients, license checkers) also uses scheduled tasks.

## Step 1: Unable to enumerate scheduled tasks

The scan couldn't retrieve the task list, most likely because it wasn't run
with sufficient privileges.

1. Re-run the scan from an elevated (Administrator) context — `schtasks
   /query` needs elevation to see the full task list including
   SYSTEM-owned tasks.
2. If it still fails when elevated, verify the Task Scheduler service is
   running: `Get-Service Schedule` — it should show `Running`. If stopped,
   this itself is worth investigating (some malware disables Task
   Scheduler enumeration to hide its own tasks), but more commonly this is
   a benign service state issue; start it with `Start-Service Schedule` and
   re-scan.

## Step 2: Encoded PowerShell command in a scheduled task (critical)

A task runs a PowerShell command using `-EncodedCommand`/`-enc`/`-e` with
Base64-encoded content — one of the most common malware persistence
patterns, since a scheduled task surviving reboot combined with an
obfuscated payload is a durable, hard-to-casually-inspect foothold.

1. Note the task name, path, and command from the finding.
2. Decode the command before acting: the encoded portion is Base64
   UTF-16LE — `[System.Text.Encoding]::Unicode.GetString(
   [System.Convert]::FromBase64String("<encoded-portion>"))`. Read the
   decoded script; don't execute it.
3. If the decoded script downloads/executes further code, or you can't
   attribute it to legitimate software you use, treat this as active
   compromise: disconnect the machine from the network before continuing.
4. Preserve evidence: `schtasks /query /tn "<task_name>" /xml` to export
   the full task definition to a file, and note the decoded command — keep
   both before removing anything.
5. Disable first, delete once confirmed: `schtasks /change /tn
   "<task_name>" /disable`, verify nothing depends on it, then `schtasks
   /delete /tn "<task_name>" /f` (elevated).
6. If the task's action pointed to a script or executable file, quarantine
   that file (move it, don't delete, to a dated folder on external
   storage) rather than deleting it outright.
7. Cross-check `respond_to_windows_malware_indicators.md`,
   `triage_windows_suspicious_processes.md`, and
   `audit_windows_autoruns.md` — encoded-PowerShell scheduled tasks are
   frequently paired with a matching Run-key entry or running process as
   redundant persistence.
8. Run an offline malware scan (Microsoft Safety Scanner or Windows
   Defender Offline) afterward.

## Step 3: Temp-directory execution as SYSTEM (critical)

A task runs a command from a temp/Downloads path *with SYSTEM privileges*
— the combination of untrusted-location + highest-privilege execution
context is a severe finding, since it means anything that can write to
that temp path effectively has a path to SYSTEM-level code execution on
every trigger.

1. Note the task name, path, and command from the finding.
2. Follow the same disconnect-network + preserve-evidence (export the task
   XML, hash the target file) procedure as Step 2 before touching anything.
3. Disable then delete the task (`schtasks /change ... /disable` then
   `schtasks /delete ... /f`), and quarantine the target executable/script.
4. Because this runs as SYSTEM, also check for related persistence at the
   SYSTEM level: services (`Get-Service` / `sc qc`), and the `HKLM` Run
   keys (not just `HKCU`) — see `respond_to_windows_malware_indicators.md`
   and `audit_windows_autoruns.md`.
5. Run an offline malware scan, and treat this finding as justification for
   a more thorough investigation (this is not a "review and move on"
   finding) — if you can't fully account for how this task was created,
   consider whether a clean reinstall is warranted given SYSTEM-level
   access may have already been used for further compromise.

## Step 4: Non-Microsoft task running as SYSTEM (warning)

A task not attributable to Microsoft runs with SYSTEM privileges. This is
unusual but not inherently malicious — some legitimate software (backup
agents, some AV/EDR tools, certain hardware vendor utilities) does
legitimately need SYSTEM for its scheduled maintenance tasks.

1. Note the task name, path, and command from the finding.
2. Open Task Scheduler (`taskschd.msc`) and locate the task for full
   detail: action, triggers, last run result, and the "Author" field if
   populated.
3. Identify the vendor/software this task belongs to — check the target
   executable's file properties (Details tab) for a publisher/company
   name, and verify that software is something you recognize as installed.
4. If attributable to known, trusted software, no action is needed.
5. If unrecognized, investigate the target file (hash check, offline
   scanner) before disabling — don't assume malicious just because it runs
   as SYSTEM, since that alone is a common and often legitimate pattern for
   background services.
6. If confirmed unwanted, disable then delete as in Step 2, preserving
   evidence first.

## Step 5: Suspiciously frequent schedule (warning)

A task is configured to run every 1-5 minutes — a pattern consistent with
malware beaconing (checking in with a C2 server) or periodic re-injection,
but also used by some legitimate sync/monitoring tools.

1. Note the task name and schedule from the finding.
2. Check what the task's action actually does (via Task Scheduler or
   `schtasks /query /tn "<task_name>" /v /fo list`) — if it's a network
   call (look for PowerShell `Invoke-WebRequest`, `curl`, or a networking
   executable in the command) with no legitimate app you recognize behind
   it, treat this as a probable beacon.
3. If you can attribute it to known monitoring/sync software (e.g. a cloud
   backup client polling for changes), no action is needed — this
   frequency is normal for some categories of legitimate software.
4. If unrecognized or confirmed to make unexplained network calls, follow
   the disconnect-network + preserve-evidence + disable/delete procedure
   from Step 2, and check outbound connections it may have made via
   `triage_suspicious_connections.md` if that scan is also available for
   this platform.

## Step 6: Recently created task with boot/logon trigger (warning)

A task created within the last 7 days triggers at system boot or user
logon — a combination that's common for newly-installed legitimate
software (which often adds a startup task during installation) but is also
the standard pattern for freshly-established persistence.

1. Note the task name, creation date, and schedule from the finding.
2. Think back: did you install any new software in the last 7 days that
   would explain this? Most legitimate installers create exactly this kind
   of task (update checkers, cloud sync clients, hardware utilities).
3. If you can attribute it to something you deliberately installed, no
   action is needed.
4. If you don't recall installing anything that would explain it, inspect
   the task's action in Task Scheduler and cross-check with Step 2-5's
   procedures depending on what you find (encoded command → Step 2, SYSTEM
   + temp path → Step 3, otherwise → Step 4's investigation approach).

## Step 7: Hidden task attributes (informational)

A task has hidden attributes set (not shown by default in the Task
Scheduler GUI) — used by some legitimate maintenance tasks (several
Windows-internal tasks are hidden by design) but also a technique malware
uses to avoid casual discovery.

1. View it explicitly: in Task Scheduler, enable View → Show Hidden Tasks,
   then locate the task by name.
2. Check whether it's paired with any other finding above (encoded
   command, temp-path SYSTEM execution, suspicious frequency) — hidden
   attributes alone are informational, but combined with another finding
   on the same task is a stronger signal.
3. If it's standalone and you can attribute it to recognized software, no
   action is needed.
4. If unrecognized, investigate its action the same way as Step 4 before
   deciding whether to disable/remove it.

## Step 8: Scheduled tasks inventory (informational)

This INFO finding summarizes the total task count and how many were
flagged as suspicious — use it as your checklist while working through
Steps 2–7, and as a baseline count for comparison on future scans.
