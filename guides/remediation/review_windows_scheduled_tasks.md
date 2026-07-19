---
title: "Review Windows scheduled tasks (basic scan)"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_scheduled_tasks.non_microsoft_tasks
  - security.win_scheduled_tasks.suspicious_path
  - security.win_scheduled_tasks.encoded_command
automatable_steps: []
human_only_steps: [1, 2, 3]
---

`win_scheduled_tasks` is a lighter-weight scan than
`win_scheduled_tasks_security` (see `secure_windows_scheduled_tasks.md` for
that module's deeper checks — encoded PowerShell, SYSTEM-privileged temp
execution, frequency-based beaconing detection, etc.). This walkthrough
covers what `win_scheduled_tasks` itself flags: the general non-Microsoft
task inventory, suspicious execution paths, and encoded commands. Task
Scheduler is a common persistence mechanism for malware, but it's also used
constantly by legitimate software (backup tools, update checkers, sync
clients) — **inspect each task individually before disabling or deleting**
rather than clearing everything non-Microsoft.

## Step 1: Non-Microsoft scheduled tasks found (INFO)

A general inventory of tasks not under the `\Microsoft\` path — expected on
most machines, since installed software routinely adds its own scheduled
tasks (update checkers, cloud sync, hardware utilities).

1. Review the task names listed in the finding.
2. For each one you don't immediately recognize, check it in Task
   Scheduler (`taskschd.msc`): look at the Actions tab (what it runs) and
   Triggers tab (when it runs).
3. Attribute tasks to installed software where you can — most map cleanly
   to something in your Programs list.
4. This finding on its own doesn't require action; use it as your
   checklist while checking Steps 2-3 for any tasks that get flagged more
   specifically.

## Step 2: Task executes from a suspicious location (WARNING)

A task's action points to an executable in a temp, AppData, Downloads, or
user-profile directory — a common pattern for malware persistence, since
these directories don't require admin rights to write to.

1. Note the task name from the finding.
2. Open Task Scheduler, find the task, and check its Actions tab for the
   exact program path and arguments.
3. Check the target file's Digital Signatures (Properties → Digital
   Signatures tab) for a recognizable, valid publisher.
4. If you can attribute it to software you deliberately installed (some
   legitimate installers do stage helper scripts in AppData), no action is
   needed.
5. If unsigned or unattributable, don't delete immediately — first export
   the task definition for evidence (`schtasks /query /tn "<task_name>"
   /xml > task_backup.xml`), then disable it (`schtasks /change /tn
   "<task_name>" /disable`) and observe whether anything breaks before
   deleting.
6. Cross-check `audit_windows_autoruns.md` and
   `respond_to_windows_malware_indicators.md` — suspicious-path scheduled
   tasks are often paired with other persistence mechanisms.

## Step 3: Encoded/obfuscated command in a task (WARNING)

A task runs a PowerShell command with `-enc`/`-encodedcommand` or other
Base64/obfuscation patterns — a common technique to hide the actual command
being executed, used both by malware and (less commonly) some legitimate
automation tools.

1. Note the task name from the finding.
2. Decode the command before acting: if it's Base64 UTF-16LE (the standard
   PowerShell `-EncodedCommand` format), decode with
   `[System.Text.Encoding]::Unicode.GetString(
   [System.Convert]::FromBase64String("<encoded-portion>"))` — read the
   decoded script, don't execute it.
3. If the decoded script downloads or executes further code and you can't
   attribute it to software you trust, treat this as a likely compromise
   indicator: disconnect from the network before continuing, and follow
   the evidence-preservation + disable-then-delete procedure from Step 2.
4. If you can attribute the encoding to legitimate automation (rare but
   not unheard of, e.g. some deployment tools encode commands to avoid
   quoting issues), no action is needed.
5. For a more thorough encoded-PowerShell-in-scheduled-tasks review
   (including SYSTEM-privilege context and beaconing-frequency detection),
   run the `win_scheduled_tasks_security` scan and follow
   `secure_windows_scheduled_tasks.md`.
