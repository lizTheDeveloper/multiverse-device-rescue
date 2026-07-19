---
title: "Review and clean suspicious cron jobs and scheduled tasks"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.cron_jobs_audit.cron_entries_found
  - security.cron_jobs_audit.rce_in_cron
  - security.cron_jobs_audit.suspicious_path
  - security.cron_jobs_audit.every_minute
  - security.cron_jobs_audit.obfuscated_command
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

`cron_jobs_audit` scans your user crontab (`crontab -l`), system crontabs
(`/etc/crontab`, `/etc/cron.d/*`), periodic scripts
(`/etc/periodic/{daily,weekly,monthly}`), and pending `at` jobs (`atq`) for
persistence and beaconing patterns. All steps are human-only: cron entries
can be legitimate maintenance jobs you rely on, so nothing is edited
automatically — you inspect and remove entries yourself.

## Step 1: Remove remote-code-execution and suspicious-path entries first

These are the highest-confidence findings: a cron entry piping `curl`/`wget`
output into a shell (`rce_in_cron`), or a cron entry executing from `/tmp`,
`/var/tmp`, or a hidden directory (`suspicious_path`). Both are CRITICAL —
this is a very common persistence technique for droppers that re-fetch a
payload on a schedule.

For each flagged entry:

1. Inspect before removing: run `crontab -l` (user) or
   `cat /etc/crontab` and `ls /etc/cron.d/` (system) to find the exact line
   reported in the finding, and read it in full — don't trust the
   truncated summary.
2. If it's a user crontab entry: `crontab -e`, delete the offending line,
   save.
3. If it's a system crontab entry: back it up first
   (`sudo cp /etc/cron.d/<file> ~/cron-quarantine/<file>.bak`), then remove
   the line or, if the whole file is malicious, move the file itself:
   `sudo mkdir -p /var/root/cron-quarantine && sudo mv /etc/cron.d/<file>
   /var/root/cron-quarantine/`.
4. If the entry references a script on disk (not just an inline command),
   inspect it before deleting (`file <path>`, `cat <path>`) — quarantine
   it (move, don't `rm -rf`) so you can hand it to malware analysis if
   needed.
5. Confirm removal: `crontab -l` / `cat /etc/crontab` should no longer show
   the entry.

## Step 2: Review "every minute" schedules

A `* * * * *` schedule (`every_minute`, WARNING) runs every single minute —
unusual for legitimate maintenance and a common pattern for C2 beaconing or
persistence re-installation.

1. Read the full command for the flagged entry.
2. If it's a recognized monitoring/sync tool you intentionally configured
   for high-frequency runs, no action needed.
3. If unfamiliar, treat it as suspicious and follow the Step 1
   inspect → quarantine → remove sequence.

## Step 3: Review obfuscated commands

Entries containing `base64`, `eval`, `decode`, or `uuencode`
(`obfuscated_command`, WARNING) are trying to hide what they actually run.
Legitimate cron jobs rarely need obfuscation.

1. Decode the obfuscated portion manually (e.g.
   `echo '<base64 string>' | base64 -d`) to see what it actually executes
   — do this in a text editor or terminal, not by running it.
2. If the decoded command is benign (e.g. a vendor updater with a bundled
   base64 config blob), no action needed.
3. If it fetches or executes remote content, treat it as malicious: quarantine
   and remove using the Step 1 sequence.

## Step 4: Review the general cron/periodic/at inventory

`cron_entries_found` (INFO) lists every cron/periodic/at entry discovered so
you have full visibility into what's scheduled on this machine.

1. Read through the full entry list from the finding.
2. For each entry not already addressed above, confirm it belongs to
   software you actively use (backup tools, package manager updaters,
   etc.).
3. Remove anything you don't recognize using the Step 1 sequence, keeping
   entries tied to software you trust.
