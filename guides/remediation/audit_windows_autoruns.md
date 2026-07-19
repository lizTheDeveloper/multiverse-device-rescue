---
title: "Audit Windows autorun/startup entries"
estimated_time: "25 minutes"
platforms: [windows]
remediates:
  - security.win_autoruns_audit.temp_path_execution
  - security.win_autoruns_audit.obfuscated_command
  - security.win_autoruns_audit.excessive_entries
  - security.win_autoruns_audit.inventory
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers the `win_autoruns_audit` module, which inventories
every entry across `HKLM\...\Run`, `HKCU\...\Run`, `HKLM\...\RunOnce`, and
both Startup folders (current user and all users), then flags entries
pointing to a temp/Downloads path or using obfuscated commands, and warns
when the total entry count is unusually high. This is distinct from the
`win_autorun` module, which checks the AutoRun/AutoPlay *policy* for
removable media rather than the actual startup entries themselves — see
`review_windows_autoruns.md` for that.

## Step 1: Autorun entry executing from a temp directory (critical)

An entry in a Run key or Startup folder points to a program in `Temp`,
`AppData\Local\Temp`, or `Downloads` — a strong persistence indicator, since
legitimate installed software runs from `Program Files` or a dedicated
install directory, not a scratch/download location.

1. Note the entry name, location, and full command from the finding.
2. Do not delete the entry yet. Inspect the target file first:
   `Get-FileHash "<path>"` and, if you have offline-scanner or VirusTotal
   access, check the hash there before continuing.
3. If unrecognized, treat this as likely active malware persistence:
   disconnect the machine from the network before proceeding, since an
   entry that's already run once (which it likely has, given it's live in
   the registry) may have already established a broader foothold.
4. Preserve evidence: `reg export "<hive_key>" autorun_backup.reg` (or note
   the exact key/value/data) and copy the target file to
   external/removable storage before removing anything.
5. Remove the Run-key entry: `reg delete "<hive_key>" /v "<entry_name>" /f`
   (elevated), or for a Startup-folder entry, move the shortcut/file out of
   the Startup folder to a quarantine location rather than deleting it
   outright.
6. Quarantine the target executable itself (move it, don't delete, to a
   dated folder on external storage).
7. Cross-check with `respond_to_windows_malware_indicators.md` and
   `triage_windows_suspicious_processes.md` — temp-path persistence is
   frequently paired with a matching running process or a suspicious
   service; also check `secure_windows_scheduled_tasks.md` for a
   Scheduled Task doing the same thing as a backup persistence mechanism.
8. Run Microsoft Safety Scanner or Windows Defender Offline for a full
   sweep, then re-run this scan to confirm the entry no longer appears.

## Step 2: Autorun entry with an obfuscated command (warning)

An entry's command line uses an obfuscation/encoding technique — a
PowerShell `-enc`/`-e` encoded command, `Invoke-Expression`/`IEX`, a pipe
into `iex`, `certutil -decode`, or a Base64-looking argument. This
technique hides the actual behavior from casual inspection and is common
in both malware and, less often, legitimate deployment tooling that
Base64-encodes arguments to avoid quoting issues.

1. Note the entry name, location, and full command from the finding.
2. If it's a PowerShell `-EncodedCommand`, decode it before deciding
   anything: the encoded portion is Base64 UTF-16LE —
   `[System.Text.Encoding]::Unicode.GetString(
   [System.Convert]::FromBase64String("<encoded-portion>"))`. Read the
   decoded script; don't re-run it.
3. If the decoded command downloads and executes further code (look for
   `Invoke-WebRequest`, `DownloadString`, a remote URL feeding into `IEX`),
   or if it's a `certutil -decode` reconstructing a hidden binary, treat
   this as malicious: follow the disconnect-network + preserve-evidence +
   remove-entry procedure in Step 1.
4. If you can attribute the entry to a known deployment/management tool you
   use (some legitimate agents do encode arguments), and the decoded
   content matches expected behavior, no action is needed.
5. When in doubt, disable rather than delete first — remove it from the Run
   key/Startup folder as in Step 1 but keep your evidence copy, and monitor
   whether anything breaks before considering the investigation closed.

## Step 3: Excessive number of autorun entries (warning)

More than 20 combined entries were found across Run keys and Startup
folders. This is usually accumulated legitimate bloat (browser updaters,
chat apps, cloud sync clients, printer/peripheral helper apps) rather than
malware on its own, but a high count makes it easier for one malicious
entry to hide unnoticed.

1. Review the full inventory (see Step 4 below) and use Task Manager's
   "Startup apps" tab (or `msconfig` → Startup) for a friendlier view with
   publisher/impact info.
2. For each entry, decide: is this something you use regularly and want
   starting automatically? Many apps (cloud sync, chat, creative suite
   helpers) don't need to auto-start for you to use them normally.
3. Disable (don't necessarily delete) entries you don't need auto-starting,
   via Task Manager's Startup apps tab (right-click → Disable) where
   possible — this is reversible and doesn't require touching the
   registry directly.
4. For entries not visible in Task Manager (some RunOnce or Startup-folder
   items), remove via the same registry-entry or Startup-folder-file
   procedure as Step 1, but only for entries you've confirmed you don't
   need — no evidence preservation or network disconnection is warranted
   here unless the entry is also flagged under Step 1 or 2.
5. Re-run the scan afterward; the count itself isn't a hard threshold to
   hit — the goal is fewer entries you can't account for, not a specific
   number.

## Step 4: Autorun entries inventory (informational)

This INFO finding lists every entry found across all locations
(`HKLM\Run`, `HKCU\Run`, `HKLM\RunOnce`, and both Startup folders) as a
reference — it's always present when any entries exist, independent of
whether anything else was flagged. Use it as your checklist when working
through Steps 1–3, and as a baseline to compare against on future scans (a
new entry appearing between scans that you didn't add yourself is worth
investigating even if it doesn't match the temp-path or obfuscation
patterns above).
