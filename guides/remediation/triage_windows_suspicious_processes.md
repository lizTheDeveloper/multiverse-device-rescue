---
title: "Triage Windows suspicious processes"
estimated_time: "30 minutes"
platforms: [windows]
remediates:
  - security.win_suspicious_processes.known_malware
  - security.win_suspicious_processes.mining_software
  - security.win_suspicious_processes.suspicious_path
  - security.win_suspicious_processes.no_file_path
  - security.win_suspicious_processes.encoded_powershell
  - security.win_suspicious_processes.summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `win_suspicious_processes` module can
flag: processes matching known malware/miner names, mining software,
processes running from temp directories, processes with no on-disk file
path, and PowerShell processes running Base64-encoded commands. Confidence
varies by category — a matched malware name is high-confidence, while a
missing file path or an encoded PowerShell command each have legitimate
explanations, so investigate before taking action.

## Step 1: Known malware process (critical)

The process name matched a known malware/RAT/credential-theft-tool
signature (e.g. Mimikatz, Cobalt Strike beacon names, LaZagne, or a known
cryptominer like XMRig).

1. Note the PID, name, and path from the finding — do not close the Task
   Manager window or the terminal you're working from yet.
2. Because tools in this category (Mimikatz, Cobalt Strike, Meterpreter)
   are commonly used for active credential theft or remote-access
   maintenance rather than opportunistic adware, treat this as a likely
   active-compromise scenario: disconnect the machine from the network
   (unplug Ethernet / disable Wi-Fi) before continuing, to cut off any
   attacker's live session.
3. Preserve evidence before killing the process: `Get-Process -Id <pid> |
   Select-Object Path,StartTime,Company` and, if a path is present, copy
   the binary to removable/external storage rather than deleting it, and
   record its hash (`Get-FileHash <path>`).
4. End the process from an elevated PowerShell: `Stop-Process -Id <pid>
   -Force`.
5. Check for persistence the tool may have installed: Scheduled Tasks
   (`Get-ScheduledTask`), Run keys (`reg query
   HKCU\Software\Microsoft\Windows\CurrentVersion\Run` and the HKLM
   equivalent), and services (`Get-Service`) referencing the same binary
   name or path — remove any you find using the `secure_windows_scheduled_tasks.md`
   or `review_windows_autoruns.md` walkthroughs as needed.
6. Run Microsoft Safety Scanner or Windows Defender Offline (boots outside
   the live OS) for a fuller sweep, since tools in this family often arrive
   alongside other payloads.
7. Change passwords for any accounts used on this machine (Windows login,
   browser-saved passwords, any accounts you signed into) from a
   *different, trusted* device once the machine is disconnected — Mimikatz
   and LaZagne specifically exist to harvest credentials, so assume they
   were exposed.
8. Only reconnect the machine to the network after the offline scan is
   clean and persistence mechanisms are removed.

## Step 2: Mining software (nicehash and similar)

Cryptomining software was detected. This may be something you installed
deliberately (e.g. you mine crypto on this machine) or may indicate a
cryptojacking infection running without your knowledge.

1. Note the PID, name, and path from the finding.
2. Confirm whether you (or someone with legitimate access to this machine)
   installed this deliberately. If so, no action is needed — this is a
   false positive for your use case.
3. If you don't recognize it, check how it's configured to run: is it set
   to auto-start (a Scheduled Task, Run key, or service)? Check the mining
   pool/wallet address it's configured to send earnings to, if visible in
   its config file — this can confirm it isn't yours.
4. If unrecognized, end the process (`Stop-Process -Id <pid> -Force`),
   quarantine the installation folder (move it, don't delete, to a dated
   folder on external storage) rather than deleting outright, and remove
   any persistence mechanism found in step 3.
5. Investigate how it arrived — cryptojacking is commonly delivered via a
   bundled "free" download, a cracked/pirated installer, or a compromised
   browser extension; check those sources before reinstalling anything
   similar.

## Step 3: Process running from a suspicious path

A process is executing from `%TEMP%` or `C:\Windows\Temp` rather than a
normal installed-application location — legitimate installers commonly run
briefly from temp during setup, but a persistent process living there is
unusual.

1. Note the PID, name, and full path from the finding.
2. Check whether it's mid-installation (an installer that's still running)
   — if so, this may be transient and benign; let it finish and re-scan.
3. If it's a standing/long-running process, inspect the file before acting:
   `Get-FileHash <path>` and, if you have an offline scanner or VirusTotal
   access, check the hash there rather than running the file further.
4. If you don't recognize it, end the process (`Stop-Process -Id <pid>
   -Force`) and quarantine the file to a dated folder on external storage
   rather than deleting it immediately, so it's available for further
   analysis.
5. Re-run the scan to confirm it no longer appears, and check Scheduled
   Tasks / Run keys for anything that might relaunch it.

## Step 4: Process with no file path

A process with no on-disk file path (other than the `System` process
itself, which is expected to have none) can indicate process hollowing or
in-memory code injection — but it can also be a protected system process
Windows won't expose the path for, or a permissions artifact of running the
scan without elevation.

1. Note the PID and name from the finding.
2. Re-run the check from an elevated (Administrator) PowerShell if you
   didn't already — many legitimate protected processes only expose their
   path to an elevated caller, so this alone can produce false positives.
3. If it still shows no path when elevated, use `Get-CimInstance
   Win32_Process -Filter "ProcessId=<pid>"` for a fuller view (parent
   process, command line) and `Get-Process -Id <pid> -Module
   -ErrorAction SilentlyContinue` to see loaded modules — a legitimate
   process usually shows normal system modules; hollowed/injected
   processes often show an anomalous module list.
4. If the parent process is also unrecognized or the module list looks
   wrong, treat this as a likely injection: disconnect from the network,
   preserve what evidence you can (the CIM output above), and run an
   offline malware scan rather than just killing the process — the
   underlying injecting process, if different, will just relaunch it.
5. If, after elevated re-check, the process resolves to a known Windows
   component (common for certain kernel-adjacent or virtualization-related
   processes), no action is needed.

## Step 5: PowerShell running an encoded command

A PowerShell process was found running with `-EncodedCommand` (or the `-e`
/`-enc`/`-ec` shorthand), which Base64-encodes the script being run. This is
a common technique for both legitimate automation (some deployment tools
use it to avoid quoting issues) and malware/living-off-the-land attacks
(it obfuscates the command from casual inspection and evades simple
string-based detection).

1. Note the truncated command from the finding's `command` field.
2. Decode it to see what it actually does — the encoded portion is
   Base64-encoded UTF-16LE: `[System.Text.Encoding]::Unicode.GetString(
   [System.Convert]::FromBase64String("<encoded-portion>"))`. Run this
   decode step only (don't re-execute the decoded script).
3. If the decoded command is something you recognize (a deployment script,
   a management tool you use, a scheduled maintenance script), no action is
   needed.
4. If the decoded command downloads and executes further code (look for
   `Invoke-WebRequest`, `DownloadString`, `IEX`/`Invoke-Expression`
   combined with a remote URL), treat this as likely malicious: note the
   PID and parent process (`Get-CimInstance Win32_Process -Filter
   "ProcessId=<pid>"` for `ParentProcessId`, then look up the parent too —
   many of these are spawned by a macro-enabled Office document or a
   scheduled task), disconnect from the network, and end the process
   (`Stop-Process -Id <pid> -Force`).
5. Check Scheduled Tasks and Run keys for anything that would relaunch a
   similar encoded PowerShell command, and remove it (see
   `secure_windows_scheduled_tasks.md` / `review_windows_autoruns.md`).
6. Run an offline malware scan afterward, since encoded PowerShell is
   frequently a second-stage loader rather than the full payload.

## Step 6: Summary finding

The INFO-level "Suspicious process activity detected" finding is a count
summary generated whenever any of the above categories fired during this
scan — it carries no action of its own beyond working through whichever
specific categories above are also present in the same scan's results.
