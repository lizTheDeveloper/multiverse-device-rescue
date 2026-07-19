---
title: "Investigate rootkit indicators"
estimated_time: "30 minutes"
platforms: [macos]
remediates:
  - security.rootkit_check.sip_disabled
  - security.rootkit_check.binary_integrity
  - security.rootkit_check.kernel_extensions
  - security.rootkit_check.hidden_processes
  - security.rootkit_check.hidden_files
  - security.rootkit_check.all_clean
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

This walkthrough covers everything the `rootkit_check` module can flag: a
disabled System Integrity Protection (SIP), system binaries that fail
code-signature verification, non-Apple kernel extensions, a process-count
mismatch that can indicate hidden processes, and unexpected hidden files at
the filesystem root. Rootkits are among the most severe compromises possible
on macOS — they run with elevated privileges and are specifically designed to
hide their own presence — so every step here is investigate-first, and
several explicitly recommend treating the machine as untrusted until you've
confirmed otherwise.

If you land on this guide with multiple CRITICAL findings at once (SIP
disabled **and** binary integrity failures, for example), treat the machine
as actively compromised: disconnect it from the network before doing
anything else, do not enter any passwords on it, and remediate from a
separate known-clean device (e.g. use another Mac to research indicators and
download tools, then transfer them via a freshly-verified USB drive).

## Step 1: Re-enable System Integrity Protection (critical)

SIP being disabled is not, on its own, proof of compromise — some
developers disable it intentionally — but it removes a major barrier that
rootkits rely on, so treat it as high priority to resolve or explain.

1. Think back to whether *you* disabled SIP intentionally (e.g. for kernel
   development, or to install a modified driver). If yes and you still need
   it disabled, document why and skip to Step 2 with extra scrutiny on the
   other findings.
2. If you didn't disable it, reboot into Recovery Mode (hold the power
   button on Apple Silicon and choose Options, or Cmd+R on Intel during
   startup).
3. Open Terminal from the Recovery utilities menu and run: `csrutil status`
   to confirm it's disabled, then `csrutil enable` to re-enable it.
4. Reboot normally and re-run this scan to confirm SIP now reports enabled.
5. If SIP re-enables cleanly and nothing else in this guide flags a problem,
   the disable was likely benign. If SIP won't stay enabled, or other
   CRITICAL findings are present alongside it, escalate to Step 6.

## Step 2: Investigate system binary signature failures (critical)

A failed `codesign` verification on a core binary (`/bin/sh`, `/bin/bash`,
`/usr/bin/login`, `/usr/sbin/sshd`) means the file on disk doesn't match
Apple's signed original — it may have been tampered with.

1. Note the exact binary path from the finding.
2. From a terminal, verify independently: `codesign -v <path>` and `codesign
   -dv <path>` — read the error output carefully.
3. **Do not run the binary further while investigating** if you can avoid it
   (e.g. avoid new `sh`/`bash` invocations beyond what you need).
4. Compare the file's modification time (`ls -la <path>`) against your
   last trusted software update — an unexpected recent timestamp is a strong
   signal of tampering.
5. Because these are core OS files, the safest remediation is a full macOS
   reinstall from Recovery Mode (`Reinstall macOS` from the Recovery
   utilities), which restores signed originals without touching your user
   data. Do not simply copy a binary over from another machine — verify
   provenance through Apple's own installer instead.
6. Before reinstalling, back up personal files you need (documents, photos)
   to external media, but avoid backing up hidden dotfiles, LaunchAgents, or
   application support directories from the compromised system, since
   malware persistence often lives there — restore those from known-clean
   backups instead, or none at all.

## Step 3: Review non-Apple kernel extensions

Third-party kernel extensions are not inherently malicious (VPN clients,
virtualization software, and some security tools use them), but they run
with kernel privileges, making them a natural target for rootkit
installation.

1. Run `kextstat` yourself and cross-reference every non-`com.apple.*`
   bundle ID the scan reported against software you remember installing.
2. For anything you don't recognize, search the bundle identifier online
   before doing anything else — many are legitimate (e.g. `com.docker.*`,
   `com.wireguard.*`).
3. For extensions you don't recognize or can't account for, identify the
   owning application (`kextfind` or `system_profiler SPKernelExtensionsData
   Type`) and quarantine it: move the application to a dated folder on your
   Desktop (`~/Desktop/quarantine-YYYYMMDD/`) rather than deleting outright,
   so you retain the artifact for further analysis if needed.
4. Reboot and confirm the extension no longer loads (`kextstat` again).
5. Only permanently delete the quarantined app once you're confident it was
   the source and you no longer need it for reference.

## Step 4: Investigate process count discrepancies

A mismatch between the process count from `ps` and from `sysctl
kern.proc.all` can indicate a process actively hiding itself from
enumeration — a classic rootkit technique — though small discrepancies can
also come from processes starting/exiting during the scan.

1. Re-run both commands yourself back-to-back to rule out a timing race:
   `ps -eo pid | wc -l` and `sysctl kern.proc.all | wc -l`.
2. If the discrepancy persists and is large, boot into Safe Mode
   (hold Shift during Intel boot, or hold power and choose Safe Mode on
   Apple Silicon) — Safe Mode disables most third-party kernel extensions
   and startup items, which can unmask a hiding process.
3. In Safe Mode, compare `ps aux` output against what you'd normally expect
   running on this machine.
4. If you can identify a specific suspicious process this way, do **not**
   simply `kill` it yet — first check what files/network connections it has
   open (`lsof -p <pid>`) to understand its footprint, since remnants may
   persist and relaunch it.
5. If you cannot pin down the discrepancy's cause and it recurs across
   reboots, treat the machine as compromised and follow the "actively
   compromised" guidance at the top of this document (disconnect network,
   remediate from a clean posture, consider professional incident response
   or a full OS reinstall).

## Step 5: Review suspicious hidden files at filesystem root

Rootkits sometimes drop dot-prefixed files directly under `/` to hide
payloads or persistence data outside the directories users normally browse.

1. Run `ls -la /` yourself and compare against the flagged file list.
2. For each unfamiliar entry, check its type and size (`file <name>`, `ls
   -la <name>`) before opening or executing anything.
3. Move (don't delete) anything you don't recognize into a quarantine
   folder for later analysis: `sudo mkdir -p /private/quarantine-YYYYMMDD &&
   sudo mv /<file> /private/quarantine-YYYYMMDD/`.
4. If a quarantined item turns out to be a legitimate tool's data file
   (some backup/virtualization software does use root-level dot files),
   move it back. Otherwise leave it quarantined or submit a sample to a
   malware-analysis service (e.g. VirusTotal) before final deletion.

## Step 6: Escalate if multiple indicators are present, or the system checks out clean

1. If this scan reports **only** the `all_clean` INFO finding, no action is
   needed — the module found signed binaries, no unexpected kernel
   extensions, matching process counts, and no unusual root-level files.
2. If two or more of the CRITICAL/WARNING checks above fired together
   (especially SIP disabled + a failed binary signature), don't try to
   remediate item-by-item — assume compromise. Disconnect from the network,
   back up only files you're confident are unaffected (documents, photos —
   not system config or app data), and rebuild from a clean macOS install
   plus fresh app downloads from original sources.
3. Change passwords for any accounts accessed from this machine, from a
   separate known-clean device, once you're confident the rebuild is
   complete.
