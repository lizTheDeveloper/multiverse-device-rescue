---
title: "Act on ClamAV scanner findings"
platforms: [macos, windows, linux]
remediates:
  - security.clamav_scanner.clamav_not_installed
  - security.clamav_scanner.clamav_version
  - security.clamav_scanner.freshclam_not_installed
  - security.clamav_scanner.clamav_definitions
  - security.clamav_scanner.clamav_outdated_definitions
  - security.clamav_scanner.clamd_not_running
  - security.clamav_scanner.clamd_running
steps_for:
  security.clamav_scanner.clamav_not_installed: [1, 4]
  security.clamav_scanner.clamav_version: [4]
  security.clamav_scanner.freshclam_not_installed: [1, 4]
  security.clamav_scanner.clamav_definitions: [4]
  security.clamav_scanner.clamav_outdated_definitions: [2, 4]
  security.clamav_scanner.clamd_not_running: [3, 4]
  security.clamav_scanner.clamd_running: [4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

ClamAV is a free, open-source virus scanner. It's optional: your computer's
own protection (XProtect on a Mac, Windows Security on Windows) already runs,
and on a Mac Reclaim City reads files with Apple's own malware rules. ClamAV
is a second opinion that the deep virus scan uses when it's installed.

## Step 1: Install ClamAV if you'd like a second opinion

`clamav_not_installed` and `freshclam_not_installed` mean ClamAV, or its
updater, isn't here.

1. Decide whether you want it. If you don't have a reason to, no action is
   needed.
2. On a Mac or Windows: download the installer from
   https://www.clamav.net/downloads (the `.pkg` file for a Mac, the `.msi`
   file for Windows) and open it. If you already use Homebrew on a Mac,
   `brew install clamav` works too.
3. On Linux: install the `clamav` package from your software app or package
   manager (on Ubuntu or Debian, `sudo apt install clamav clamav-freshclam`).
4. Check it: `clamscan --version` should print a version.

## Step 2: Update its virus list

`clamav_outdated_definitions` means ClamAV's list of known viruses is more
than a month old, so it would miss recent ones.

1. Run ClamAV's updater, `freshclam`, from a network you trust.
2. If it reports a lock or permission problem, another update may be
   running; let it finish instead of stopping it.
3. The deep virus scan (`rescue scan --profile deep_virus_scan`) fetches a
   fresh list of its own into Reclaim City's cache folder when ClamAV's is
   more than a week old, so you don't have to do this before a scan.

## Step 3: The background scanner is optional

`clamd_not_running` means ClamAV's background service isn't running. Reclaim
City doesn't need it: it runs `clamscan` when you ask for a scan. Start it
only if you want ClamAV watching all the time (it costs memory and power).
`clamd_running` is the confirmation that it's on.

## Step 4: Check its version and list

`clamav_version` and `clamav_definitions` are for your information: which
ClamAV is installed and how old its virus list is. Nothing to do unless the
list gets old (Step 2).
