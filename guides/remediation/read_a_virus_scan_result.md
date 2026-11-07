---
title: "Read a virus scan result"
platforms: [macos, windows, linux]
remediates:
  - security.malware_file_scan.no_match
  - security.malware_file_scan.scan_stopped_early
  - security.clamav_scanner.deep_scan_available
  - security.clamav_scanner.scan_clean
  - security.clamav_scanner.scan_incomplete
  - security.clamav_scanner.could_not_scan
  - security.win_defender_scan.no_threats
  - security.win_defender_scan.quick_scan_done
  - security.win_defender_scan.quick_scan_failed
  - security.win_defender_scan.could_not_read
  - security.win_defender_scan.other_antivirus_in_charge
steps_for:
  security.malware_file_scan.no_match: [1]
  security.malware_file_scan.scan_stopped_early: [2, 3]
  security.clamav_scanner.deep_scan_available: [3]
  security.clamav_scanner.scan_clean: [1]
  security.clamav_scanner.scan_incomplete: [2, 3]
  security.clamav_scanner.could_not_scan: [2]
  security.win_defender_scan.no_threats: [1]
  security.win_defender_scan.quick_scan_done: [1]
  security.win_defender_scan.quick_scan_failed: [2, 4]
  security.win_defender_scan.could_not_read: [2, 4]
  security.win_defender_scan.other_antivirus_in_charge: [4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Reclaim City's virus scans read files and compare them with lists of known
malware: Apple's own XProtect rules on a Mac, ClamAV's virus list where
ClamAV is installed, and Windows Defender's records on Windows.

## Step 1: Nothing matched

A clean result means none of the files that were checked is on those lists.
That lowers the odds of a problem without ruling one out: brand-new malware
isn't on any list yet. The ordinary checkup reads only programs and scripts in
the places malware usually lands; the deep virus scan reads more.

## Step 2: A scan that stopped or couldn't run isn't clean

If a scan stopped at its limit, couldn't download what it needed, or couldn't
read Defender's records, the files it didn't reach weren't checked. The item
says why. Most often it's a limit (run the deep virus scan), a missing
download (run it again with the internet on), or a permission macOS or
Windows is asking for.

## Step 3: Run the deep virus scan

The deep virus scan has much higher limits and also uses ClamAV where it's
installed (inside zip files and disk images too). In Terminal:
`rescue scan --profile deep_virus_scan`. The first time, ClamAV may download a
fresh virus list from ClamAV's own servers (about 115 MB); add
`--no-downloads` to skip that. ClamAV uses a lot of memory while it runs, so
close other apps first.

## Step 4: Use the antivirus that's in charge

On Windows, open **Windows Security > Virus & threat protection** to run a
scan and see **Protection history**. If another antivirus is in charge, open
that program and run its full scan instead.
