---
title: "Respond to mobile spyware findings (MVT)"
estimated_time: "45 minutes to 2 hours (varies; forensic support may take longer)"
platforms: [macos, linux]
remediates:
  - security.mvt_spyware_scan.mvt_requires_wsl
  - security.mvt_spyware_scan.no_backups_found
  - security.mvt_spyware_scan.mvt_not_installed
  - security.mvt_spyware_scan.mvt_spyware_detected
  - security.mvt_spyware_scan.mvt_clean_scan
  - security.mvt_spyware_scan.mvt_backup_too_large
  - security.mvt_spyware_scan.mvt_scan_available
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This module wraps Amnesty International's Mobile Verification Toolkit (MVT)
to scan iOS/Android device backups for known mobile spyware indicators
(Pegasus, Predator, and similar mercenary spyware families). Every step
below is human-guided — none of it is automatable, because it involves your
phone, an external CLI tool, and (in the worst case) irreversible actions
like a factory reset.

## Step 1: Set up MVT on Windows via WSL

MVT does not run natively on Windows.

1. Install the Windows Subsystem for Linux: `wsl --install` (requires a
   restart on first install).
2. Inside the WSL Linux environment, install MVT: `pip install mvt`.
3. On macOS/Linux (including inside WSL) you'll also want
   `libimobiledevice` installed for iOS backup decryption support — see
   your distro's package manager (e.g. `apt install libimobiledevice-utils`
   on Debian/Ubuntu, `brew install libimobiledevice` on macOS).
4. Re-run the `mvt_spyware_scan` module from inside WSL once MVT is
   installed.

## Step 2: Create a device backup if none was found

This module can only scan backups it can find — it does not connect to a
phone directly.

1. **iOS**: connect the device and create an unencrypted-or-encrypted local
   backup via Finder (macOS) or iTunes, or use
   `idevicebackup2 backup --full <destination>` from libimobiledevice. The
   default scan locations are
   `~/Library/Application Support/MobileSync/Backup` (macOS) or
   `~/.local/share/libimobiledevice/Backup` / `~/MobileSync/Backup`
   (Linux).
2. **Android**: use `adb backup` or a full device backup tool supported by
   MVT's `mvt-android` command; place it where you intend to point the scan.
3. Re-run the scan once a backup exists.
4. Even before a scan runs, if you suspect you are a high-risk target
   (journalist, activist, dissident, human-rights worker), consider Step 5's
   guidance on Lockdown Mode and contacting Amnesty International's
   Security Lab immediately rather than waiting for scan results.

## Step 3: Install MVT

1. Install MVT: `pip install mvt` (a Python virtual environment is
   recommended: `python3 -m venv mvt-env && source mvt-env/bin/activate &&
   pip install mvt`).
2. For iOS backup decryption support, also install `libimobiledevice`
   (`brew install libimobiledevice` on macOS, or your Linux distro's
   package).
3. Re-run the scan once installed; it will use `mvt-ios` or `mvt-android`
   automatically depending on what's found.

## Step 4: Respond to a confirmed spyware detection — this is the critical path

A `mvt_spyware_detected` finding means MVT matched a known indicator from
Amnesty International's published spyware IOC feeds against your backup —
this is a high-confidence signal of a targeted compromise (e.g. Pegasus,
Predator, or a similar mercenary spyware family), not a false-positive-prone
heuristic.

1. **Do not restore anything from the compromised backup.** Preserve the
   original backup exactly as-is (do not delete or modify it) — it is
   evidence, and Amnesty International's Security Lab or another forensic
   team may want a copy to help track the spyware campaign.
2. **Back up only essential personal data** (photos, documents you're
   certain aren't executable/malicious) to a *new*, separate location —
   never restore apps or a full device backup from the compromised backup,
   since that can reinfect the device with the same spyware.
3. **Perform a full factory reset** on the affected device and set it up as
   new — do not restore from the compromised backup during setup.
4. **Update to the latest OS version** before restoring anything.
   Mercenary spyware typically exploits zero-day vulnerabilities that get
   patched in later updates, so update first, then bring your data back.
5. **Enable Lockdown Mode** (iOS: Settings → Privacy & Security → Lockdown
   Mode) if you may be a target of state-sponsored or mercenary spyware —
   it significantly reduces the device's attack surface at the cost of some
   functionality.
6. **Contact Amnesty International's Security Lab**
   (https://www.amnesty.org/en/tech/) for forensic support and to help them
   track the spyware campaign. Bring the preserved original backup from
   Step 1.
7. Change passwords and re-authenticate accounts from a *different, known
   clean* device — an infected phone may have exposed session tokens,
   2FA secrets, or credentials to the spyware operator.

## Step 5: Clean-scan hygiene (no detection found)

An `mvt_clean_scan` finding means MVT found no known indicators. This is
**not** proof the device is clean — MVT can only detect indicators that
have already been published in known spyware IOC feeds; it cannot detect
novel, unpublished, or bespoke spyware.

1. Keep the device OS updated to the latest version — this is your primary
   defense against the zero-days mercenary spyware relies on.
2. If you are a high-risk target, enable Lockdown Mode regardless of a
   clean scan result.
3. Re-run MVT scans periodically as Amnesty International's indicator feeds
   are updated — a clean scan today does not mean a clean scan next month
   against the same backup.
4. If you have specific reason to suspect targeting despite a clean scan
   (unusual battery drain, unexpected reboots, data usage spikes), consider
   reaching out to Amnesty International's Security Lab for a deeper manual
   forensic review beyond what MVT's automated indicators can catch.
