# Bootable rescue stick: scope

**Status:** scope only, nothing built.

**Decided (2026-10-27):**
- Targets: Windows, Linux **and** Mac.
- The stick may ask for a BitLocker recovery key or a Linux (LUKS) passphrase
  in its own unlock prompt.
- The stick helps people reinstall their operating system when that's the
  right fix, with a walkthrough and links. That covers phones too: alternative
  Android systems and restoring an iPhone.

Today's stick (`docs/usb-rescue-stick.md`) carries installers. The person
installs Reclaim City on the computer's own OS, so a compromised OS can lie to
it, and a computer that won't start can't be checked at all. The bootable stick
starts the computer from the stick, reads the internal disk while its own OS
isn't running, and, if the person decides to, helps them start over with a
clean install. The July design spec already lists this as "Phase 2 (Future)"
(`2026-07-05-multiverse-device-rescue-design.md`, lines 12 and 343–347).

## What blocks it

### 1. The engine can only check the computer it is running on

- **No target option.** Nothing like `--root` or `--target` exists. Each
  module hardcodes absolute paths (`/Library/LaunchAgents`, `/etc/...`,
  `C:\...`) and calls `Path.home()`.
- **No choke point.** 243 modules call `subprocess` directly and only about 21
  use `rescue/fsbounds.py`, so there is no single place to redirect paths or
  commands.
- **Platform comes from the running system.** It is detected from
  `sys.platform`, so on a Linux stick only the Linux modules would run, and
  they would check the stick itself.
- **Windows-only tools.** 23 Windows modules read the registry through
  `reg query` or PowerShell, and neither exists on Linux.
- **macOS-only tools.** macOS modules use `defaults`, `plutil`, `codesign`
  and `launchctl`.

Rough split by what each module reads (a static survey; counts approximate):

| Target OS | Modules | Read only files (could work offline) | Need the running OS | Both |
|---|---|---|---|---|
| Windows | 102 | 16 | 52 | 33 |
| macOS | 197 | 27 | 103 | 65 |
| Linux | 30 | 4 | 8 | 17 |

The "both" group holds most of the checks that matter for "is someone
watching me / is there malware":

- persistence (Run keys, startup folders, scheduled tasks, LaunchAgents,
  systemd units, cron)
- `stalkerware_scan`: installed apps and plist or registry names work
  offline; the running-process half doesn't
- remote-access tools and `authorized_keys`
- hosts file, browser extensions, TCC permissions

Each of these needs its file-reading half split out and made to run against a
target root.

**No offline virus scan exists.** The bundled indicators are name and pattern
lists (48 stalkerware entries, miners, AI-worm paths), with no file hashes and
no YARA rules. `clamav_scanner` only checks whether ClamAV is installed.

### 2. Each kind of computer needs a different way in

| Computer | Can it start from a Linux stick? | Reading the disk | Route |
|---|---|---|---|
| Windows PC | Yes, with Secure Boot on, if the stick boots through Microsoft-signed shim | BitLocker is on by default in Windows 11 24H2 for Microsoft-account sign-ins ([Windows Latest](https://www.windowslatest.com/2024/05/08/microsoft-confirms-windows-11-24h2-turns-on-device-encryption-by-default/amp/)), so the person types the 48-digit recovery key | Linux live system |
| Linux machine | Yes | LUKS passphrase | Linux live system |
| Apple Silicon Mac | **No.** It can't boot any OS from USB except macOS ([Asahi FAQ](https://asahilinux.org/docs/project/faq/)) | | A **macOS installer** on the stick, made with Apple's `createinstallmedia` |
| Intel Mac with a T2 chip | Only after lowering startup security, and the T2 distrusts the Linux signing CA ([Apple](https://support.apple.com/en-gu/guide/security/secc7b34e5b5/web)) | FileVault, and Linux APFS support is read-only and experimental | macOS installer, same as Apple Silicon |
| Older Intel Mac | Yes | APFS or HFS+, read-only | Either route |

- **Linux base.** The Linux part has to be Debian or Ubuntu with the
  dual-signed shim, which covers the new Microsoft 2023 UEFI CA as well as the
  2011 one that expired in June 2026
  ([Red Hat](https://www.redhat.com/en/blog/expiration-secure-boot-signing-certificates-2026)).
  The July spec's Alpine or Arch base won't boot with Secure Boot on.
- **Ubuntu as the base.** It brings the Linux reinstaller with it.

**The Mac route.**
- The stick gets a partition holding a bootable macOS installer
  ([Apple: create a bootable installer](https://support.apple.com/en-us/101578)).
- That one partition gives the person:
  - Apple's own reinstaller
  - the installer's Terminal and Disk Utility. The internal disk unlocks with
    the Mac's own login password through `diskutil apfs unlockVolume`, typed
    into the Mac's prompt.
- **The helper builds that partition on a Mac.** macOS can't be
  redistributed, so the stick builder runs `createinstallmedia` on the
  helper's Mac from Apple's own download. A stick built on Windows or Linux
  has no Mac partition, and says so.
- **Open questions, for a Phase 3 spike:**
  - Will the installer environment run our engine binary from the stick? It
    would need to be Developer ID signed and notarized; today's builds aren't.
  - Do current Apple Silicon Macs boot the installer without a
    Startup Security change? Sources disagree.
- **Fallback if the spike fails.** The Mac starts in Share Disk mode from
  Recovery, and a trusted Mac running Reclaim City checks its disk with the
  same `--target-root` mode from Phase 1. A macOS host has `plutil` and the
  rest natively, so offline macOS checks are easiest there.

### 3. Tools that already exist

- **Microsoft Defender Offline** reboots a Windows PC into a scanner outside
  Windows, with current signatures, and needs no stick
  ([Microsoft](https://support.microsoft.com/en-in/help/17466/windows-defender-offline-help-protect-my-pc)).
  The repo's Windows remediation guides already point to it.
- **Kaspersky and ESET** publish rescue disks.

Their strength is antivirus signatures; ours is monitoring and persistence
explained in plain language, plus a guided way to start over. Point to them
for virus scanning rather than competing.

## Safety properties the design must keep

- **Checking is read-only.**
  - Mount the target `ro`. For NTFS, use `ntfs3` with `ro` and never replay
    the journal, because a hibernated or Fast Startup Windows disk is "dirty".
  - Results go only to the stick's own data partition.
  - No fixes from the stick. This matches rule 1 in `AGENTS.md`.
- **Reinstalling is the person's choice, made by the vendor's own
  installer.**
  - The stick never erases anything itself. It hands off to the Windows
    installer, Ubuntu's installer, or Apple's installer, after the person has
    read what will be lost and said yes.
- **The monitoring gate comes before any reinstall.**
  - A reinstall removes monitoring software, and that can alert whoever
    installed it (rule 4).
  - Before the reinstall walkthrough, the person sees the README's safety
    note and is asked whether removal is safe for them. That includes the
    Domestic Violence Hotline: 1-800-799-7233, or text START to 88788.
  - The same applies to reflashing a phone.
  - An offline check is quieter than a live one, since the monitoring
    software isn't running to see it. That makes looking a safe first step.
- **"Couldn't check" stays honest.** In offline mode, every live-only check
  is reported as couldn't-check, never as clean.
- **Keys go only into the stick's own unlock prompt.**
  - Never stored, logged, or put in a report.
  - The prompt says where to find the key: the BitLocker key is at
    https://aka.ms/myrecoverykey, and a work or school key is at
    https://aka.ms/aadrecoverykey
    ([Microsoft](https://support.microsoft.com/en-us/windows/security/encryption/find-your-bitlocker-recovery-key)).
  - `AGENTS.md` rule 2 (an AI assistant never asks for one in chat) is
    unchanged.

## The reinstall walkthrough

**Format.** One walkthrough per system:
- on the stick, as a page in `guides/`
- in the app, as a mission in the city
- in the plain list, as steps

**Order.** Each walkthrough starts with the lightest fix and ends with a full
reinstall. Every step links to the vendor's own page, so the instructions stay
current when menus change.

### Before any reinstall (all systems)

1. **Is it safe to remove monitoring?** Show the safety note and ask (see
   above).
2. **Fix your accounts first, from a different device you trust.**
   - A reinstall doesn't fix a stolen password, and a compromised account can
     reach the new system through cloud sync.
   - Walk through `rescue guide digital_security_reset`.
3. **Back up your own files only:** documents, photos, anything you made.
   - Leave out apps, installers, browser profiles, and full-system backups:
     restoring those can bring the problem back.
   - The bootable stick can copy files out to another drive without changing
     the computer (Phase 2).
4. **Have these ready:**
   - the BitLocker recovery key
   - the Apple Account (Apple ID) password
   - the Wi-Fi password
   - any license keys for paid apps
5. **Afterwards, set the computer up as new.**
   - Turn on updates and disk encryption.
   - Don't restore apps from the old backup.
   - Run a Reclaim City checkup.

### Windows

1. **Keep everything, repair Windows:** "Fix problems using Windows Update"
   ([Microsoft](https://support.microsoft.com/en-us/windows/deployment/install-upgrade/fix-issues-by-reinstalling-the-current-version-of-windows)).
2. **Reset this PC → Remove everything → Cloud download.** No stick needed
   ([Microsoft: Reset your PC](https://support.microsoft.com/en-us/windows/experience/backup-recovery/reset-your-pc)).
3. **Clean install from USB.**
   - The bootable stick's menu offers "Reinstall Windows".
   - Otherwise, make installation media with Microsoft's tool. The
     manufacturer's recovery media is the best match for the hardware
     ([Microsoft: Recovery options](https://support.microsoft.com/en-us/windows/experience/backup-recovery/recovery-options-in-windows)).
4. **For malware that keeps coming back, scan before deciding:** Microsoft
   Defender Offline ([Microsoft](https://support.microsoft.com/en-in/help/17466/windows-defender-offline-help-protect-my-pc)).

### Mac

1. **Erase All Content and Settings** (Macs with Apple silicon or a T2 chip),
   or erase in Disk Utility, then reinstall
   ([Apple: erase and reinstall](https://support.apple.com/guide/mac-help/erase-and-reinstall-macos-mh27903/mac)).
2. **Reinstall from macOS Recovery.** Needs internet
   ([Apple: how to reinstall macOS](https://support.apple.com/en-us/102655)).
3. **Reinstall from the bootable stick's macOS installer**, if Recovery won't
   start or there's no internet
   ([Apple: bootable installer](https://support.apple.com/en-us/101578)).
4. **Still won't start:** Apple's restore with Apple Configurator from another
   Mac, or an Apple Store. Find and verify the current Apple page before
   linking it.

### Linux

1. **The bootable stick is an Ubuntu installer.** Its menu offers "Reinstall
   Linux"
   ([Ubuntu: install Ubuntu Desktop](https://ubuntu.com/desktop/docs/en/latest/tutorial/install-ubuntu-desktop/)).
2. **For another distribution,** make its installer
   ([Ubuntu: create a bootable USB stick](https://ubuntu.com/desktop/docs/en/latest/how-to/create-a-bootable-usb-stick/)),
   then download from the distribution's own site.
3. **Turn on full-disk encryption** in the installer.

### Phones

Today, `iphone_spyware_check` checks iPhone backups with MVT. Rule 5 still
applies: ask first.

**iPhone**
1. **Erase and restore with a computer**
   ([Apple: restore to factory settings](https://support.apple.com/en-us/118107)).
2. **Recovery mode** if that fails
   ([Apple: if you can't update or restore](https://support.apple.com/en-us/118106)).
3. **Afterwards, set it up as new.** Don't restore a backup from before the
   problem.

**Android: factory reset first.** For many people that's enough. The steps
vary by maker; link Google's and each maker's own pages, verified when written.

**Android: a different operating system.** This is for people who want a
phone that's harder to monitor. Every option here:
- wipes the phone when the bootloader is unlocked
- may break banking and some other apps
- needs a computer. Web installers need Chrome or Edge, or the bootable stick
  (below).

| System | Phones | Where to start |
|---|---|---|
| GrapheneOS | Google Pixel only | https://grapheneos.org/install/ (web installer: https://grapheneos.org/install/web) |
| CalyxOS | Pixel and a few others; Android 17 rollout began October 2026 | https://calyxos.org/install |
| LineageOS | Hundreds of models | https://wiki.lineageos.org/devices/ |
| /e/OS | About 290 models; Google-free | https://doc.e.foundation/devices/ |
| Nura (formerly postmarketOS; renamed September 2026) | Real Linux on phones; support varies by model and is still early | https://nura.eco/ (device list: https://wiki.nura.eco/wiki/Devices) |

**Recommendation.** The walkthrough recommends GrapheneOS on a Pixel for
people at risk; it's the most hardened. It shows the others for phones that
GrapheneOS doesn't support. After installing GrapheneOS or CalyxOS, relock
the bootloader as their guides say.

**Phones and the bootable stick.** The stick doubles as a clean computer:
- a browser for the web installers
- `adb` and `fastboot`
- `libimobiledevice` and MVT, to back up and check an iPhone

That way a person whose only computer is suspect can still reflash a phone or
check an iPhone.

## Phases

**Phase 0: walkthroughs on today's stick and in the app (no engine work).**
- The reinstall walkthroughs above, plus "the computer won't start, or I don't
  trust it": Defender Offline, the BitLocker key, Mac Recovery and Share Disk,
  and when to get professional incident response.
- In `guides/` on the stick, as city missions, and as plain-view steps.
- Every link checked when it's written, with a link-check test like the
  existing guide tests.

**Phase 1: offline mode in the engine, tested without booting anything.**
- **Target root.**
  - Add `rescue scan --target-root PATH --target-os windows|linux|macos`.
  - Carry the target in `SystemProfile`.
  - Add a target profiler for installed apps and startup items.
  - Modules opt in with an `offline_capable` flag. Everything else reports
    couldn't-check.
- **Linux targets first.** `linux_account_audit`, `linux_persistence_audit`,
  `linux_ssh_hardening` and others already keep their paths as class
  attributes, and `systemctl --root` and `journalctl -D` work offline.
- **Windows targets.**
  - Read registry hives with a pure-Python parser (e.g. `regipy`): `SOFTWARE`,
    `SYSTEM`, and each user's `NTUSER.DAT`.
  - Parse `System32\Tasks` XML and the services under
    `SYSTEM\CurrentControlSet\Services`.
  - Cover startup folders, hosts, browser extension folders, and the
    stalkerware app and registry matches.
- **macOS targets.** Run from a macOS host for now: Share Disk, or a disk
  mounted on a trusted Mac.
  - LaunchAgents and LaunchDaemons, login items, TCC databases, `/Applications`
    and stalkerware matches, browser extensions, hosts, `authorized_keys`.
  - Plist reads become Python `plistlib`, so the same code later runs on Linux
    and in the installer environment.
- **Tests.** Fixture directory trees and small hive files in `tests/`.

**Phase 2: the bootable stick (Windows and Linux computers, and phones).**
- **Build.**
  - Ubuntu live image with the dual-signed shim, built in CI from a `v*` tag
    and published with a `SHA256SUMS` entry.
- **Boot menu (GRUB):**
  - "Check this computer": a full-screen Linux build of the desktop app
    (Electron builds for Linux; there's no Linux desktop app today).
  - "Reinstall Windows": chainloads a Windows installer partition the builder
    fills from Microsoft's download.
  - "Reinstall Linux": the Ubuntu installer.
- **Check this computer.**
  - Pick a disk; unlock BitLocker (`cryptsetup` supports it since 2.3) or
    LUKS with the person's key.
  - Mount read-only; scan with `--target-root`; show results in the city or
    plain view.
- **Also in the live system:** copy personal files out, plus the phone tools.
- **One stick, several partitions:**
  - boot (FAT32)
  - Windows installer (NTFS or FAT32 with a split `install.wim`)
  - data (exFAT): today's installers, guides and results
  - optional macOS installer (HFS+, Phase 3)

  Expect 32 GB minimum, and 64 GB if it carries the macOS installer.
- **Writing the stick.** `build_rescue_stick.py --bootable --write-to` writes
  partitions to a whole drive (today it only copies files), with the same
  refuse-internal-disk check and a typed confirmation, because it erases the
  stick.
- **Before Phase 2 ships:**
  - An offline copy pass: no finding or walkthrough for a disk result tells
    the person to run a fix-style command or to "re-run with sudo", since on
    the stick those would act on the stick, not the disk. That includes the
    commands in the remediation catalog.
  - The desktop app shows each check's `not_checked` list.
  - The app offers no re-check, fix or "It's mine" on disk results.

**Phase 3: the Mac partition.**
- **Spike first:**
  - Does a `createinstallmedia` installer boot on current Apple Silicon and
    T2 Macs without a security change?
  - Does a Developer ID–signed, notarized engine binary run from the stick in
    the installer's Terminal?
  - Can `diskutil apfs unlockVolume` open a FileVault disk there?
- **If yes:** the builder adds the macOS installer partition on a helper's
  Mac, and a "Check this Mac" script in the installer environment.
- **If no:** Macs use the Share Disk route plus the Recovery and reinstall
  walkthrough.
- **Either way, needs an Apple Developer ID**, for signing and notarizing the
  engine. Today's releases are unsigned.

**Later, optional.** ClamAV with definitions downloaded at build time. They
are about 300 MB and go stale, so show their age.

## Still to decide

1. **Order:** start with Phase 0 (walkthroughs) and Phase 1 (offline engine)?
   Recommended. Phase 0 helps people right away and Phase 1 proves the checks
   before any image work.
2. **What the stick boots into:** the city, plain view, or the same choice the
   app offers?
3. **An Apple Developer ID** for the Mac partition (Phase 3), and signing
   generally.
