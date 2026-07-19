---
title: "Investigate Windows rootkit indicators"
estimated_time: "40 minutes"
platforms: [windows]
remediates:
  - security.win_rootkit_check.unsigned_drivers
  - security.win_rootkit_check.alternate_data_streams
  - security.win_rootkit_check.secure_boot_disabled
  - security.win_rootkit_check.hidden_services
  - security.win_rootkit_check.boot_tampering
  - security.win_rootkit_check.all_passed
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

Rootkits are designed to hide themselves, so every check here is a
*possible* indicator, not proof of infection — unsigned drivers, Alternate
Data Streams, and unusual boot flags all have legitimate explanations. Work
through each flagged category methodically, don't jump straight to
reinstalling Windows, and treat "unsigned driver" + "Secure Boot disabled" +
"hidden service" appearing together as a much stronger signal than any one
alone.

## Step 1: Unsigned drivers in System32\drivers (critical)

A driver running without a valid signature can operate at kernel level,
which is the classic rootkit foothold — this is the highest-confidence
signal in this scan.

1. Note the driver name(s) from the finding.
2. Do not delete or unload anything yet. From an elevated PowerShell, get
   more detail: `driverquery /v /fo list | Select-String -Context 5
   "<drivername>"` and `Get-WindowsDriver -Online -Driver
   "<drivername>.inf"` if it resolves.
3. Check whether it's a known unsigned-but-legitimate driver (some older
   hardware/OEM drivers are unsigned) by searching the exact filename and
   the associated device — cross-reference with Device Manager
   (`devmgmt.msc`) to see what device it belongs to.
4. If you cannot identify a legitimate owning device or vendor, treat this
   as active compromise: disconnect the machine from the network (unplug
   Ethernet / disable Wi-Fi) before doing further live investigation, so
   any C2 or lateral-movement channel is cut.
5. Preserve evidence: copy the driver file (`.sys`) to an external/removable
   drive rather than deleting it, and note the full path, hash
   (`Get-FileHash <path>`), and `driverquery /v` output — you'll want this
   if you later submit it to a scanner (VirusTotal) or hand off to IT/an
   incident responder.
6. Run Microsoft Safety Scanner or Windows Defender Offline scan (boots
   outside the running OS, which matters for rootkits that hide from a
   live-OS scan) rather than trying to remove the driver by hand.
7. If the offline scan confirms malware, follow its removal guidance; if it
   comes back clean but you're still uncertain, treat the machine as
   compromised and prefer a clean reinstall from known-good media over
   continued live remediation — rootkits are specifically built to survive
   partial cleanup.

## Step 2: Alternate Data Streams on system executables (warning)

An ADS attached to a file in `C:\Windows\System32` can hide a secondary
payload inside what looks like a normal system file.

1. Note the file(s) from the finding.
2. Inspect without executing: `Get-Item '<path>' -Stream *` to list all
   streams, then `Get-Content -Path '<path>:<streamname>' -Encoding Byte
   -TotalCount 64 | Format-Hex` to preview the stream's header bytes (a PE
   header `MZ` is a strong red flag; readable metadata/Zone.Identifier text
   is usually benign — Windows itself uses a `Zone.Identifier` ADS to mark
   downloaded files, which is expected and not malicious).
3. If the stream is a `Zone.Identifier` (download-mark-of-the-web) stream,
   this is normal Windows behavior, not a rootkit indicator — no action
   needed.
4. If the stream contains executable content or anything you can't
   identify, copy the file (with its streams intact,
   `Copy-Item -Path '<path>' -Destination 'D:\quarantine\' `) to preserve
   evidence, then run an offline scan as in Step 1 rather than stripping
   the stream yourself.
5. Only after a clean scan (or expert confirmation the stream is benign)
   should you consider removing an unwanted stream, via `Remove-Item
   '<path>' -Stream '<streamname>'` — never do this before you've
   identified what the stream contains.

## Step 3: Secure Boot disabled (critical)

Secure Boot disabled on a UEFI system removes a key protection against
bootkits (malware that loads before Windows itself, surviving reinstalls).

1. Confirm you (or whoever set up this PC) didn't intentionally disable it
   for a specific reason (dual-boot with an OS that doesn't support it,
   certain older hardware/driver compatibility, virtualization/testing).
2. If unintentional, re-enable it: reboot into UEFI/BIOS settings
   (Settings → System → Recovery → Advanced Startup → Restart now →
   Troubleshoot → Advanced options → UEFI Firmware Settings) and enable
   Secure Boot in the Boot/Security tab. Exact menu labels vary by
   motherboard/OEM.
3. Before re-enabling, if you have any reason to suspect active compromise
   (this finding combined with unsigned drivers or hidden services above),
   do not simply flip Secure Boot back on and consider it fixed — a
   bootkit that disabled it may already be resident. Preserve what evidence
   you can, disconnect from the network, and plan for a clean reinstall
   from trusted media rather than relying on re-enabling Secure Boot alone
   to remove existing malware.
4. After re-enabling and rebooting, re-run the scan to confirm Secure Boot
   now reports enabled.

## Step 4: Hidden services (warning)

A service visible to `sc query` but missing from `Get-Service` is unusual —
it can mean a service is actively being hidden, but can also reflect
timing/permission quirks in how each tool enumerates services.

1. Note the service name(s) from the finding.
2. Query it directly: `sc qc <servicename>` (shows the binary path and
   start type) and `sc query <servicename>` (shows current state).
3. Check the binary path it points to — is it in a normal system location
   (`System32`, a recognized installed application's folder) or somewhere
   unusual (temp, user profile, a hidden folder)?
4. If the binary path is in a normal location and you can attribute it to
   known software, this is likely a benign enumeration quirk — no action
   needed, but note it for next scan.
5. If the binary path is unusual or unrecognized, do not delete the service
   yet. Preserve evidence (`sc qc <servicename>` output, the binary file
   copied to quarantine storage, its hash), disconnect from the network if
   you suspect active compromise, and run an offline malware scan before
   disabling (`sc config <servicename> start= disabled`) or removing it.

## Step 5: Boot configuration tampering (warning)

Unusual `bcdedit` entries (unexpected safe-mode boot counts, debug/test
signing mode, disabled integrity checks, suspicious load options) can
indicate an attacker configured the system to load unsigned code at boot,
or persist through safe mode.

1. Run `bcdedit /enum` yourself (elevated) and review the full output
   against what the finding flagged.
2. "Debug/test signing mode" (`testsigning`) enabled is specifically what
   lets unsigned drivers load — if you don't recognize a reason for it
   (some driver development work), disable it: `bcdedit /set testsigning
   off`, then reboot.
3. "Integrity checks disabled" (`nointegritychecks`) similarly should be
   off on a normal system: `bcdedit /set nointegritychecks off`.
4. If you find these settings and don't recall enabling them yourself (they
   normally require deliberate, elevated action to set), treat this
   combined with any other flagged category above as a stronger compromise
   signal — preserve the `bcdedit /enum` output as evidence and lean
   towards a clean reinstall rather than just reverting the flags, since an
   attacker who could modify boot config had elevated access already.
5. Reboot and re-run the scan to confirm boot configuration issues have
   cleared.

## No issues found

If the scan reports only the `all_passed` INFO finding, none of the rootkit
indicators above were detected. No action is needed, but note that rootkit
detection from within a running OS has inherent limits — if you have other
reasons to suspect compromise, an offline scan (Windows Defender Offline)
is still worth running periodically regardless of this result.
