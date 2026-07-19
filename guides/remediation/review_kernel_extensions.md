---
title: "Review and remove problematic kernel extensions (kexts)"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.kernel_extensions_audit.kext_retrieval_failed
  - security.kernel_extensions_audit.problematic_kexts
  - security.kernel_extensions_audit.third_party_kexts
automatable_steps: []
human_only_steps: [1, 2, 3]
---

This walkthrough covers `kernel_extensions_audit`, which lists loaded
kernel extensions (via `kmutil showloaded` on Monterey+, falling back to
`kextstat` on older macOS) and separates them into Apple's own kexts,
known-problematic third-party kexts (legacy antivirus, VPN, and
virtualization kexts that predate the System Extensions framework), and
everything else third-party.

**Kernel extensions run in kernel space with full system privileges.**
Removing the wrong one, or removing one while a dependent driver is still
attached, can cause a kernel panic or leave hardware (webcam, audio,
storage controllers) non-functional until reboot. All steps are
human-only — inspect the vendor and purpose before removing anything, and
always reboot after making changes rather than assuming the change took
effect live.

## Step 1: Address known-problematic kexts

`problematic_kexts` (WARNING) flags kexts from vendors (legacy Kaspersky,
McAfee, Norton, Symantec, Avast, AVG, Bitdefender, VirtualBox, Parallels,
OpenVPN, Little Snitch) known to ship kext-based versions that are now
deprecated in favor of System Extensions. These aren't necessarily
malicious — most likely they're outdated versions of software you
installed intentionally — but old kexts are a common source of stability
and security bugs.

1. Identify the exact bundle ID and vendor from the finding's `kexts` list.
2. Check whether the vendor ships a modern System-Extensions-based version:
   check for updates in the app itself, or the vendor's site.
3. **Prefer updating over removing**: if a newer version exists, update the
   app through its normal installer/uninstaller first — that typically
   removes the old kext for you cleanly.
4. If no modern version exists and you no longer need the software,
   uninstall via the vendor's official uninstaller rather than deleting the
   kext bundle by hand.
5. Only if no uninstaller is available, unload then quarantine (do not
   `rm -rf` directly):
   ```
   sudo kextunload /Library/Extensions/<name>.kext
   sudo mkdir -p /Library/Extensions-quarantine
   sudo mv /Library/Extensions/<name>.kext /Library/Extensions-quarantine/
   ```
6. Reboot to confirm the kext no longer loads: `kmutil showloaded | grep
   <bundle_id>` (or `kextstat | grep <bundle_id>` on older macOS) should
   return nothing.

## Step 2: Review the general third-party kext inventory

`third_party_kexts` (INFO) lists every non-Apple kext currently loaded that
isn't already flagged as known-problematic, so you have full visibility.

1. For each bundle ID, identify the vendor and confirm it's software you
   installed intentionally (audio interfaces, hardware drivers, and some
   security tools still legitimately ship kexts).
2. If you don't recognize a vendor, research the bundle ID before doing
   anything — do not remove kexts you can't positively identify, since an
   unrelated hardware driver mistaken for malware can break peripherals.
3. For kexts you no longer need, follow the Step 1 uninstall-first, then
   unload → quarantine sequence.

## Step 3: If kext auditing itself failed

`kext_retrieval_failed` (INFO) means neither `kmutil showloaded` nor
`kextstat` returned usable output — common on newer macOS releases with
restricted permissions, or on Apple Silicon Macs with no legacy kexts
loaded at all.

1. Manually check with elevated output: `sudo kmutil showloaded` (some
   fields require sudo to populate fully).
2. As a modern alternative, open **System Settings → General → Login
   Items & Extensions** and review the "Driver Extensions" / "Endpoint
   Security Extensions" sections — this is where most current macOS
   versions surface what used to be kext-only functionality.
3. If you don't run any legacy hardware drivers or virtualization software,
   this finding is expected and requires no action.
