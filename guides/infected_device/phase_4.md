---
profile: infected_device
phase: 4
title: "Erase and Reinstall, When That's the Honest Answer"
automatable_steps: []
human_only_steps: [1, 2, 3]
---

## Step 1: Decide

Erase and reinstall when the computer won't start normally, when the
infection keeps coming back, when you found ransomware or monitoring
software someone else controls, or when you just can't trust it any more.
It's the only fix that doesn't depend on finding every piece. Copy your
files off first (Phase 2): erasing deletes everything. If monitoring
software someone you know installed is involved, talk to an advocate before
you erase: it removes their software too, and they may notice.

## Step 2: On a Mac

Erase first, then reinstall. On macOS Monterey or later, on a Mac with
Apple silicon or the Apple T2 chip: Apple menu > **System Settings** >
**General** > **Transfer or Reset** > **Erase All Content and Settings**.
Otherwise, or if the Mac won't start: start macOS Recovery (Phase 1,
Step 3), use **Disk Utility** to erase the startup disk, then choose
**Reinstall macOS**.

Reinstalling macOS downloads it, so the Mac needs the internet for this
step. That's fine once the disk is erased: the infection was on the disk.

Apple's instructions: support.apple.com/en-us/102664 (erase) and
support.apple.com/en-us/102655 (reinstall).

## Step 3: On Windows

**Settings** > **System** > **Recovery** > **Reset PC** (Windows 10:
**Update & Security** > **Recovery** > **Get started**), or from Windows
Recovery: **Troubleshoot** > **Reset this PC**. Choose **Remove
everything**: "Keep my files" keeps files the malware may have touched.
**Local reinstall** works offline; **Cloud download** needs the internet.

For a computer you can't trust at all, the cleaner way is a fresh install
from a USB drive made on a different, clean PC with Microsoft's media
creation tool.

Microsoft's instructions: "Reset your PC" and "Reinstall Windows with the
installation media" on support.microsoft.com.
