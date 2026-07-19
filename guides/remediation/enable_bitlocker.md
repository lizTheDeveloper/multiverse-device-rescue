---
title: "Enable BitLocker and secure recovery keys"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_bitlocker.os_drive_not_encrypted
  - security.win_bitlocker.encryption_suspended
  - security.win_bitlocker.no_recovery_key
  - security.win_bitlocker.status_info
  - security.win_bitlocker_check.os_drive_not_encrypted
  - security.win_bitlocker_check.encryption_suspended
  - security.win_bitlocker_check.no_recovery_key
  - security.win_bitlocker_check.fixed_drive_not_encrypted
  - security.win_bitlocker_check.status_info
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

`win_bitlocker` and `win_bitlocker_check` both parse `manage-bde -status` and
flag the same underlying BitLocker problems — `win_bitlocker_check` adds one
extra finding for non-OS fixed drives. This single walkthrough covers both.
BitLocker protects data at rest if the device is lost or stolen, but getting
locked out of your own encrypted drive is a real risk if the recovery key
isn't stored safely — **never paste a recovery key into this tool, a chat, or
any other place that isn't a dedicated password manager or printed copy kept
somewhere secure.**

## Step 1: Encrypt the OS drive (C:) if it is not encrypted

This is the highest-priority finding — an unencrypted C: drive means anyone
with physical access to the disk can read its contents.

1. Confirm current state from an elevated (Administrator) prompt: `manage-bde
   -status C:`.
2. Enable encryption via Settings > System > About > Device encryption (if
   offered on this edition of Windows), or from an elevated PowerShell:
   `Enable-BitLocker -MountPoint C: -EncryptionMethod Aes256
   -UsedSpaceOnly -RecoveryPasswordProtector`.
3. When prompted, **save the recovery key immediately** — to a Microsoft
   account, a printed copy stored somewhere physically secure, or your
   organization's IT-managed key escrow. Do not save it as a plain text file
   on this same (unencrypted-until-now) drive, and do not paste it into this
   tool or any chat.
4. Encryption of a large drive can take a long time in the background —
   re-run the scan (`win_bitlocker` / `win_bitlocker_check`) later to confirm
   it reports the volume as encrypted.

## Step 2: Resume encryption if it shows as suspended

Encryption can be suspended by Windows Update, firmware changes, or manual
action — while suspended, the drive is not actively protected even though it
was previously encrypted.

1. Confirm current state: `manage-bde -status <mount point>`.
2. If you don't recall intentionally suspending it (e.g. for a BIOS update
   in progress), resume it from an elevated PowerShell: `Resume-BitLocker
   -MountPoint <mount point>`.
3. Re-run the scan to confirm the volume no longer reports "suspended".

## Step 3: Add a recovery key protector if one is missing

Without a recovery key protector, a lost password or TPM failure means the
data is unrecoverable — this doesn't weaken security, it just adds a safety
net.

1. Confirm no recovery protector exists: `manage-bde -protectors -get
   <mount point>`.
2. Add one from an elevated PowerShell: `Add-BitLockerKeyProtector
   -MountPoint <mount point> -RecoveryPasswordProtector`.
3. Immediately save the printed recovery key it outputs somewhere secure
   (see Step 1.3) — never in an unencrypted file on this machine.
4. Re-run the scan to confirm the recovery-key finding clears.

## Step 4: Encrypt other fixed drives (win_bitlocker_check only)

`win_bitlocker_check` additionally flags fixed (non-removable) drives other
than C: that aren't encrypted — for example a second internal disk.

1. Confirm which drives are fixed vs. removable before proceeding — you
   don't want to accidentally attempt to BitLocker-encrypt a drive you
   intend to move between machines without careful key management.
2. Enable encryption the same way as Step 1: `Enable-BitLocker -MountPoint
   <mount point> -EncryptionMethod Aes256 -UsedSpaceOnly
   -RecoveryPasswordProtector`, and save the recovery key securely.
3. Re-run the scan to confirm.

If the scan reports only the informational "BitLocker status" finding for a
volume, that volume is already encrypted and protected — no action needed;
review the reported key protectors just to confirm a recovery protector is
present.
