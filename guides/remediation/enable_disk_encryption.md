---
title: "Enable disk encryption (FileVault)"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.encryption_check.filevault_disabled
automatable_steps: []
human_only_steps: [1]
---

FileVault encrypts the entire startup disk so its contents cannot be read
without the correct password or recovery key, even if the physical disk is
removed. Enabling it is human-only: it requires an admin to interactively
confirm the change and decide how the recovery key will be stored, and
initial encryption runs in the background for a while, so nothing here is
auto-applied.

## Step 1: Enable FileVault and securely store the recovery key

1. Inspect current status first: open System Settings > Privacy & Security >
   FileVault (or run `fdesetup status` in Terminal) to confirm it is
   genuinely off before changing anything.
2. In System Settings > Privacy & Security > FileVault, click **Turn On...**
   (or run `sudo fdesetup enable` in Terminal and follow the prompts).
3. You will be asked how to save the recovery key. Choose one:
   - **Store it with your Apple ID** — Apple can help you reset it if you
     forget your password, provided you still have access to that Apple ID.
   - **Create a recovery key and do not use my Apple ID** — you are shown a
     one-time recovery key string; you are solely responsible for storing it.
4. If you get a recovery key string, **write it down or save it in a
   password manager immediately** — do not paste it into this tool, into
   chat, into a note synced to an account you don't control, or anywhere
   else it could be read by someone else. Treat it like a master password:
   anyone who has it can decrypt the entire disk.
5. Confirm the choice and let the Mac restart if prompted. Initial
   encryption then runs in the background — you can keep using the Mac, but
   avoid shutting it down until `fdesetup status` reports encryption as
   complete (this can take from under an hour to several hours depending on
   disk size and usage).
6. Re-run the scan afterward to confirm FileVault now reports as on.
