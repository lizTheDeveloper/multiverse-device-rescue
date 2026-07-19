---
title: "Secure FileVault disk encryption recovery keys"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.disk_encryption_recovery.fv_disabled
  - security.disk_encryption_recovery.recovery_key_unknown
  - security.disk_encryption_recovery.no_recovery_key
  - security.disk_encryption_recovery.institutional_key_only
  - security.disk_encryption_recovery.users_not_all_enabled
  - security.disk_encryption_recovery.disk_encryption_status
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

This walkthrough covers everything the `disk_encryption_recovery` module can
flag: FileVault being off entirely, missing/unclear recovery keys, an
institutional-only key with no personal backup, user accounts that aren't
FileVault-enabled, and the informational status summary. All of it is
human-only: generating or rotating a recovery key is a credential operation,
and the key itself must never be pasted into this tool or any other
automation.

## Step 1: Enable FileVault if it's off

If `fv_disabled` was reported, FileVault encryption isn't active yet, so
recovery-key checks don't apply.

1. Confirm current status: `fdesetup status` in Terminal.
2. See `enable_disk_encryption.md` for the full walkthrough on turning
   FileVault on and safely capturing the recovery key during setup.

## Step 2: Resolve unknown recovery key status

If `recovery_key_unknown` was reported, the scan couldn't determine whether
a recovery key exists.

1. Run `fdesetup hasinstitutionalrecoverykey` and `fdesetup
   haspersonalrecoverykey` yourself in Terminal to check directly.
2. If both report "No", treat this the same as Step 3 (no recovery key) and
   generate one.
3. If one reports "Yes", note which type of key exists so you know whether
   you're covered by a personal key (only you know it) or an institutional
   one (your organization's MDM can use it).

## Step 3: Generate and securely store a missing recovery key (critical)

If `no_recovery_key` was reported, FileVault is on but there is no way to
recover the data if the login password is lost — this is a critical,
unrecoverable data-loss risk.

1. In Terminal, run `sudo fdesetup changerecovery -personal`.
2. This prints a new personal recovery key to the terminal exactly once.
   **Write it down or save it into a password manager immediately** — do
   not paste it into this tool, into chat, into a note synced to an account
   you don't fully control, or anywhere else it could be read by someone
   else. Anyone holding the key can decrypt the disk.
3. Verify it was recorded: `fdesetup haspersonalrecoverykey` should now
   report "Yes".
4. Re-run the scan to confirm the finding clears.

## Step 4: Add a personal backup key alongside an institutional-only key

If `institutional_key_only` was reported, an MDM-issued key exists but there
is no personal backup — if the institutional key becomes unavailable
(MDM misconfiguration, org offboarding, etc.), you have no fallback.

1. Confirm your organization's policy allows a personal key alongside the
   institutional one (some MDM setups intentionally disallow this — check
   with IT before proceeding on a managed device).
2. If allowed, run `sudo fdesetup changerecovery -personal` and store the
   printed key exactly as described in Step 3.

## Step 5: Enable FileVault for accounts that are missing it

If `users_not_all_enabled` was reported, one or more local accounts are not
FileVault-enabled — their data would not benefit from disk encryption even
though the volume itself is encrypted for enrolled users.

1. Review the list of disabled users in the finding and confirm each is a
   real account that should be protected (not a service/system account).
2. Have each affected user log in, then, as an admin, run `sudo fdesetup add
   -usertoadd <username>` in Terminal and enter that user's password when
   prompted.
3. Re-run the scan to confirm all real user accounts now show as enabled.

## Step 6: Review the status summary

The `disk_encryption_status` finding is informational — it reports current
FileVault state, which recovery key types are present, and which users are
enabled. Confirm it matches your expectations; no action is required unless
one of the findings above was also raised.
