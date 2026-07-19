---
title: "Secure FileVault recovery keys (family devices)"
estimated_time: "15 minutes"
platforms: [macos]
remediates:
  - security.filevault_recovery.fv_disabled
  - security.filevault_recovery.recovery_key_unknown
  - security.filevault_recovery.no_recovery_key
  - security.filevault_recovery.users_not_all_enabled
  - security.filevault_recovery.fv_status
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything the `filevault_recovery` module can flag:
FileVault being off, missing/unclear recovery keys, user accounts that
aren't FileVault-enabled, and the informational status finding. All of it is
human-only: generating a recovery key is a credential operation and the key
itself must never be pasted into this tool or any other automation.

## Step 1: Enable FileVault if it's off

If `fv_disabled` was reported, encryption isn't active yet.

1. Confirm current status: `fdesetup status` in Terminal.
2. See `enable_disk_encryption.md` for the full walkthrough on turning
   FileVault on and safely capturing the recovery key during setup.

## Step 2: Resolve unknown or missing recovery key status

If `recovery_key_unknown` was reported, verify directly by running
`fdesetup hasinstitutionalrecoverykey` and `fdesetup
haspersonalrecoverykey` in Terminal.

If `no_recovery_key` was reported (critical — data is unrecoverable without
a key if the password is lost):

1. Run `sudo fdesetup changerecovery -personal` in Terminal.
2. This prints a new personal recovery key exactly once. **Write it down or
   save it into a password manager immediately** — do not paste it into
   this tool, into chat, or into any note synced to an account you don't
   fully control. On a family device, consider also recording where the
   key is stored somewhere the other parent/guardian can find it in an
   emergency, without weakening how it's protected day-to-day.
3. Verify with `fdesetup haspersonalrecoverykey`, which should now report
   "Yes".
4. Re-run the scan to confirm the finding clears.

## Step 3: Enable FileVault for accounts that are missing it

If `users_not_all_enabled` was reported:

1. Review the listed accounts and confirm each is a real user (a kid's
   account, a spouse's account, etc.) that should be protected.
2. Have each user log in, then, as an admin, run `sudo fdesetup add
   -usertoadd <username>` in Terminal and enter that user's password when
   prompted.
3. Re-run the scan to confirm all accounts now show as enabled.

## Step 4: Review the status summary

The `fv_status` finding is informational — it reports current FileVault
state, which recovery key types are present, and which users are enabled.
No action is required unless one of the findings above was also raised.
