---
profile: digital_security_reset
phase: 4
title: "Rebuilding Security"
automatable_steps: [1, 4]
human_only_steps: [2, 3]
estimated_time: "40 minutes"
---

## Step 1: Set up a password manager

Run `password_manager_check`. It reports whether a password manager is
installed here, and — separately — whether a browser is keeping its own
password database, which is the copy an attacker with access to your account
can read without a master password. It looks at file names and dates only; it
never opens a password database.

If no manager is installed, set one up now and start migrating your accounts
into it, beginning with the ones you haven't touched yet. If a browser database
turned up, move those passwords across and then turn off the browser's own
password saving.

## Step 2: Verify unique passwords everywhere

Use your password manager's security report across the account list from
Phase 1 to confirm nothing is reused and everything meets a minimum strength
bar.

## Step 3: Review app permissions on your phone

Go through installed apps and revoke location, contacts, and microphone
access for anything that doesn't need it.

## Step 4: Set up strong 2FA on your most critical accounts

Re-run `twofa_audit` now that Phase 2 is behind you. For email, banking, and
any account tied to your identity or finances, move from SMS-based 2FA to an
authenticator app or hardware security key where the service supports it.

If the audit reports that every factor it can see lives on this one device, add
one that doesn't — a security key, or an authenticator app on a separate phone.
A second factor stored beside the password is not a second factor.
