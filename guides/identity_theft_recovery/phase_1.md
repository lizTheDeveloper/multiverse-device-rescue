---
profile: identity_theft_recovery
phase: 1
title: "Make Sure The Device Is Not The Leak"
automatable_steps: [1, 2, 3]
human_only_steps: [4, 5]
estimated_time: "45 minutes"
---

## Step 1: Scan for monitoring and malware on this device

Run the profile's device checks: `stalkerware_scan`, `keylogger_indicators`,
`malware_scan_indicators` or `win_malware_indicators`, `suspicious_processes`
or `win_suspicious_processes`, and `process_scanner`.

The point is narrow. You are about to type new passwords, account numbers, and
possibly a Social Security number into this machine. If something is recording
keystrokes, every step after this hands the thief a fresh copy.

## Step 2: Check the browser, where credential theft usually lives

Run `browser_extension_audit`, `browser_hijack_check`, and
`certificate_trust_audit`.

An extension with permission to read every page can read your banking session
as easily as you can. A rogue root certificate lets whoever installed it read
traffic that the padlock says is encrypted. Both are quieter than malware and
both are commonly how account access outlives a password change.

## Step 3: Check whether someone else is still logged in

Run `remote_login_check` or `win_remote_access_audit`.

Remote access left switched on is the most boring explanation for ongoing
fraud, and the most common one after a "tech support" phone call.

## Step 4: If anything was found, do the recovery from a different device

Do not clean the machine and immediately carry on. Borrow a device, use a
phone on mobile data, or use a library computer for the account changes, and
come back to cleaning this one afterwards.

If the checks found something serious, the `digital_security_reset` profile
covers the cleanup, and a full operating-system reinstall is the only way to
be certain.

## Step 5: Secure your email and phone before anything else

Email and phone number are the recovery path for every other account, which
makes them the two things worth over-protecting:

- New, unique password on the primary email account, and two-factor
  authentication turned on — an authenticator app rather than SMS.
- Check the email account's forwarding rules and filters. A rule quietly
  forwarding or deleting mail is how a thief keeps reading your alerts after
  you have changed the password. It survives password changes; look for it
  explicitly.
- Call your mobile carrier and add a port-out PIN or a SIM-swap lock to the
  account. Without one, a thief who can convince a shop assistant to move your
  number receives every SMS code you have.
