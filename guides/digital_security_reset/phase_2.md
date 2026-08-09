---
profile: digital_security_reset
phase: 2
title: "Immediate Protective Actions"
automatable_steps: [2, 3, 4]
human_only_steps: [1]
estimated_time: "30 minutes"
---

## Step 1: Change your primary email password

Do this first — your email is the recovery path for almost every other
account. Use a long, unique passphrase you haven't used anywhere else.

## Step 2: Turn on two-factor authentication for your email

Run `twofa_audit`. It lists the second factors this device can actually offer —
authenticator apps, an attached security key, hardware-backed SSH keys — and
says so plainly when the only one it finds is software running on the machine
you are recovering. Use the strongest factor it reports, and prefer an
authenticator app or security key over SMS.

The audit cannot see which accounts already have 2FA switched on; only each
provider's security page can tell you that.

## Step 3: Revoke sessions and connected apps you don't recognize

Run `session_revocation_scan` first. It lists what on this device stays signed
in after a password change: browser session stores, and credential files
holding long-lived API tokens. It reports each file's name, date, and
permissions — it never opens one — and gives the revocation step for each
service, because deleting the file leaves the token live on the server.

Then review each provider's active sessions and connected-apps page and revoke
anything you do not recognize or no longer use. Change the password before you
sign out other sessions, or whoever has the old password simply signs back in.
This part requires signing in to the provider directly; the toolkit does not
access account sessions or tokens.

## Step 4: Run the stalkerware and remote-access scan

Run the profile's local security checks for remote login, unexpected network
connections, suspicious processes, browser extensions, and sharing services.
