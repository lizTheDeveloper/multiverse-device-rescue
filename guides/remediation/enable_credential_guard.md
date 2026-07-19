---
title: "Enable Credential Guard and tighten password policy"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_credential_guard.credential_guard_disabled
  - security.win_credential_guard.windows_hello_configured
  - security.win_credential_guard.password_min_length_below_threshold
  - security.win_credential_guard.passwords_never_expire
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

`win_credential_guard` reports on four independent things: whether Credential
Guard is enabled, whether Windows Hello is set up, and two password-policy
settings. Credential Guard requires hardware virtualization support and a
reboot, so confirm compatibility before enabling it — it can affect certain
legacy authentication scenarios (some older VPN clients, NTLM-only tools) on
domain-joined machines.

## Step 1: Enable Credential Guard (if flagged as disabled)

Credential Guard isolates credential material (NTLM hashes, Kerberos tickets)
in a hardware-protected virtualized container, defending against
pass-the-hash and similar credential-theft attacks.

1. Confirm hardware support first: from an elevated PowerShell, run
   `Get-ComputerInfo -Property "DeviceGuard*"` — you need UEFI firmware with
   Secure Boot and virtualization extensions (Intel VT-x/AMD-V) enabled in
   the BIOS.
2. Enable via Group Policy: Win+R, `gpedit.msc`, then Computer Configuration
   > Administrative Templates > System > Device Guard > "Turn On
   Virtualization Based Security" > Enabled, with "Credential Guard
   Configuration" set to "Enabled with UEFI lock".
3. Restart the system — this is required for the change to take effect.
4. Re-run the scan afterward to confirm Credential Guard now reports as
   enabled. If this is a work/managed machine, check with IT before making
   this change, since some managed environments configure it centrally.

## Step 2: Windows Hello (informational, no action needed)

If the scan reports Windows Hello as configured, this is already a secure
state and needs no action — biometric/PIN sign-in is a strong credential
protection. Nothing to do here beyond leaving it enabled.

## Step 3: Raise the minimum password length policy

1. Confirm the current policy: `net accounts` (look for "Minimum password
   length").
2. Increase it: Win+R, `gpedit.msc`, then Computer Configuration > Windows
   Settings > Security Settings > Account Policies > Password Policy >
   "Minimum password length" > set to at least 8 (12+ is stronger).
3. Click Apply, then re-run `net accounts` to confirm the new value took
   effect.

## Step 4: Set password expiration for accounts flagged "never expires"

Passwords that never expire widen the window during which a stolen or
guessed credential stays valid indefinitely.

1. Confirm which accounts are affected — the finding lists the specific
   usernames.
2. Set a maximum password age via the same Password Policy panel as Step 3
   ("Maximum password age", 30–90 days is typical), or per-account with
   `net user USERNAME /expires:YYYY-MM-DD` if you want a one-off expiry
   instead of a blanket policy.
3. Confirm you (or the account owner) can still sign in and are prepared to
   change the password before it expires, so this doesn't lock anyone out
   unexpectedly.
4. Re-run the scan to confirm the finding clears.
