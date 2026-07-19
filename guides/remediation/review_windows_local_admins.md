---
title: "Review Windows local administrator accounts"
estimated_time: "20 minutes"
platforms: [windows]
remediates:
  - security.win_local_admin_audit.guest_account_enabled
  - security.win_local_admin_audit.builtin_admin_enabled
  - security.win_local_admin_audit.excessive_admin_accounts
  - security.win_local_admin_audit.admin_blank_password
  - security.win_local_admin_audit.admin_password_never_expires
  - security.win_local_admin_audit.admin_accounts_summary
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5]
---

`win_local_admin_audit` focuses specifically on accounts with administrator
rights — the accounts most valuable to an attacker, since compromising one
means full control of the machine. **Verify every account before disabling,
removing, or changing it** — an admin account you don't recognize might
still be one you (or another household/IT member) actually use; when in
doubt, ask before acting.

## Step 1: Disable the Guest account (critical)

Same underlying check as `win_user_accounts`, but flagged at CRITICAL here
because this module treats it in the context of privileged access exposure.

1. Confirm it: `net user Guest`.
2. Disable it from an elevated prompt: `net user Guest /active:no`.
3. Re-run the scan to confirm.

## Step 2: Disable the built-in Administrator account

The built-in Administrator account is a well-known target (fixed name, often
has broad rights) and Microsoft recommends keeping it disabled, using a
named administrator account instead for day-to-day elevated tasks.

1. Confirm it's enabled and check whether it's actively used for anything
   (some troubleshooting/recovery workflows expect it): `net user
   Administrator`.
2. If unused, disable it: `net user Administrator /active:no`.
3. Keep at least one other working administrator account available before
   disabling this one, so you don't lock yourself out of admin access
   entirely.
4. Re-run the scan to confirm.

## Step 3: Review accounts if more than 3 have admin rights

1. List them: `net localgroup Administrators`.
2. For each account beyond what's actually needed, confirm with whoever owns
   it whether admin rights are still required.
3. To downgrade an account from admin to standard user without deleting it,
   remove it from the Administrators group only: `net localgroup
   Administrators username /delete` (this removes group membership, not the
   account itself).
4. Re-run the scan to confirm the admin count is back to a reasonable
   number.

## Step 4: Set a password for any admin account with no password (critical)

An administrator account with no password is trivially exploitable by
anyone with local or network access to the login screen.

1. Confirm which account(s) are affected — the finding lists them.
2. Set a strong password immediately via Win+R, `compmgmt.msc` > Local Users
   and Groups > Users > right-click the account > "Set Password" > enter a
   strong password (12+ characters, mixed case, numbers, symbols).
3. Re-run the scan to confirm the finding clears.

## Step 5: Enable password expiration for admin accounts

1. Confirm which accounts are flagged.
2. Via the same Local Users and Groups panel, double-click the account and
   uncheck "Password never expires" — or with PowerShell: `Set-LocalUser
   -Name username -PasswordNeverExpires $false`.
3. Confirm the account owner is prepared to change their password
   periodically once expiration is enforced, so it doesn't lock them out
   unexpectedly.
4. Re-run the scan to confirm.

The admin-accounts-summary finding is informational — it lists every current
administrator with their enabled/password-required status for your review;
it doesn't require action beyond confirming the list looks right.
