---
title: "Review Windows user accounts, Guest access, and auto-login"
estimated_time: "15 minutes"
platforms: [windows]
remediates:
  - security.win_user_accounts.guest_account_enabled
  - security.win_user_accounts.auto_login_enabled
  - security.win_user_accounts.no_min_password_length
  - security.win_user_accounts.multiple_admin_accounts
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

`win_user_accounts` looks at account-level settings that affect who can get
onto this machine and how. Before disabling anything, confirm you (or
whoever uses this device) don't rely on the flagged behavior — auto-login in
particular is sometimes set up deliberately for convenience on a home PC and
disabling it changes daily behavior.

## Step 1: Disable the Guest account if enabled

The Guest account allows sign-in without a password, which is a broad
exposure for any machine that isn't strictly kiosk-mode.

1. Confirm it's actually enabled and check whether anyone uses it: `net user
   Guest`.
2. If unused, disable it from an elevated prompt: `net user Guest
   /active:no`.
3. Re-run the scan to confirm.

## Step 2: Review automatic login

Auto-login skips the password prompt entirely on boot — convenient, but it
means anyone who can power on the machine gets full access to that user's
account without a password.

1. Confirm which account auto-login is configured for — the finding names
   it.
2. Decide deliberately: if this is a shared or portable device, or the data
   on it matters, disable auto-login via Win+R, `netplwiz`, then check
   "Users must enter a user name and password to use this computer".
3. If this is a dedicated single-user home machine and you've made an
   informed choice to keep auto-login for convenience, that's a valid
   trade-off — just be aware physical access equals full account access.
4. Re-run the scan to confirm the current state matches your decision.

## Step 3: Set a minimum password length policy

1. Confirm current policy: `net accounts` (look for "Minimum password
   length" — 0 means unset).
2. Set one via Win+R, `gpedit.msc`, then Computer Configuration > Windows
   Settings > Security Settings > Account Policies > Password Policy >
   "Minimum password length" > at least 8 characters.
3. Re-run `net accounts` to confirm the new value applied.

## Step 4: Review accounts with admin privileges

Multiple admin accounts isn't inherently wrong (e.g. a household with
several members who each need to install software), but each one is an
additional target — worth confirming they're all still needed.

1. List them: `net localgroup Administrators`.
2. For each one, confirm it's an account someone still actively uses and
   genuinely needs administrator rights for.
3. For any account you don't recognize or that belongs to someone who no
   longer uses this machine, remove it from the Administrators group (not
   necessarily delete the account) via Win+R, `compmgmt.msc` > Local Users
   and Groups > Groups > Administrators > select the user > Remove — or
   downgrade it to a standard user rather than deleting outright unless
   you're certain the account itself should go.
4. Re-run the scan to confirm the reviewed list.
