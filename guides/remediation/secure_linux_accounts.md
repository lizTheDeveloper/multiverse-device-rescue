---
title: "Lock down accounts that have no password or too much power"
estimated_time: "20 minutes"
platforms: [linux]
remediates:
  - security.linux_account_audit.empty_password
  - security.linux_account_audit.extra_uid0_account
  - security.linux_account_audit.passwordless_sudo
  - security.linux_account_audit.admin_inventory
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

Every account on a computer is a door. An account with no password lets anyone
in. A second account with full administrator ("root") power lets someone keep
control of the computer even after you change your own password. Rules that let
a program run as administrator without asking for a password mean that anyone
who gets into your everyday session also gets full control.

**Before you remove or change anything:** if someone you know may be monitoring
you, removing an account they set up can alert that person. Talk to an advocate
first (US National DV Hotline: 1-800-799-7233, or text START to 88788). Don't
delete anything yet. Write down the account name and when you noticed it.

## Step 1: Work out which accounts are yours

Open **Settings > Users** (or **System Settings > Users & Groups**) and look at
the list. Optional, from a terminal: `cut -d: -f1 /etc/passwd` lists every
account name. Accounts you or your family set up are normal. Names you don't
recognise are worth a closer look, but many system names (like `daemon` or
`nobody`) are normal too.

## Step 2: Give every account you keep a password

Open **Settings > Users**, select the account, and set a password only you know.
For an account nobody should log in to, lock it instead. Optional, from a
terminal: `sudo passwd -l NAME`.

## Step 3: Deal with an extra administrator account

If a second account has root power (user ID 0) and you didn't create it, don't
log in as it and don't delete it. Talk to an advocate or someone you trust who
knows Linux, as the note above says. A computer with an unexplained root
account has been changed by someone with full access, so the safest course is
to back up your files and reinstall.

## Step 4: Remove "no password needed" administrator rules

If the finding names a rule that lets a user run commands as administrator
without a password: unless you know a program needs it, ask a trusted
technically minded person to open the sudo settings with `sudo visudo` and
remove the `NOPASSWD` part. Don't edit that file any other way, because a
mistake can lock you out.
