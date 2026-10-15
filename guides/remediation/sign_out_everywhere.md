---
title: "Sign out of other devices and cut off old access"
estimated_time: "30 minutes"
platforms: [macos, windows]
remediates:
  - security.session_revocation_scan.browser_sessions
  - security.session_revocation_scan.system_accounts
  - security.session_revocation_scan.ssh_authorized_keys
steps_for:
  security.session_revocation_scan.browser_sessions: [1, 3]
  security.session_revocation_scan.system_accounts: [2]
  security.session_revocation_scan.ssh_authorized_keys: [4]
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

When you sign in to an account, the website remembers you in your browser so
you don't have to sign in each time. That memory stays valid after you change
your password. So if someone else once used your browser, or got a copy of its
saved sign-ins, changing your password alone won't kick them out. Signing out
everywhere does.

**Before you remove any account or device:** if someone you know may be
monitoring you, removing access they use can alert that person. Talk to an
advocate first (US National DV Hotline: 1-800-799-7233, or text START to 88788).
Change passwords from a device they have never had access to.

## Step 1: Sign out of all devices on your main accounts

Do this on your email first, then banking, then social media. On each site,
open its **Security** or **Account** settings and look for **Sign out of all
devices**, **Where you're signed in**, or **Your devices**. Sign out of anything you don't
recognise or no longer use. Google, Apple, Microsoft, Facebook and most banks
have this.

## Step 2: Check the accounts saved on this computer

- **Mac:** **System Settings > Internet Accounts**.
- **Windows:** **Settings > Accounts > Email & accounts**, and
  **Settings > Accounts > Access work or school**.

Remove any account you don't recognise or no longer use. Read the note above
first.

## Step 3: Clean up unused browser profiles

Each browser profile keeps its own sign-ins. Remove profiles you don't use from
your browser's profile menu (the picture near the top right in Chrome, or
Firefox's account menu), and sign out of the ones you keep, then sign in again.

## Step 4: Check which computers can log in to this one remotely

If the finding mentions authorised SSH keys, each one is a separate way in that
a password change doesn't affect. Unless you set those up yourself or know what
they're for, ask a technical helper to review `~/.ssh/authorized_keys` with
you. Don't delete lines on your own if you are unsure; each line is one allowed
computer.
