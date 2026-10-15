---
title: "Give your passwords one safe home"
estimated_time: "20 minutes"
platforms: [macos, windows]
remediates:
  - security.password_manager_check.no_password_manager
  - security.password_manager_check.browser_stored_passwords
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

A password manager makes a different strong password for every account and
remembers them for you, so one leaked password can't unlock everything else.
You only have to remember one password: the one for your computer or the
manager itself.

## Step 1: Pick one place for your passwords

- **Mac, iPhone and iPad only:** use the **Passwords** app. It's already
  installed and free. Open it from Launchpad or Spotlight (press Command +
  Space and type "Passwords").
- **Windows, Android, or a mix of devices:** install **Bitwarden** (free) or
  **1Password** (paid). Download it only from the maker's own website
  (bitwarden.com, 1password.com) or your device's app store, never from an ad.

Pick one. Having passwords in several places is how they get lost or reused.

## Step 2: Protect the password manager itself

1. If you installed Bitwarden or 1Password, choose a long main password you
   have never used anywhere else. Four or five random words is good, like
   "lamp river orange pocket".
2. Write it on paper and keep it somewhere safe at home until you know it by
   heart.
3. Turn on two-step sign-in in the manager's settings.

The Passwords app on a Mac is protected by your Mac login, so make sure that
is a password only you know.

## Step 3: Bring in the passwords your browsers saved

Each browser can export its saved passwords so the manager can import them.

- **Safari:** saved passwords already live in the Passwords app.
- **Chrome, Brave or Edge:** open the browser's password settings (in the
  address bar, type `chrome://password-manager/settings`, or
  `brave://password-manager/settings`, or `edge://wallet/passwords`) and
  choose **Export passwords**. Then use **Import** in your password manager
  and pick that file.
- **Firefox:** Settings > Passwords > the "⋯" menu > Export Passwords.

The exported file holds every password in plain text. As soon as the import
finishes, delete the file and empty the Trash.

## Step 4: Turn off password saving in the other browsers

So new passwords don't end up scattered again:

- **Chrome / Brave / Edge:** in the password settings, turn off "Offer to save
  passwords".
- **Firefox:** Settings > Passwords > untick "Ask to save passwords".

Then, as you change passwords, let the manager make a new random one each
time and save it.

## If you're doing this after a break-in

Set the manager up **before** changing passwords, then change them in this
order: your email first, then banking, then everything else. If you think
someone you know is monitoring this computer, set it up on a device they have
never had access to.
