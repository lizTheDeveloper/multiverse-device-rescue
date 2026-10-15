---
title: "Install pending security updates and restart"
estimated_time: "20 minutes"
platforms: [linux]
remediates:
  - integrity.linux_package_updates.security_updates_pending
  - integrity.linux_package_updates.reboot_required
  - integrity.linux_package_updates.updates_pending
  - integrity.linux_package_updates.release_end_of_life
automatable_steps: []
human_only_steps: [1, 2, 3]
---

Security updates fix holes that have already been made public, so anyone who
writes attack software knows about them. Until you install the updates, your
computer has holes that people know how to use. Updates that are installed but
waiting for a restart aren't protecting you yet either.

## Step 1: Install the updates

Open **Software Updater** (Ubuntu and Mint), or **Software** or **Discover**
(Fedora, KDE and others), and install everything it offers. Security updates
matter most, but installing all of them is fine.

Optional, from a terminal:

- Ubuntu, Debian, Mint: `sudo apt update && sudo apt upgrade`
- Fedora: `sudo dnf upgrade`

## Step 2: Restart the computer

Restart so the new versions are actually in use. Save your work first.

## Step 3: Check that your Linux version is still supported

Every release stops receiving security updates on a set date. Look up your
version on your distribution's website (for Ubuntu, search "Ubuntu release
cycle"). If yours has ended, upgrade to the current release. A computer on an
unsupported version shows no pending updates because none are being made, which
is exactly why it's easy to miss.
