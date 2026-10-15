---
title: "Make remote login (SSH) safer"
estimated_time: "20 minutes"
platforms: [linux]
remediates:
  - security.linux_ssh_hardening.root_login_permitted
  - security.linux_ssh_hardening.password_auth_enabled
  - security.linux_ssh_hardening.empty_passwords_permitted
  - security.linux_ssh_hardening.listening_on_all_interfaces
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

SSH lets someone log in to this computer over the network and run commands.
Automated programs try to guess passwords on every computer they can reach,
all day. If your settings let the administrator account log in directly, or
accept passwords, or accept accounts with no password, guessing can eventually
work and whoever gets in has full control.

**Before you change anything:** if you didn't turn SSH on yourself, ask why it
is running. Switching off remote access someone else set up can alert them. If
someone you know may be monitoring you, talk to an advocate first (US National
DV Hotline: 1-800-799-7233, or text START to 88788).

## Step 1: Decide whether you need SSH at all

If you never log in to this computer from another one, turn SSH off. Optional,
from a terminal: `sudo systemctl disable --now ssh` (the service may be called
`sshd` on your system). If you do use it, carry on with the steps below.

## Step 2: Set up key login before turning passwords off

Make sure you can log in with an SSH key first, from the computer you use.
Otherwise you could lock yourself out. If you need help with keys, search for
"ssh-keygen and ssh-copy-id" together with your distribution's name.

## Step 3: Edit the SSH settings

Ask a technical helper if you aren't comfortable editing system files. Open
`/etc/ssh/sshd_config` as administrator and set:

- `PermitRootLogin no`
- `PasswordAuthentication no`
- `PermitEmptyPasswords no`

Save the file, then restart SSH: `sudo systemctl restart ssh` (or `sshd`).

## Step 4: Keep it off public networks

If you only use SSH at home, add `ListenAddress` with your home address in the
same file, or block SSH from other networks in your firewall. Then check that
you can still log in before you close your current session.
