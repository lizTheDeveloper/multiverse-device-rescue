---
title: "Harden SSH keys and configuration"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.ssh_key_audit.dsa_key_found
  - security.ssh_key_audit.weak_rsa_key
  - security.ssh_key_audit.bad_ssh_dir_perms
  - security.ssh_key_audit.bad_key_perms
  - security.ssh_key_audit.permit_root_login
  - security.ssh_key_audit.password_auth_enabled
  - security.ssh_key_audit.authorized_keys
  - security.ssh_key_audit.known_hosts
  - security.ssh_key_audit.ssh_agent_running
  - security.ssh_key_audit.ssh_agent_not_running
  - security.ssh_key_audit.ed25519_keys
  - security.ssh_key_audit.rsa_keys
automatable_steps: []
human_only_steps: [1, 2, 3, 4, 5, 6]
---

This walkthrough covers everything the `ssh_key_audit` module can flag: weak
or broken key material, incorrect file permissions, risky `sshd_config`
settings, and general inventory items worth reviewing (`authorized_keys`,
`known_hosts`, the running SSH agent, and your existing Ed25519/RSA keys).
Key regeneration and `sshd_config` edits are all human-only — they touch
credentials and a service you may currently be relying on to reach this
machine remotely, so nothing here is auto-applied.

## Step 1: Regenerate DSA keys (critical)

DSA is cryptographically broken and should not be used for anything.

1. Identify the flagged key file(s) under `~/.ssh/` (the scan reports the
   filename).
2. Generate a replacement Ed25519 key:
   `ssh-keygen -t ed25519 -f ~/.ssh/id_ed25519 -N ''` (add a passphrase
   instead of `-N ''` if you want the key protected at rest — recommended
   for laptops).
3. Add the new public key (`~/.ssh/id_ed25519.pub`) to every server/service
   that trusted the old DSA key, then confirm you can log in with the new
   key before removing the old one.
4. Once confirmed, remove the old DSA private and public key files and
   remove the corresponding entry from `~/.ssh/config` if one references it
   by name.

## Step 2: Regenerate weak RSA keys

RSA keys under 2048 bits are considered weak.

1. Note the flagged key filename and bit size from the finding.
2. Generate a stronger replacement — either Ed25519 (`ssh-keygen -t ed25519
   -f ~/.ssh/id_ed25519_new -N ''`) or RSA with at least 4096 bits
   (`ssh-keygen -t rsa -b 4096 -f ~/.ssh/id_rsa_new -N ''`).
3. Distribute the new public key to servers/services that trusted the old
   one, confirm login works, then remove the old weak key.

## Step 3: Fix SSH directory and private key permissions

Overly permissive modes on `~/.ssh/` or its key files let other local
accounts (or a compromised process) read your private keys.

1. If `~/.ssh` itself was flagged: `chmod 700 ~/.ssh`.
2. For each flagged private key file: `chmod 600 <path-to-key>`.
3. Re-run the scan to confirm both report as fixed.

## Step 4: Review sshd_config for risky remote-login settings

These findings only apply if this Mac runs `sshd` (i.e. Remote Login is
enabled — see `disable_unwanted_remote_access.md` if you don't need inbound
SSH at all). If you do need inbound SSH, tighten it:

1. Back up the file first: `sudo cp /etc/ssh/sshd_config
   /etc/ssh/sshd_config.bak`.
2. If `permit_root_login` was flagged, edit `/etc/ssh/sshd_config` and set
   `PermitRootLogin no` (or `prohibit-password` if you specifically need
   scripted root access via key only).
3. If `password_auth_enabled` was flagged, set `PasswordAuthentication no`
   so only key-based auth is accepted — do this only after confirming you
   have a working key-based login, so you don't lock yourself out.
4. Validate the edited file before reloading: `sudo sshd -t`. Fix any syntax
   errors it reports.
5. Apply the change: `sudo launchctl restart com.openssh.sshd` (or
   `sudo launchctl kickstart -k system/com.openssh.sshd` on newer macOS).
6. From a **separate terminal window** (keep your current session open),
   test a fresh SSH login before closing the original session — this way
   you can revert from `sshd_config.bak` if something is wrong.

## Step 5: Review authorized_keys and known_hosts entries

These are informational inventory findings — nothing is inherently wrong,
but stale entries are worth pruning.

1. Open `~/.ssh/authorized_keys` and confirm every entry corresponds to a
   device/person you still want to have SSH access to this account. Remove
   lines for anything you don't recognize or no longer trust, keeping a
   backup copy first (`cp ~/.ssh/authorized_keys
   ~/.ssh/authorized_keys.bak`).
2. Open `~/.ssh/known_hosts` and remove entries for hosts you no longer
   connect to, especially any that correspond to servers you've
   decommissioned (stale entries are low risk but bloat the file and can
   mask host-key-change warnings for reused IPs).

## Step 6: Review SSH agent state and key inventory

Informational — confirms what's currently loaded and what keys you have.

1. If the scan reported the agent as **not running** and you rely on
   agent-forwarding or frequent key use, start it:
   `eval $(ssh-agent -s)` then `ssh-add ~/.ssh/id_ed25519` (or your key of
   choice).
2. If the agent **is running**, run `ssh-add -l` yourself and confirm every
   loaded key is one you expect — remove any surprise entries with
   `ssh-add -d <key>`.
3. Review the reported inventory of Ed25519/RSA keys and confirm you still
   need each one; delete key pairs you no longer use (after confirming
   nothing still authenticates with them).
