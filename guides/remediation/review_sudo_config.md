---
title: "Review sudo configuration: NOPASSWD, timestamp timeout, Touch ID, root account"
estimated_time: "20 minutes"
platforms: [macos]
remediates:
  - security.sudo_config_audit.nopasswd_all
  - security.sudo_config_audit.nopasswd_partial
  - security.sudo_config_audit.timestamp_long
  - security.sudo_config_audit.timestamp_ok
  - security.sudo_config_audit.touchid_enabled
  - security.sudo_config_audit.touchid_disabled
  - security.sudo_config_audit.root_enabled
  - security.sudo_config_audit.root_disabled
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

This walkthrough covers everything `sudo_config_audit` can flag: NOPASSWD
entries in `/etc/sudoers`, the sudo authentication timestamp timeout, Touch
ID for sudo, and whether the root account is enabled. **Every edit here
touches the mechanism that grants administrative access on this Mac.** A
mistyped `/etc/sudoers` edit can lock every account out of `sudo`, so:

- Always edit sudoers with `sudo visudo` (never a plain text editor) — it
  syntax-checks the file before saving and refuses to save a broken file.
- Keep a second terminal window open with an active root/admin session
  while you make the change, so you can recover if something goes wrong.
- Never remove your own admin access without a tested fallback.

## Step 1: Remove `NOPASSWD ALL` (critical)

`NOPASSWD ALL` lets any user who can reach that sudoers rule run any command
as root with no password check at all.

1. Note the location from the finding (`/etc/sudoers` by default) and the
   flagged line(s).
2. Open a second terminal and confirm you have a working admin session
   before changing anything.
3. Run `sudo visudo` to edit safely.
4. Find and remove (or narrow) the line(s) containing `NOPASSWD: ALL`. If a
   specific command genuinely needs passwordless sudo (e.g. an automated
   script), replace `ALL` with the specific command path instead of
   removing the line entirely.
5. Save and let `visudo` validate the syntax — if it reports an error, fix
   it before saving; do not force-save invalid syntax.
6. From your second terminal, run a simple `sudo` command to confirm access
   still works as expected.

## Step 2: Review partial NOPASSWD entries

These allow specific commands to run without a password — narrower than
`NOPASSWD ALL`, but still worth reviewing.

1. Read the reported entries (`entries` field on the finding).
2. For each, confirm the command path is one you (or an automated process
   you trust) actually needs passwordless access to.
3. Remove entries covering commands that don't need frequent unattended
   use, again via `sudo visudo`.

## Step 3: Review the sudo timestamp timeout

A long timeout (over 30 minutes, per this module's threshold) means once you
authenticate with sudo, no further password prompt is needed for that
window — convenient, but a risk if your session is left unattended or
compromised during that time.

1. If `timestamp_long` was flagged: run `sudo visudo` and add or edit a line
   like `Defaults timestamp_timeout=5` (5-15 minutes is a reasonable
   balance).
2. If `timestamp_ok` was reported, no action is needed — the current value
   is already reasonable.
3. Verify with `sudo -v` after the timeout period lapses that a fresh sudo
   command prompts for a password again.

## Step 4: Touch ID for sudo, and the root account

Both are informational/optional — review and decide based on your own setup
rather than blindly enabling or disabling.

1. `touchid_disabled`: if this Mac has Touch ID hardware and you want the
   convenience, back up first: `sudo cp /etc/pam.d/sudo
   /etc/pam.d/sudo.bak`. Then edit `/etc/pam.d/sudo` and add `auth
   sufficient pam_tid.so` as the first `auth` line. Test in the same
   terminal session with a throwaway `sudo -k && sudo true` before closing
   any other sessions.
2. `touchid_enabled`: already configured — no action needed.
3. `root_enabled`: confirm you don't have a specific reason to keep the
   root account active (rare on modern macOS) before disabling it via
   Directory Utility (Edit > Disable Root User, after unlocking with your
   admin password). Confirm `sudo` access still works afterward — root
   being enabled/disabled is independent of sudo.
4. `root_disabled`: already the recommended state — no action needed.
