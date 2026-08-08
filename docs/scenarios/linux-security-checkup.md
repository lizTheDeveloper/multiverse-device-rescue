# Linux security checkup

**`linux_security_checkup`** — 10 modules, no guide.

## Who this is for

Anyone with a Linux desktop, laptop, or small server who wants a read-only
security and health review in one command. You do not need to suspect anything;
this is the checkup, not the emergency.

It is also the single entry point for the Linux modules. Linux support in this
tool used to be thin — 26 of the 287 modules run there — and this profile is
where nine of the newest ones live together.

From the profile's own description, the questions it answers:

> Is anything filtering inbound traffic, can anyone log in over SSH with a
> password, who on this machine can become root, is the disk encrypted if it is
> lost or stolen, is anything arranged to run at every boot that you do not
> recognise, are there published security fixes waiting to be installed, and is
> the hardware reporting the early warnings that precede a drive or memory
> failure.

## What to run

```console
$ rescue --auto --profile linux_security_checkup
```

There is **no guide for this profile** — `rescue guide linux_security_checkup`
reports `No guide content found`. Unlike the four scenario profiles that carry
phased walkthroughs, this one is scan-only, and every module tells you the
exact command to fix what it found. Findings carry codes that map into the
[remediation catalog](../REMEDIATION_CATALOG.md).

Run it unprivileged first. Some checks (firewall rulesets in particular) can
read more as root — but the design rule here is that a check without privileges
**says so** rather than reporting a clean result. Elevate only for the gaps:

```console
$ sudo -E $(which rescue) --auto --profile linux_security_checkup
```

## The order is the argument

The include list is sequenced, and the comments in the YAML explain why. It is
not alphabetical and it is not by module size — it is by what an attacker needs
in the order they need it.

1. **Exposure first — what can reach this machine, and who can log in to it.**
   `linux_firewall_check`, `linux_ssh_hardening`, `linux_account_audit`. Nothing
   else matters if the front door is open, and this is the group where a real
   misconfiguration is most likely.
2. **Then what happens if the machine itself is taken.**
   `linux_disk_encryption_check`. A different threat entirely — a screwdriver,
   not a network — and one that no amount of firewall helps with.
3. **Then what is arranged to run again, which is where persistence lives.**
   `linux_persistence_audit`. Survival across reboots is malware's first job
   after landing, so this is where you look for something that already got in.
4. **Then the patch level, which is what most real compromises actually use.**
   `linux_package_updates`. Unglamorous and statistically the most likely way
   in.
5. **Then health: services that have failed, and hardware asking for help.**
   `linux_service_health`, `linux_journal_errors`, `linux_memory_pressure`,
   `disk_space`. A machine that is failing is a machine you cannot trust to
   report on itself, and a full disk breaks logging — which is how you lose the
   evidence of everything above.

## What the tool does

| Module | What it answers | Duration |
| --- | --- | --- |
| `linux_firewall_check` | Is anything actually filtering inbound traffic (ufw, firewalld, nftables, iptables) | 10s |
| `linux_ssh_hardening` | The effective SSH server configuration, and the settings that turn a key-only server into a password one | 10s |
| `linux_account_audit` | Who can log in, and who can become root | 10s |
| `linux_disk_encryption_check` | Is the data encrypted at rest | 15s |
| `linux_persistence_audit` | Every place something can arrange to run again — systemd, cron, XDG autostart, shell rc files, `ld.so.preload` | 20s |
| `linux_package_updates` | Are security updates waiting, and is this release still getting them | 45s |
| `linux_service_health` | What systemd has given up on, and what keeps dying and restarting | 20s |
| `linux_journal_errors` | The journal errors that predict hardware failure | 30s |
| `linux_memory_pressure` | Memory, swap, and the kernel's own pressure signals | 5s |
| `disk_space` | Filesystems running out of room | 5s |

All ten are `RiskLevel.SAFE`, all are Linux-only except `disk_space`, and the
whole profile takes about three minutes.

Two design notes worth knowing before you read the output:

**"Could not determine" is a real answer.** `linux_firewall_check` asks all four
front-ends in turn, because a machine can have all four installed while none is
filtering — and checking only one produces a confident, wrong answer. An
unreadable ruleset is reported as *could not determine*, never as *no firewall*.

**The persistence inventory is mostly `[info]` on purpose.** Almost everything
it finds is legitimate: a user systemd unit is how Syncthing starts, `~/.profile`
sets `PATH` on every machine ever. Flagging those as malware would be a
false-positive machine. Only structural properties escalate — a unit that pipes
the network into a shell, an autostart entry pointing at `/tmp`, a
world-writable unit file. The inventory exists so *you* can notice the one entry
you do not recognise, which is the only detection mechanism that works against
something novel.

## Real output

From a live run on an Ubuntu 24.04 machine:

```console
$ rescue --auto --profile linux_security_checkup
==================================================
Multiverse Device Rescue — Auto Mode
Profile: Linux Security Checkup
==================================================

Scanned 10 module(s), found 12 issue(s). Auto mode is read-only: made 0 system
change(s); 0 manual action(s) require you.

=== linux_firewall_check ===
Found 1 issue(s):
  [warning] A firewall is installed but not active: Found nftables, iptables,
  but none of them is currently filtering. Installed and running are different
  things; an inactive firewall protects nothing.

=== linux_account_audit ===
Found 2 issue(s):
  [warning] claude can run commands as root without a password: /etc/sudoers
  contains a NOPASSWD rule for claude.

  This is convenient and it is also the difference between 'someone got into
  your user session' and 'someone got root'. Automation on a server sometimes
  needs it; a desktop rarely does. If it is needed, scope it to specific
  commands rather than ALL.
  [info] 2 account(s) can log in to this machine: Accounts that can log in:
  root, ubuntu

  Administrative group membership:
    sudo: ubuntu

  Look for a name you do not recognise. That is the whole point of this list;
  there is nothing wrong with any of these entries by default.

=== linux_disk_encryption_check ===
Found 1 issue(s):
  [warning] / is not encrypted: /dev/vda mounted at / is stored unencrypted.

  Everything on this machine — saved passwords, browser sessions, SSH keys,
  documents — can be read by anyone who gets the drive out of it. That takes a
  screwdriver and a few minutes; your login password is not involved.

=== linux_persistence_audit ===
Found 1 issue(s):
  [info] 7 startup entries inventoried: Every place something can arrange to
  run again on this machine, listed so you can look for the one you do not
  recognise. Most entries here are ordinary software.

  cron job (4):
    /etc/cron.d/e2scrub_all
    /etc/cron.d/php
    /etc/cron.daily/apt-compat
    /etc/cron.daily/dpkg
  shell startup file (3):
    /root/.bashrc
    /root/.profile
    /root/.zshrc

=== linux_service_health ===
Found 1 issue(s):
  [warning] No time-synchronisation service appears to be running: Nothing on
  this machine is keeping the clock correct. A drifted clock breaks HTTPS
  certificate validation, two-factor codes, and scheduled jobs.

  Checked for: systemd-timesyncd, chronyd, ntpd, ntpsec
```

Twelve findings, zero changes. Note the shape of a good result here: four
`[warning]` items that each name a specific thing to do, and inventories that
ask you to look rather than telling you to panic.

## What stays human-led

Everything. This profile changes nothing and proposes nothing automatically —
each module reports what it found and, where there is something to do, gives
you the exact command to run yourself.

- Enabling and configuring the firewall.
- Editing `sshd_config` and restarting the service.
- Scoping or removing a `NOPASSWD` sudo rule.
- Enabling full-disk encryption (which on an existing install generally means a
  reinstall — worth planning, not worth rushing).
- Investigating a startup entry you do not recognise.
- Installing the pending updates, and upgrading a release that is past its
  end-of-life.
- Replacing a drive whose journal is warning about it.

## What it will never ask you for

Your login password, your sudo password, your SSH passphrase, or any account
credential. `linux_ssh_hardening` reads the *effective server configuration*;
`linux_account_audit` reads account and sudoers *metadata*. Neither reads
private key material or password hashes out to you. If you choose to run under
`sudo`, `sudo` itself prompts — the tool never sees what you type.

## Afterwards

```console
$ rescue export --profile linux_security_checkup
```

Writes a redacted case to `~/.rescue/cases/`. Note that under `sudo` that
resolves to `/root/.rescue/cases/` — use `--output` if you want it elsewhere.

If the checkup turned up something that looks like an active compromise rather
than a misconfiguration, switch to
[digital security reset](digital-security-reset.md) or, if it came in through a
package, [AI worm response](ai-worm-response.md).
