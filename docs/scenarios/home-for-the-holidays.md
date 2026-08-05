# Home for the holidays

**`home_for_the_holidays`** — 4 modules, a 1-phase, 13-step guide.

## Who this is for

You are the family's tech person, you are visiting, and you have one afternoon.
Somebody's laptop has been getting slower for two years, has no backups, reuses
one password everywhere, and nobody knows what to do if they get locked out.

This is the least alarming profile in the set and arguably the most useful one:
it is preventative, and it ends with a document that helps after you leave.

## What to run

```console
$ rescue --auto --profile home_for_the_holidays
$ rescue guide home_for_the_holidays
```

Budget about two hours for the guide. Mark steps off as you go so you can pick
it back up after dinner:

```console
$ rescue guide home_for_the_holidays --complete 3
```

## What the tool does

Four checks — this profile is deliberately light on scanning and heavy on the
checklist.

| Module | What it answers | Platforms |
| --- | --- | --- |
| `disk_space` | Is a filesystem running out of room | macOS, Windows, Linux |
| `disk_smart_check` | Is the drive reporting early failure signs | macOS |
| `malware_scan_indicators` | Known malware indicators on disk | macOS |
| `automatic_updates` | Are OS and app updates actually turning on | macOS |

`disk_space` is configured at `sensitivity: normal` here — this is a
maintenance visit, not an investigation, and a wall of warnings would make the
afternoon worse.

!!! info "Three of the four are macOS-only"
    On Windows or Linux you get `disk_space` and not much else from the modules.
    The 13-step guide is entirely platform-independent and is the substance of
    this profile — so the visit still works, you just do the storage-health and
    malware parts with the platform's own tools. If the machine is Linux,
    pair the visit with the
    [Linux security checkup](linux-security-checkup.md).

## What stays human-led

Twelve of the thirteen steps. That is the point: this is a profile about a
person doing maintenance with someone, not about a program doing it to them.

## The one phase, thirteen steps

**Phase 1 — The Family Device Checkup**, about two hours.

| # | Step | Who |
| ---: | --- | --- |
| 1 | Run a full device health check | **the tool** |
| 2 | Clear out old temp files and caches | you |
| 3 | Install pending OS and app updates | you |
| 4 | Set up a password manager | you |
| 5 | Migrate saved browser passwords | you |
| 6 | Enable two-factor authentication | you |
| 7 | Review logged-in devices and sessions | you |
| 8 | Set up automatic backups | you |
| 9 | Review social media privacy settings | you |
| 10 | Remove unused accounts and apps | you |
| 11 | Set a strong lock screen | you |
| 12 | Confirm disk encryption is enabled | you |
| 13 | Write the "Help Me" reference document | you |

**Step 13 is the one that matters most after you leave.** A short document,
kept somewhere they can find it, covering: how to get into the password
manager, where the backups are, what to do if the machine will not start, and
who to call. Most of the value of the visit evaporates without it — a password
manager nobody can get into is worse than no password manager.

**Steps 4–7 are the security core.** Password manager, migrate the browser's
saved passwords into it, 2FA on the important accounts, then sign out the
devices and sessions nobody recognises. Do them in that order; enabling 2FA
before there is somewhere safe to keep recovery codes creates a lockout waiting
to happen.

**Step 12 is worth insisting on.** Disk encryption is free, already built in,
and is the difference between a stolen laptop being an expensive inconvenience
and being an identity-theft event.

## What it will never ask you for

Nothing here needs a credential from them or from you. The tool does not want
their Apple ID, their email password, their bank login, or a 2FA code. Every
account step happens in their browser, on the provider's site, with them
driving — which is also better teaching. If you set up a password manager, its
master password is theirs, is typed into the password manager, and is never
seen by this tool.

Do not set up their accounts *for* them while they watch. The person who has to
use this in six months should be the one who set it up.

## Afterwards

```console
$ rescue export --profile home_for_the_holidays --output ~/family-laptop
```

A redacted case is a decent "here is what I checked and what I found" record to
leave alongside the Help Me document — or to compare against next year's visit.

If the checkup turns up something that looks like an actual compromise, stop and
switch to [digital security reset](digital-security-reset.md).
