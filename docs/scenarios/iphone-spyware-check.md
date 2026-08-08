# iPhone / iPad spyware check

**`iphone_spyware_check`** — 1 module, no guide (but there *is* a
[plain-language walkthrough](../CHECK_IPHONE_FOR_SPYWARE.md)).

## Who this is for

You think there may be mercenary spyware — Pegasus, Predator, or similar — on
your iPhone or iPad. This profile scans a **backup of that device that already
exists on your computer**, using Amnesty International's Mobile Verification
Toolkit (MVT).

This is the tool's only real mobile capability. There are no modules that talk
to a phone directly; everything else mobile in this project is human-guided.

!!! info "Start with the walkthrough, not this page"
    [Check an iPhone or iPad for spyware](../CHECK_IPHONE_FOR_SPYWARE.md) is
    written to be followed step by step by someone non-technical, including how
    to make the backup in the first place. This page is the reference for what
    the profile does.

## What to run

```console
$ rescue --auto --profile iphone_spyware_check
```

You need a local backup of the device on the computer you are running this on
(made through Finder on macOS, or iTunes / Apple Devices on Windows). Nothing
is uploaded anywhere; the scan happens entirely on your computer.

There is **no guide for this profile** — `rescue guide iphone_spyware_check`
reports `No guide content found`. Use the walkthrough linked above.

## What the tool does

One module, `mvt_spyware_scan`, on macOS, Windows, or Linux.

It is worth understanding why this profile exists at all when the module is
available everywhere. From the profile's own description:

> This is the one profile that actually **RUNS** the backup scan — every other
> scan only reports that a scan is available, because scanning a backup is a
> heavy operation.

So `mvt_spyware_scan` appearing in a general `rescue scan` will tell you a scan
is possible; only this profile turns it on, through `module_config`:

```yaml
module_config:
  mvt_spyware_scan:
    scan_backups: true
    max_backup_bytes: 2147483648   # 2 GB
```

**The 2 GB limit is a safety measure, not a capability limit.** Backups larger
than that are *skipped rather than scanned*, because scanning a very large
backup can use a lot of memory. Raising `max_backup_bytes` lets bigger backups
through — only do that on a computer with plenty of free memory.

The module's declared duration reflects this: *"instant by default; 1–10m if
backup scanning is enabled"*. It is `RiskLevel.SAFE` and reads the backup; it
does not modify it.

## What stays human-led

- **Making the backup.** Encrypted local backups contain more of the artifacts
  MVT looks at; the walkthrough covers this.
- **Interpreting a detection.** MVT indicators are exactly that — indicators.
  A hit is a reason to get expert help, not a verdict.
- **What to do if something is found.** Do not factory-reset immediately; that
  destroys the evidence someone qualified would need. Amnesty's Security Lab
  and Access Now's Digital Security Helpline
  (<https://www.accessnow.org/help/>) work with people in exactly this
  situation, for free.
- **Everything on the phone itself.** Passcodes, Apple ID, Lockdown Mode,
  updates. This tool does not touch the device.

!!! danger "If you are a journalist, activist, lawyer, or dissident"
    Mercenary spyware is targeted, expensive, and used against specific people.
    If you have reason to think you are a target, contact Access Now's Digital
    Security Helpline or Amnesty's Security Lab **before** changing anything on
    the device. Preserving the backup matters more than cleaning the phone.

## What it will never ask you for

Your Apple ID password, your device passcode, your backup encryption password,
or any two-factor code. The module reads a backup that already exists on disk.
If a backup is encrypted and cannot be read, you will be told that — you will
not be asked to type the password into this tool.

## Afterwards

```console
$ rescue export --profile iphone_spyware_check
```

If you are handing findings to a helpline or a security researcher, send the
redacted Markdown case and say which device and which backup it refers to.
Keep the backup itself; do not delete it.
