# Android spyware check

**`android_spyware_check`**: 1 module, no guide (but there *is* a
[plain-language walkthrough](../CHECK_ANDROID_FOR_SPYWARE.md)).

## Who this is for

You think there may be stalkerware or mercenary spyware on an Android phone.
This profile scans an **AndroidQF acquisition that already exists on your
computer**, using Amnesty International's Mobile Verification Toolkit (MVT).
MVT's downloadable lists include Echap's stalkerware indicators as well as
Pegasus, Predator and other mercenary spyware.

!!! info "Start with the walkthrough, not this page"
    [Check an Android phone for spyware](../CHECK_ANDROID_FOR_SPYWARE.md) is
    written to be followed step by step, including turning on USB debugging
    and running AndroidQF. This page is the reference for what the profile
    does.

!!! warning "Consent"
    AndroidQF and MVT are licensed for use only with the explicit consent of
    the person whose data is being checked. Check your own phone, or a phone
    whose owner asked you to.

## What to run

```console
$ rescue --auto --profile android_spyware_check
```

Before that, three things have to exist on the computer:

1. **MVT**: `pip install mvt`.
2. **MVT's indicator lists**: `mvt-android download-iocs`, once. Without them
   MVT matches nothing, so the module reports `mvt_no_indicators` and doesn't
   scan, rather than reading as clean.
3. **An AndroidQF acquisition**: a `<UUID>.zip` (AndroidQF 1.8 and later) or
   `<UUID>/` folder (older versions) in the home folder, `~/Downloads`,
   `~/Desktop`, `~/Documents`, `~/androidqf`, or a `~/Downloads/androidqf*`
   folder. A zip is only counted if it contains `acquisition.json`,
   `packages.json` or `getprop.txt`.

macOS and Linux. On Windows the module reports `mvt_requires_wsl`.

## What the tool does

One module, `mvt_spyware_scan`, with `look_for: android`:

```yaml
module_config:
  mvt_spyware_scan:
    scan_backups: true
    look_for: android
    max_backup_bytes: 0   # no size limit
```

For each acquisition it runs `mvt-android check-androidqf --non-interactive`.
AndroidQF 1.8+ writes its files at the top of the zip, but MVT's AndroidQF
modules look for them one folder down (`*/packages.json`), so a zip passed to
MVT as-is is checked against almost nothing. The module unpacks it into a
private temporary folder named after the acquisition, scans that, and deletes
it.

It reads MVT's `alerts.json`:

| MVT alert | Finding |
| --- | --- |
| Any match against a downloaded indicator list | `mvt_spyware_detected`, critical, naming the list (for example *Stalkerware Indicators of Compromise*) |
| HIGH or CRITICAL heuristic (no list match), such as root binaries | `mvt_suspicious_signal`, warning, one per MVT module |
| MEDIUM heuristics, such as sideloaded apps or an old security patch | one `mvt_suspicious_signal` info note listing them |
| LOW and INFORMATIONAL | dropped |

A run that exits non-zero or times out is `mvt_scan_incomplete`, and an
age-encrypted `.zip.age` acquisition is `mvt_backup_encrypted`. Neither counts
toward `mvt_clean_scan`.

## What stays human-led

- **Making the acquisition.** USB debugging, AndroidQF, and answering its
  prompts. The walkthrough covers this.
- **Interpreting a detection.** Indicators are reasons to get help, not
  verdicts.
- **Removing anything.** If someone close to the person installed it, removing
  it can alert them. Advocate first.
- **Turning USB debugging and Developer options off afterwards.**

## What it will never ask you for

Your Google account password, your phone's PIN, or any code. It reads a file
that already exists on disk.
