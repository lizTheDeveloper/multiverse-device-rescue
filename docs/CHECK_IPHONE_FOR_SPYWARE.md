# Check an iPhone or iPad for spyware

This guide walks you through scanning an iPhone or iPad for known spyware
(like Pegasus or Predator) using the `rescue` tool. It's written to be
followed step by step — you do **not** need to be technical.

Everything runs **on your own computer**. Nothing is uploaded anywhere.

---

## What this does (and doesn't) do

- It looks at a **backup** of your iPhone/iPad that lives on your computer and
  checks it against a public list of known spyware fingerprints.
- **A clean result does not prove the phone is safe.** It only means none of
  the *known, published* spyware fingerprints were found. Brand-new or custom
  spyware won't show up. If you have real reason to think you're targeted, get
  expert help (see the end of this guide).

---

## Before you start: two one-time setup steps

### 1. Make a backup of the phone onto this computer

1. Plug the iPhone/iPad into your Mac with a cable.
2. Open **Finder**. Your phone appears in the left sidebar — click it.
3. Choose **"Back up all the data on your iPhone to this Mac"**, then click
   **Back up now**.
4. Wait for it to finish. (An encrypted backup is fine and recommended.)

> On older macOS or on Windows, you do this in **iTunes** instead of Finder:
> Device → **Back Up Now**.

### 2. Install the scanner (MVT)

The scan uses a free, open-source tool called **MVT** (Mobile Verification
Toolkit), made by Amnesty International. Install it once by opening the
**Terminal** app and pasting this line, then pressing Return:

```
pip install mvt
```

If that command isn't found, you may need Python first (`python.org/downloads`),
then run the line above again. On a Mac you also need `libimobiledevice`
(`brew install libimobiledevice`) so MVT can read the backup.

You'll know it worked if this prints a version number:

```
mvt-ios version
```

---

## Run the scan

Open **Terminal** and run this **one line**:

```
rescue --auto --profile iphone_spyware_check
```

That's it. The tool finds your backup, scans it, and prints a plain-language
result. A scan can take a few minutes depending on how big the backup is.

---

## Reading the result

- **"No spyware indicators detected"** — nothing from the known-spyware list was
  found. (Remember the caveat above: this is reassuring, not a guarantee.)
- **"Spyware indicator detected"** (shown in red/critical) — the scan matched a
  known spyware fingerprint. **Do not panic and do not wipe the phone yet.**
  Skip to *If something is found* below.
- **"This backup is encrypted"** — MVT can't read an encrypted backup until
  it's unlocked with the backup password. See *Scanning an encrypted backup*
  below. Nothing was checked, so this is not a clean result.
- **"The spyware scan didn't finish"** — the scanner stopped before the end.
  Nothing was confirmed, so this is not a clean result. Run it by hand (below)
  to see what happened.
- **"MVT is not installed"** — go back and do setup step 2.
- **"No device backups found"** — go back and do setup step 1.

---

## Large backups

Backups of any size are scanned. A full iPhone backup is often tens of GB, and
the scan can take a while: let it run. If the scan stops before the end, the
result says **"didn't finish"**, never "clean".

To see the scan's own progress and errors, run it by hand (the path is in the
result message):

```
mvt-ios check-backup --output ~/mvt-results "<path-to-your-backup>"
```

Then look in the `~/mvt-results` folder: any file whose name contains
`_detected` means something was found.

On a computer that's very short on memory you can skip big backups instead:
set `max_backup_bytes` in `profiles/iphone_spyware_check.yaml` to a size in
bytes (2 GB = 2147483648). The default, `0`, means no limit.

## Scanning an encrypted backup

An encrypted backup (the **Encrypt local backup** box in Finder) is the right
choice for your phone's data, but MVT has to unlock it before it can check it.

1. Make an unlocked copy. It asks for the backup password you chose in Finder:

   ```
   mvt-ios decrypt-backup -d ~/iphone-backup-decrypted "<path-to-your-backup>"
   ```

2. Scan the copy:

   ```
   mvt-ios check-backup --output ~/mvt-results ~/iphone-backup-decrypted
   ```

3. **Delete `~/iphone-backup-decrypted` when you're done.** It holds your
   messages and photos without the password's protection.

---

## If something is found

1. **Don't wipe the phone yet** — the backup is evidence. Keep an unchanged copy.
2. **Get expert help.** Amnesty International's Security Lab helps people who may
   be targeted by this kind of spyware, for free:
   <https://securitylab.amnesty.org/get-help/>
3. When you're ready to clean the device, the tool's guidance (shown after the
   scan) walks through it: back up only your essential personal files, factory
   reset the phone, update to the latest iOS, and turn on **Lockdown Mode**.

---

## Why is this scan separate from the normal checkup?

The everyday checkup —

```
rescue --auto
```

— is deliberately quick and light so it's always safe to run. The spyware
backup scan is heavier (it reads through your whole phone backup), so it's kept
as its own opt-in command. That way the normal checkup can never accidentally
tie up your computer.
