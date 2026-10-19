# USB Rescue Stick

A rescue stick is a USB drive with the Reclaim City desktop app on it, for
Mac (Apple chip and Intel) and Windows. You build it on your machine and hand
it to someone, or keep one in your bag for the next time someone asks for help.
The person plugs it in, opens `START-HERE`, and installs the app. They don't
need an internet connection.

The stick holds the **released** installers, the same files as the download
buttons in the [README](https://github.com/lizTheDeveloper/multiverse-device-rescue#download).
The build script downloads them from GitHub Releases and checks each one
against the release's `SHA256SUMS.txt` before it puts anything on the stick.

## What's on the stick

```
(the drive)
├── START-HERE.html              ← open in any browser; same as the .txt, easier to read
├── START-HERE.txt               ← which file to open, the first-open warning, the safety note
├── For Mac with Apple chip/
│   └── ReclaimCity-mac-arm64.dmg
├── For Mac with Intel/
│   └── ReclaimCity-mac-x64.dmg
├── For Windows/
│   └── ReclaimCity-windows-x64.exe
├── For helpers/
│   ├── SHA256SUMS.txt           ← the release's checksum file, unchanged
│   └── CHECKSUMS.txt            ← how to re-check the installers on Mac or Windows
├── guides/
│   ├── index.html               ← step-by-step walkthroughs, offline
│   └── quick-reference.txt      ← one-page card to print and put in the bag
├── tools/                       ← only if the school repo was found (see below)
│   └── index.html
└── command-line/                ← only with --with-cli
```

`START-HERE` tells the person, in plain words:

- how to tell which Mac they have (Apple menu → **About This Mac**: "Chip:
  Apple M…" or "Processor: … Intel"), and which folder to open
- what to do about the first-open warning, using the same wording as the app
  (`shared/permissions-content.json`): **System Settings → Privacy & Security
  → Open Anyway** on a Mac, **More info → Run anyway** on Windows
- that the app only looks, and changes nothing unless they say yes
- the safety note for anyone who may be monitored: removing monitoring
  software can alert the person who installed it, talk to an advocate first,
  use a device the other person can't reach, and the US National Domestic
  Violence Hotline (1-800-799-7233, or text START to 88788)

The `tools/` folder holds interactive security guides from
[The Multiverse School](https://themultiverse.school): password health,
personal threat model, scam dissection, ad tracking audit, and more. They run
in any browser, work offline, and keep their data in the browser. If the person
opts in to anonymous analytics (a checkbox on first use), usage data goes to
the school's analytics server.

## Build the stick

You need [uv](https://docs.astral.sh/uv/) and the
[GitHub CLI](https://cli.github.com/) signed in (`gh auth login`).

```console
$ ./scripts/build-usb-stick.sh
```

This downloads the latest release into a new, empty folder under `dist/`,
checks every installer against `SHA256SUMS.txt` (and stops if anything doesn't
match), builds the guides, bundles the school's tools if it finds the school
repo, and writes the stick to `dist/rescue-stick/`. It deletes the download
folder afterwards and prints the stick's size (a little under 400 MB).

The wrapper runs `uv run scripts/build_rescue_stick.py`; you can run that
directly with the same options.

### Options

```console
$ ./scripts/build-usb-stick.sh --version v0.3.4        # a specific release instead of the latest
$ ./scripts/build-usb-stick.sh --with-cli              # also build the command-line tool for this computer
$ ./scripts/build-usb-stick.sh --skip-tools            # leave out the school's web tools
$ ./scripts/build-usb-stick.sh --school-dir PATH       # where your themultiverse.school checkout is
```

`--with-cli` builds the command-line `rescue` binary with PyInstaller
(`uv run --with pyinstaller pyinstaller rescue.spec`) for the OS and chip of
the machine you build on only. It isn't part of the release, so it isn't in
`SHA256SUMS.txt`; its checksum goes in `command-line/SHA256SUMS-cli.txt`.
Most people should use the desktop app.

The script looks for the school repo at `../themultiverse.school` or
`~/src/themultiverse.school`. It builds the tools in a scratch copy, so the
school repo isn't modified.

## Prepare the USB drive

Use **exFAT** if the stick might be used on both Mac and Windows. Macs and
Windows PCs can both read and write it, and unlike FAT32 it has no 4 GB file
limit. Many new drives come formatted as exFAT or FAT32 already; both work.

If you need to reformat it on a Mac (this **erases everything on the drive**,
so check it's the right one):

1. Open **Disk Utility** (Applications → Utilities).
2. Choose **View → Show All Devices**.
3. In the sidebar, select the USB drive itself (the top-level entry for it,
   not your Mac's internal disk).
4. Click **Erase**. Name: `RESCUE`. Format: **ExFAT**. Scheme: **GUID
   Partition Map**.
5. Click **Erase**, then **Done**.

The build script never formats or erases anything. That step is up to you.

## Copy to the USB drive

With the drive plugged in and showing in Finder:

```console
$ ./scripts/build-usb-stick.sh --write-to /Volumes/RESCUE
```

This copies `dist/rescue-stick/` onto the drive and checks the copied
installers against `SHA256SUMS.txt` again. It only copies: it doesn't
format, erase or delete anything, and files already on the drive are left
alone (files with the same names are replaced). Before copying it shows what
it will copy and asks you to type `y`. Add `--yes` to skip the question.

It refuses to copy when:

- the path isn't under `/Volumes/` (for example `/Volumes/Macintosh HD`, which
  is your startup disk)
- nothing is mounted there
- `diskutil` says the volume is on the startup disk, is an internal
  non-removable disk, or is a mounted disk image
- the drive doesn't have enough free space

`--write-to` works on macOS only. On Windows or Linux, copy the
**contents** of `dist/rescue-stick/` to the root of the drive by hand.

When it's done, eject the drive in Finder before unplugging it.

## What the person receiving it does

They plug in the drive, open it, and double-click `START-HERE.html` (or read
`START-HERE.txt`). The short version:

=== "macOS"

    1. Apple menu → About This Mac. "Chip: Apple M…" → open **For Mac with
       Apple chip**. "Processor: … Intel" → open **For Mac with Intel**.
    2. Double-click the `.dmg` and drag **Reclaim City** into **Applications**.
    3. Open Reclaim City. A warning appears. Click **Done**.
    4. System Settings → Privacy & Security, scroll down, click **Open Anyway**.
    5. Click **Get started**.

=== "Windows"

    1. Open **For Windows** and double-click `ReclaimCity-windows-x64.exe`.
    2. If "Windows protected your PC" appears, click **More info**, then
       **Run anyway**.
    3. Click **Get started**.

## Checking the stick later

If the stick has been out of your sight, `For helpers/CHECKSUMS.txt` explains
how to re-check each installer (`shasum -a 256` on a Mac, `Get-FileHash` in
PowerShell) against `SHA256SUMS.txt`. For the strongest check, compare against
the `SHA256SUMS.txt` on the release page from a different computer, so a
changed drive can't vouch for itself.

## Limitations

- The installers are **unsigned**, so macOS Gatekeeper and Windows SmartScreen
  warn on first open. START-HERE walks the person through it.
- The stick has the release it was built from. To pick up a newer release,
  build it again and copy it again.
- There's no Linux desktop app. For Linux, build with `--with-cli` on a Linux
  machine, or install from source (see the README).
- This is a **portable app on a USB drive**, not a bootable recovery
  environment. It runs on the machine's own OS, which means a deeply
  compromised OS could lie to it. If you suspect that level of compromise,
  you need professional incident response. See
  [Trust and safety](trust-and-safety.md).
