# USB Rescue Stick

A rescue stick is a USB drive with a ready-to-run copy of Device Rescue on it.
You build it on your machine, hand it to someone (or carry it with you), and
they plug it in and run the tool — no install, no internet, no Python required.

This is useful when you're helping someone whose machine you can't set up
remotely, or when you want a grab-and-go drive you can keep in a bag for the
next time someone asks for help.

## What's on the stick

```
RESCUE-STICK/
├── START-HERE.txt          ← Plain-English instructions for the person using it
├── macos/
│   └── rescue              ← Standalone macOS binary (Apple Silicon)
├── windows/
│   └── rescue.exe          ← Standalone Windows binary
├── tools/
│   ├── index.html          ← Security tools hub (open in any browser)
│   ├── password-health.html
│   ├── threat-model.html
│   ├── pretext-anatomy.html
│   ├── ad-surface.html
│   ├── device-rescue.html  ← Browser version of the rescue walkthrough
│   └── attack-surface.html
└── guides/
    └── quick-reference.txt ← One-page printed reference card
```

The `tools/` folder contains interactive security guides from
[The Multiverse School](https://themultiverse.school) — password health
assessment, personal threat modeling, scam dissection, ad tracking audit,
and more. They run in any browser, work offline, and keep all data in
the browser's local storage using MVProfile. If the user opts in to
anonymous analytics (a checkbox they see on first use), usage data goes
to the analytics server to help improve the tools.

You only need to build the platform(s) you'll actually hand out. The script
below builds for the machine you run it on.

## Build the stick

### Prerequisites

- Python 3.11+ with the project installed (`pip install .`)
- PyInstaller (`pip install pyinstaller`)
- A USB drive, formatted as exFAT (readable by both macOS and Windows) or
  APFS/NTFS if you're targeting only one platform

### Quick build

```console
$ ./scripts/build-usb-stick.sh
```

This runs the PyInstaller build, bundles the security tools from The
Multiverse School (if the repo is found nearby), and assembles the rescue
stick directory at `dist/rescue-stick/`. Copy that folder to a USB drive
and you're done.

The script looks for the school repo at `../themultiverse.school` or
`~/src/themultiverse.school`. If it's somewhere else:

```console
$ ./scripts/build-usb-stick.sh --school-dir /path/to/themultiverse.school
```

### Options

```console
$ ./scripts/build-usb-stick.sh --skip-build        # assemble only (binary already built)
$ ./scripts/build-usb-stick.sh --skip-tools         # don't bundle the web tools
$ ./scripts/build-usb-stick.sh --school-dir PATH    # specify the school repo location
```

### Copy to USB

On macOS:
```console
$ cp -R dist/rescue-stick/* /Volumes/YOUR-USB-DRIVE/
```

On Windows:
```doscon
C:\> xcopy /E dist\rescue-stick\* E:\
```

## What the person receiving it does

They plug in the drive, open it, and read `START-HERE.txt`. The short version:

=== "macOS"

    1. Open the `macos` folder on the USB drive
    2. Right-click `rescue` → Open (macOS will ask about an unidentified developer — click Open)
    3. A terminal window opens and the scan starts
    4. Read the results — nothing is changed unless you say so

=== "Windows"

    1. Open the `windows` folder on the USB drive
    2. Double-click `rescue.exe` (Windows may show a SmartScreen warning — click "More info" → "Run anyway")
    3. A terminal window opens and the scan starts
    4. Read the results — nothing is changed unless you say so

## The quick reference card

`guides/quick-reference.txt` is a one-page document you can print and include
in the envelope or bag with the USB drive. It covers:

- What Device Rescue is (one sentence)
- How to open and run it
- How to read the four outcomes (clean / findings / unavailable / unsupported)
- How to export a report to share
- What the tool will never ask for (passwords, 2FA codes, recovery keys)
- The domestic-violence safety note and hotline number

## Limitations

- The binary is built for **one architecture**. An Apple Silicon Mac produces a
  binary that won't run on Intel Macs (and vice versa). If you need both, build
  on both and put both in the `macos/` folder (`rescue-arm64` and
  `rescue-x86_64`).
- The macOS binary is **unsigned** — Gatekeeper will block it on first launch.
  The recipient has to right-click → Open (or go to System Settings → Privacy &
  Security → Open Anyway). The START-HERE instructions walk them through this.
- The Windows binary is **unsigned** — SmartScreen will flag it. Same deal:
  "More info" → "Run anyway."
- The binary includes the modules, profiles, and guides that existed at build
  time. To pick up new content, rebuild the stick.
- This is a **portable app on a USB drive**, not a bootable recovery
  environment. It runs on the machine's own OS, which means a deeply
  compromised OS could lie to it. If you suspect that level of compromise,
  you need professional incident response — see
  [Trust and safety](trust-and-safety.md).
