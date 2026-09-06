# Multiverse Device Rescue

[![tests](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/tests.yml/badge.svg)](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/tests.yml)
[![docs](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/docs.yml/badge.svg)](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/docs.yml)
![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Platforms: macOS | Windows | Linux](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)

You, or someone you're helping, thinks something is wrong with a computer.
Maybe an account was broken into. Maybe something unfamiliar showed up in the
startup list. Maybe a partner or housemate installed something.

Device Rescue scans the machine, tells you in plain English what it found, and
walks you through fixing it. **It is read-only by default** — it never changes
anything unless you say so, it never asks for a password, and it never phones
home.

**Documentation:** <https://lizthedeveloper.github.io/multiverse-device-rescue/>

---

## Who it's for

- Someone who's been hacked and needs a checklist that doesn't assume they're a
  security engineer.
- The relative who ends up as everyone's tech support at the holidays.
- People helping others in a domestic-abuse or stalking context, where "is there
  monitoring software on this device?" needs a concrete answer.
- Sysadmins who want a fast, scriptable read-only sweep (`rescue scan --json`)
  before deciding what to do next.

## Install

> [!WARNING]
> This project is **not on PyPI**. Any package published there under this name
> is not this project. Install from a source checkout only.

```bash
git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
cd multiverse-device-rescue
python3 -m venv .venv && source .venv/bin/activate   # Windows: py -m venv .venv && .venv\Scripts\activate
pip install .
rescue version
```

For development: `pip install -e ".[dev]"` — see [Contributing](CONTRIBUTING.md).

There's also an Electron desktop app in `desktop/` and a standalone binary via
PyInstaller — see [Desktop app builds](docs/quickstart.md) and
[USB rescue stick](docs/usb-rescue-stick.md).

## Quick start

### Scan the machine

```console
$ rescue scan
=== disk_space ===
Found 2 issue(s):
  [critical] Disk / is 95% full
  [warning]  Disk /home is 80% full
=== linux_service_health ===
Found 1 issue(s):
  [warning] No time-synchronisation service appears to be running
=== arp_spoof_check ===
Check unavailable: The neighbour table could not be read.
=== linux_firewall_check ===
No issues found.
```

Nothing was changed. "Check unavailable" means the check couldn't run — it's
not a clean bill of health, and the tool says so explicitly.

### Pick your situation

The generic scan checks everything. Profiles focus on a specific threat and
pair the scan with a human walkthrough:

```console
$ rescue profiles
digital_security_reset    — Post-compromise recovery
home_for_the_holidays     — Help a family member's device in one visit
home_network_intrusion    — Someone is on your Wi-Fi
identity_theft_recovery   — Step-by-step after identity theft
iphone_spyware_check      — Scan an iPhone backup for spyware
ai_worm_response          — AI worm & spyware response
linux_security_checkup    — Full Linux security review
```

Run a profile and open its guide:

```console
$ rescue --auto --profile digital_security_reset
$ rescue guide digital_security_reset
```

### Export a report

```console
$ rescue export
Wrote ~/.rescue/cases/case-20260805T230525Z.md
```

Credentials, email addresses, and account names are redacted before the file
is written. Read it before sharing — module output is free text.

## What else it does

| Command | What it does |
| --- | --- |
| `rescue` | Interactive TUI — scan, browse findings, open guides |
| `rescue scan --json` | Machine-readable output for scripts |
| `rescue run <module> [--yes]` | Run a specific check (and optionally its fix) |
| `rescue guide <profile>` | Resume a step-by-step walkthrough |
| `rescue validate` | Check the shipped module/profile/guide catalog |
| `rescue export` | Redacted case report (JSON + Markdown) |
| `rescue explain` / `rescue recommend` | Opt-in AI explanations (needs an API key) |

## 287 checks across three platforms

| | macOS | Windows | Linux |
| --- | ---: | ---: | ---: |
| Modules | 199 | 100 | 26 |

Security (118), integrity (106), performance (51), network (8), bloatware (4).
macOS has the deepest coverage; Linux is newer and narrower.

## Learn more

| | |
| --- | --- |
| [Quickstart](docs/quickstart.md) | Install and run your first scan |
| [Scenarios](docs/scenarios/) | The seven built-in situations |
| [CLI reference](docs/cli.md) | Every command and flag |
| [Trust and safety](docs/trust-and-safety.md) | How to verify it does what it claims |
| [Privacy](docs/privacy.md) | What leaves your machine (almost nothing) |
| [USB rescue stick](docs/usb-rescue-stick.md) | Build a portable rescue drive |
| [Architecture](docs/architecture.md) | How the code is organized |
| [Roadmap](docs/ROADMAP.md) | What's planned |
| [Contributing](CONTRIBUTING.md) | Dev setup, tests, module authoring |
| [Security policy](SECURITY.md) | How to report a vulnerability |
