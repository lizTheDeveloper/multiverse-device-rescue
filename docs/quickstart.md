# Quickstart

Install the tool, run one read-only scan, and learn to read the output. Fifteen
minutes, and nothing on your machine changes.

## 1. Install

The tool needs **Python 3.11 or newer**. Check with `python3 --version` (macOS
and Linux) or `py --version` (Windows). You also need `git`.

!!! danger "This project is not published on PyPI — install from source"
    There is no `pip install multiverse-device-rescue`. The maintainers do not
    control that name on PyPI or any other package registry, so **any package
    published there under that name is not this project**, and installing it
    would run code from a party unrelated to this repository.

    That is precisely the supply-chain attack this tool helps people
    investigate, so it would be a poor way to start. Every tab below installs
    from a git checkout you can read before you run it.

    The same applies to the extras: use `pip install ".[ai]"` **from your
    checkout**, never `pip install "multiverse-device-rescue[ai]"`. (One
    provider error message in the source suggests the latter; it is wrong, and
    the checkout form is the one to use.)

=== "macOS"

    ```console
    $ git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
    $ cd multiverse-device-rescue
    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip install .
    $ rescue version
    multiverse-device-rescue 0.1.0
    ```

    If `rescue` is not found after activating the venv, call the tool through
    Python instead:

    ```console
    $ python3 -m rescue.cli version
    ```

    Some checks read system state that macOS protects. See
    [permissions](troubleshooting.md#permissions-and-sudo) before you conclude
    a check is broken.

=== "Windows"

    ```doscon
    C:\> git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
    C:\> cd multiverse-device-rescue
    C:\> py -m venv .venv
    C:\> .venv\Scripts\activate
    C:\> pip install .
    C:\> rescue version
    multiverse-device-rescue 0.1.0
    ```

    If `rescue` is not recognised, use `py -m rescue.cli` instead. A number of
    Windows checks read state that requires an elevated prompt; run
    **Windows Terminal as Administrator** if a check reports that it could not
    read something.

=== "Linux"

    ```console
    $ git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
    $ cd multiverse-device-rescue
    $ python3 -m venv .venv
    $ source .venv/bin/activate
    $ pip install .
    $ rescue version
    multiverse-device-rescue 0.1.0
    ```

    The virtual environment is not optional on most distributions: a
    system-wide `pip install` is refused by PEP 668 ("externally-managed
    environment"). Add `.venv/bin` to your `PATH` if you want to type `rescue`
    from anywhere.

=== "For development"

    Use an editable install so your edits take effect without reinstalling, and
    pull in the test tooling:

    ```console
    $ git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
    $ cd multiverse-device-rescue
    $ python3 -m venv .venv
    $ source .venv/bin/activate      # Windows: .venv\Scripts\activate
    $ pip install -e ".[dev]"
    $ python -m pytest -q
    ```

    See [Contributing](contributing.md).

Installing from source is also how you read every check before you run it — the
modules are plain Python files under `modules/`, with nothing compiled and
nothing fetched at runtime. See
[Trust and safety](trust-and-safety.md#read-the-source-of-any-check).

!!! info "Desktop app builds"
    The repository contains packaging scripts for a desktop build —
    `scripts/build-macos-app.sh` and `scripts/build-windows.bat`, which wrap
    PyInstaller (`scripts/build.py`) and the Electron shell in `desktop/`.
    These are **run by a maintainer to produce an installer**; this project
    does not publish prebuilt downloads, and nothing in CI produces one. If
    someone hands you an installer claiming to be this tool, verify where it
    came from — or build it yourself from the checkout.

!!! note "The modules, profiles, and guides are data, not code you import"
    They install to a share directory alongside the package rather than inside
    it. That is why a working install can still report "no modules
    discovered" if the packaging is broken — and why CI has a job that installs
    into a clean environment and runs the tool from outside the source tree.

## 2. Your first scan

```console
$ rescue scan
```

That is the whole thing. `scan` runs every check that declares support for your
platform, prints a report per module, and exits. It does not prompt you, it
does not apply anything, and it does not ask for a password.

Expect it to take a few minutes on a full desktop scan. Each individual check
is capped at 60 seconds by the orchestrator, so one hung command cannot stall
the session.

## 3. Reading the results

Here is real output, lightly trimmed, from a Linux machine:

```console
$ rescue scan
=== process_scanner ===
No issues found.
=== linux_package_updates ===
Found 2 issue(s):
  [info] 1 package update(s) available: Ordinary updates — bug fixes and new
  versions. Worth applying, but not urgent in the way security updates are.

  coreutils
  [info] Confirm Ubuntu 24.04.4 LTS is still receiving security updates: This
  machine reports Ubuntu 24.04.4 LTS (version 24.04).

  A release past its end-of-life keeps working and stops getting security
  fixes, so it reports zero pending updates while quietly accumulating
  unpatched vulnerabilities.
=== linux_service_health ===
Found 1 issue(s):
  [warning] No time-synchronisation service appears to be running: Nothing on
  this machine is keeping the clock correct. A drifted clock breaks HTTPS
  certificate validation, two-factor codes, and scheduled jobs — and it does it
  in ways that look like a network fault rather than a clock fault.

  Checked for: systemd-timesyncd, chronyd, ntpd, ntpsec
=== arp_spoof_check ===
Check unavailable: The neighbour table could not be read, or is empty. Check
that this machine is connected to the network.
=== linux_account_audit ===
Found 2 issue(s):
  [warning] claude can run commands as root without a password: /etc/sudoers
  contains a NOPASSWD rule for claude.

  This is convenient and it is also the difference between 'someone got into
  your user session' and 'someone got root'.
  [info] 2 account(s) can log in to this machine: Accounts that can log in:
  root, ubuntu
```

### The four outcomes

Every check lands in exactly one of four states, and they are deliberately not
interchangeable.

| What you see | What it means | Should you worry? |
| --- | --- | --- |
| `No issues found.` | The check ran to completion and found nothing. | No. |
| `Found N issue(s):` | The check ran and has findings. | Read them — severity decides. |
| `Check unavailable: <reason>` | The check **errored or timed out**. It did not look. | Not necessarily, but you have no information here. |
| `Not supported here: <reason>` | The check cannot run on this machine (wrong platform, missing tool, no permission). | No — but again, you have no information. |

The last two are the important ones. "Check unavailable" is **not** a clean
bill of health. The tool refuses to collapse "I could not look" into "nothing
is wrong", so when you see it, either fix the cause (usually permissions, see
[Troubleshooting](troubleshooting.md)) or treat that area as unexamined.

### The three severities

- **`[info]`** — an observation, usually an inventory. Most `info` findings
  exist so a human can spot the one entry they do not recognise. That is the
  actual detection mechanism for anything novel: no signature list can know
  what is unusual *for you*.
- **`[warning]`** — something is misconfigured, weakened, or worth changing.
  Not an emergency.
- **`[critical]`** — something is wrong now and warrants attention today.

A long list of `info` findings is normal and healthy. Read it, do not panic at
its length.

## 4. A worked example

Suppose the scan above is your machine. Here is what you would actually do.

**Step one — deal with the `[warning]`, ignore the length of the list.** Two
findings matter: no time synchronisation, and a passwordless `sudo` rule. The
rest is inventory.

**Step two — look at the one module more closely.** Every module runs
standalone:

```console
$ rescue run linux_account_audit
System: Ubuntu 24.04.4 LTS 6.18.5 | Intel(R) Xeon(R) Processor @ 2.10GHz | x86_64
Running 1 module(s)...

=== linux_account_audit ===
Found 2 issue(s):
  [warning] claude can run commands as root without a password: ...
  [info] 2 account(s) can log in to this machine: ...

Apply fixes for linux_account_audit? [y/N]:
```

Answer `N`. You have not committed to anything — the prompt appears *before*
`fix()` runs, and answering no ends the module. For most modules `fix()`
produces guidance text rather than changes anyway, but you never have to find
out to stay safe.

**Step three — read the check before you trust it.** If you want to know
exactly what `linux_account_audit` looked at, it is one file:

```console
$ less modules/security/linux_account_audit/__init__.py
```

**Step four — get a copy you can share.** When you want to hand the results to
someone who can help:

```console
$ rescue export
Wrote /home/you/.rescue/cases/case-20260805T230542Z.json
Wrote /home/you/.rescue/cases/case-20260805T230542Z.md

Both files are redacted, but module output is free text — read them before
sharing.
```

The `.md` file is the one for people. Credential-shaped strings, email
addresses, your account name, your home path, and the hostname are stripped
before either file is written. Read [Privacy](privacy.md#the-redacted-case-export)
for exactly what redaction does and does not cover.

## 5. Now pick your actual situation

A whole-machine scan is the generic answer. The profiles are the specific ones:
they select the relevant modules, configure them for the threat, and pair them
with a phased human walkthrough.

```console
$ rescue profiles
ai_worm_response — AI Worm & Spyware Response
    Comprehensive scan for AI-led worm compromise ...
digital_security_reset — Digital Security Reset
    Post-compromise recovery for someone who has been hacked ...
home_for_the_holidays — Home for the Holidays
    Help a family member get their device cleaned up ...
home_network_intrusion — Home Network Intrusion & Cryptojacking Response
    Response for a household whose Wi-Fi has been broken into ...
identity_theft_recovery — Identity Theft Recovery
    Step-by-step recovery for someone whose identity has been stolen ...
iphone_spyware_check — iPhone / iPad Spyware Check
    Scans a local iPhone or iPad backup for known mercenary-spyware ...
```

Run one, then open its guide:

```console
$ rescue --auto --profile digital_security_reset
$ rescue guide digital_security_reset
```

`--auto` here still changes nothing — it prints a summary that includes the
number of system changes made, which on the shipped tree is always zero:

```console
==================================================
Multiverse Device Rescue — Auto Mode
==================================================

Scanned 26 module(s), found 20 issue(s). Auto mode is read-only: made 0 system
change(s); 0 manual action(s) require you.
```

The guide is the part that carries the actual recovery. It tracks your progress
across sessions:

```console
$ rescue guide identity_theft_recovery
=== Identity Theft Recovery: Phase 0 — The First Hour ===
Estimated time: 1 hour

[human] [pending] Step 1: Start a recovery log before you do anything else
[human] [pending] Step 2: Write down what you already know
[human] [pending] Step 3: Know what identity theft is not your fault
[human] [pending] Step 4: Understand the order, and why it is this order
[human] [pending] Step 5: Decide what to do about the immediate money

Run again with --complete <step number> to mark a step done.

$ rescue guide identity_theft_recovery --complete 1
Marked step 1 complete for phase 0.
```

Progress lives in `~/.rescue/sessions/<profile>.json`, so you can close the
terminal and come back next week.

## Where to go next

- **[Pick a scenario](scenarios/index.md)** — the seven built-in situations.
- **[CLI reference](cli.md)** — every command and flag.
- **[Trust and safety](trust-and-safety.md)** — how to satisfy yourself that
  this thing is not going to do something to your computer.
- **[Troubleshooting](troubleshooting.md)** — permissions, unavailable checks,
  and where files are stored.
