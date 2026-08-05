# Multiverse Device Rescue

A local diagnostic, maintenance, and guided-recovery toolkit for macOS,
Windows, and Linux. It runs **287 read-only checks** against the machine it is
installed on, tells you plainly what it found, and walks you through the parts
that a program cannot and should not do for you.

It is built for the moment after something has gone wrong — you think you have
been hacked, your Wi-Fi has strangers on it, your identity has been stolen, a
family member's laptop has been getting slower for two years — when you need to
know what is actually true about the machine in front of you before you start
changing things.

<div class="grid cards" markdown>

-   :material-rocket-launch: **[Quickstart](quickstart.md)**

    Install it and run your first scan in about a minute.

-   :material-map-marker-path: **[Scenarios](scenarios/index.md)**

    Seven built-in situations, each with the exact command to run.

-   :material-shield-check: **[Trust and safety](trust-and-safety.md)**

    Every safety claim on this page, traced to the code that implements it.

-   :material-console: **[CLI reference](cli.md)**

    Every command and flag the tool has.

</div>

## The safety stance

This tool is designed to be run by someone who is already frightened, on a
machine they are no longer sure they can trust. That constrains what it is
allowed to do.

!!! success "Read-only by default"
    `rescue --auto` never changes your system. Not "rarely" — never, on the
    shipped tree. Unattended repair requires a module to opt in by setting
    `auto_apply = True`, and **zero of the 287 shipped modules do**. The
    summary line prints the number of changes it made, and on this tree that
    number is always `0`. See
    [how that is enforced](trust-and-safety.md#auto-mode-is-read-only).

!!! success "It never asks for your secrets"
    The tool does not have a prompt for an account password, a one-time 2FA
    code, a recovery code, a seed phrase, or a password-manager master
    password, because it never needs one. If anything ever asks you for one
    while claiming to be this tool, that is not this tool. Everything that
    genuinely requires signing in to an account happens on the provider's own
    website, in the guide, done by you.

!!! success "Nothing leaves your machine"
    Checks read local files and run local commands. There is no telemetry, no
    analytics, and no upload. The single exception is the optional AI
    explanation layer, which only runs when you explicitly pass `--copilot` or
    run `rescue explain` / `rescue recommend`, and which sends only finding
    titles and descriptions to the provider you configured. See
    [Privacy](privacy.md).

!!! success "Guidance and system changes are counted separately"
    "Here is what you should do" and "I did this to your computer" are
    different things, and the tool tracks them as different things right down
    in the data model (`ActionKind.GUIDANCE` vs `ActionKind.MUTATION`). A
    manual instruction can never be reported as a change that was made.

!!! success "A check that could not run says so"
    A check that lacked permission, hit an unsupported platform, timed out, or
    crashed reports `unsupported` or `failed`. It never quietly reports "no
    issues found". This distinction is baked into `CheckStatus`, because a
    security tool that turns "I could not look" into "everything is fine" is
    worse than no tool.

## When to use it

**Good fits**

- You suspect an account or device compromise and need to know what is
  observable on the device before you start resetting things.
- Someone unwanted may be on your home network, or your machine is mining
  cryptocurrency for a stranger.
- Your identity has been stolen and you need a checklist that survives the
  next three weeks of phone calls.
- You are visiting family and have one afternoon to leave their laptop in a
  better state than you found it.
- You want a plain-language read on a machine that "feels wrong".

**Poor fits — please use something else**

- **An active, ongoing intrusion of a business or a high-risk target.** Use a
  professional incident-response team. Running diagnostics on a live
  compromise can destroy the evidence they need.
- **Forensic evidence collection for legal proceedings.** This is a triage
  tool, not a forensic imager.
- **Antivirus.** It looks for indicators and misconfiguration, and it does not
  replace an endpoint-protection product.
- **Android and iOS device internals.** Mobile steps are human-guided. The one
  exception is scanning an iPhone/iPad *backup* that already exists on your
  computer — see the [iPhone spyware check](scenarios/iphone-spyware-check.md).

!!! danger "If the person who may have access is someone you know"
    If a partner, ex-partner, family member, or housemate may be monitoring
    you, removing monitoring software can escalate the situation. The safety
    plan comes before the technical cleanup. In the US, the National Domestic
    Violence Hotline is 1-800-799-7233; the Coalition Against Stalkerware
    (<https://stopstalkerware.org>) lists resources internationally. The
    [home network intrusion](scenarios/home-network-intrusion.md) guide opens
    with this for a reason.

## 60-second quickstart

!!! danger "This project is not published on PyPI"
    Install it from a source checkout, as below. There is no
    `pip install multiverse-device-rescue` — the maintainers do not control
    that name on any package registry, so **any package by that name on PyPI is
    not this project**. Installing it would be exactly the supply-chain
    mistake this tool exists to help you avoid.

=== "macOS / Linux"

    ```console
    $ git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
    $ cd multiverse-device-rescue
    $ python3 -m venv .venv && source .venv/bin/activate
    $ pip install .
    $ rescue scan
    ```

=== "Windows"

    ```doscon
    C:\> git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
    C:\> cd multiverse-device-rescue
    C:\> py -m venv .venv && .venv\Scripts\activate
    C:\> pip install .
    C:\> rescue scan
    ```

`rescue scan` runs every check that applies to your platform and prints what it
found. It changes nothing.

```console
$ rescue scan
=== linux_service_health ===
Found 1 issue(s):
  [warning] No time-synchronisation service appears to be running: Nothing on
  this machine is keeping the clock correct. A drifted clock breaks HTTPS
  certificate validation, two-factor codes, and scheduled jobs.
=== linux_firewall_check ===
No issues found.
=== arp_spoof_check ===
Check unavailable: The neighbour table could not be read, or is empty.
```

Then pick the situation you are actually in:

```console
$ rescue profiles                                  # what scenarios exist
$ rescue --auto --profile digital_security_reset   # scan for one scenario
$ rescue guide digital_security_reset              # the human walkthrough
```

Keep going in the [Quickstart](quickstart.md), or jump to the
[scenario that matches your situation](scenarios/index.md).

## Where things live

| Thing | Path |
| --- | --- |
| Saved guide progress | `~/.rescue/sessions/<profile>.json` |
| Exported rescue cases | `~/.rescue/cases/` |
| Downloaded content updates | `~/.local/share/rescue/content/` |
| Locally revoked update signers | `~/.config/rescue/revoked_signers.json` |

Nothing else is written anywhere unless you ask for it.
