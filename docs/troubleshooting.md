# Troubleshooting

## `rescue: command not found`

The console script installed somewhere that is not on your `PATH`. Every
command works through the module path instead:

```console
$ python3 -m rescue.cli scan          # macOS / Linux
```

```doscon
C:\> py -m rescue.cli scan
```

To fix it properly, add your user script directory to `PATH` (`python3 -m site
--user-base` + `/bin` on macOS/Linux, `%APPDATA%\Python\Scripts` on Windows),
or install into a virtual environment and use its `bin`/`Scripts` directory.

## "No modules discovered" / `rescue profiles` prints nothing

`modules/`, `profiles/`, and `guides/` install **outside** the Python package,
as data files under `share/multiverse-device-rescue/`. If they did not land,
the tool launches perfectly and checks nothing.

Diagnose with:

```console
$ rescue validate
[error] registry:...: no modules were discovered; the install is missing its content
```

Fixes, in order of likelihood:

1. Reinstall from your checkout: `pip install --force-reinstall .`.
2. If you are running from a source checkout, run from the repository root, or
   `pip install -e .` so the package can find its sibling directories.
3. Point the tool at the content explicitly:

    ```console
    $ RESCUE_ASSETS_DIR=/path/to/checkout rescue profiles
    ```

## Permissions and sudo

**You do not need to run the tool as root or administrator**, and mostly you
should not. It is designed to work unprivileged and to say clearly when it
could not read something.

**macOS.** Some checks read state protected by TCC (Transparency, Consent and
Control). If checks that look at your Documents, Desktop, Downloads, or other
applications' data report that they could not read anything, grant your
terminal **Full Disk Access**: System Settings → Privacy & Security → Full Disk
Access → add Terminal (or iTerm), then restart it. macOS may also show its own
authorisation dialog for certain system queries — that is macOS asking, on its
own dialog, and the tool never sees your password.

**Windows.** Event log, WMI, driver, BitLocker, and service-configuration
checks generally need elevation. Open **Windows Terminal → Run as
administrator** and re-run. Without it, those checks report that they could not
read, rather than reporting a false clean result.

**Linux.** Firewall rulesets (`nft list ruleset`, `iptables -S`), some journal
scopes, and other users' processes need privilege. Two options:

```console
$ sudo -E $(which rescue) scan          # keep your environment
$ sudo ~/.venvs/rescue/bin/rescue scan  # explicit path to the venv's script
```

`-E` matters if you rely on `RESCUE_ASSETS_DIR` or an AI provider variable —
`sudo` scrubs the environment by default.

!!! note "Elevation changes where things are written"
    Under `sudo`, `Path.home()` is root's home, so guide progress and case
    exports land in `/root/.rescue/`. If you cannot find a case you just
    exported, that is usually why. Use `rescue export --output ~/cases` to be
    explicit.

**Should you elevate?** Only if a check you care about reported that it could
not read something. Running an unprivileged scan first and elevating for the
gaps is the better habit.

## "Check unavailable" versus "No issues found"

These are three genuinely different outcomes and the tool refuses to blur them.

```text
=== linux_firewall_check ===
No issues found.                       ← ran, found nothing. Good.

=== arp_spoof_check ===
Check unavailable: The neighbour table could not be read, or is empty.
                                       ← errored or timed out. Looked at nothing.

=== win_bitlocker_check ===
Not supported here: This check reads Windows BitLocker state; this host
reports linux.
                                       ← cannot run on this machine at all.
```

**"Check unavailable"** means `check()` raised or exceeded its 60-second
timeout. Common causes: a required command is not installed; a path is
unreadable without elevation; the machine is not connected to the network; an
external command hung. It is **not** a clean result — either fix the cause or
treat that area as unexamined.

**"Not supported here"** means the module knows it cannot produce a meaningful
answer on this machine. Wrong platform, missing subsystem, or missing
permission it can detect up front. The reason text always says which.

Neither ever appears as "No issues found". If you are reading a scan for
security purposes, read these lines first — a scan with ten unavailable checks
is a scan with ten blind spots.

## "timed out after 60.0s"

The orchestrator caps each module's `check()` at 60 seconds and abandons it if
it overruns, so one hung external command cannot stall the session. It is
recorded as an error on that module and the scan continues.

If it happens consistently on one module, run it alone to see:

```console
$ rescue run <module_name>
```

Common causes are a huge home directory, a network-mounted path being walked,
or an external tool waiting on something. Note that Python cannot forcibly kill
a thread stuck in a blocking syscall, so a timed-out check is abandoned on a
daemon thread rather than killed — the process may hold that thread until it
returns on its own.

## "skipped: session time budget exhausted"

The orchestrator's optional whole-session budget ran out before this module
ran. Modules are reported honestly as skipped rather than silently dropped.
Run the ones you care about individually with `rescue run`.

## Unsupported-platform results are normal

The tool ships 287 modules; on any given machine most of them do not apply and
are filtered out before the scan starts. Coverage is uneven by design: 199
modules run on macOS, 100 on Windows, 26 on Linux. A short Linux scan is not a
broken install — check the [module catalog](modules.md) for what exists for
your platform.

If a module you expected did not appear at all, it is platform-filtered. If it
appeared and said "Not supported here", it ran and self-excluded for the reason
given.

## Where sessions, cases, and content live

| Path | What | Safe to delete? |
| --- | --- | --- |
| `~/.rescue/sessions/<profile>.json` | Guide progress | Yes — resets progress |
| `~/.rescue/cases/case-<timestamp>.{json,md}` | Exported case reports | Yes |
| `~/.local/share/rescue/content/` | Applied content updates | Yes — falls back to bundled content |
| `~/.config/rescue/revoked_signers.json` | Locally revoked signers | Yes — but you lose your revocations |

Overrides: `RESCUE_CONTENT_DIR` moves the content checkout,
`RESCUE_ASSETS_DIR` moves the bundled assets. Under `sudo`, all of these
resolve against root's home instead of yours.

## `rescue guide` says "No guide content found"

Two profiles ship no guide: `ai_worm_response` and `iphone_spyware_check`. Both
are scan-only — run them with `rescue --auto --profile <name>`. For the iPhone
check, the human walkthrough is
[Check an iPhone or iPad for spyware](CHECK_IPHONE_FOR_SPYWARE.md).

If a profile that *should* have a guide reports this, the content directory is
missing — see "No modules discovered" above.

## `rescue guide` shows the same phase after I complete a step

A phase only advances once **every** step in it is marked complete. Mark them
one at a time:

```console
$ rescue guide identity_theft_recovery --complete 1
$ rescue guide identity_theft_recovery --complete 2
```

Then the next invocation prints `Phase N complete! Moving to Phase N+1.` To
start over, delete `~/.rescue/sessions/<profile>.json`.

## "WARNING: rescue's own installed files do not match the expected integrity manifest"

The tool hashes its own `rescue/**/*.py` at launch and compares to the shipped
manifest.

- **On a release install:** files changed after installation. Reinstall from a
  source you trust.
- **In a development checkout:** you edited the code. Run
  `python scripts/generate_integrity_manifest.py` and commit the result.

It warns and continues; it never blocks. It also cannot detect tampering by
anything that could also rewrite the manifest. See
[Trust and safety](trust-and-safety.md#the-self-integrity-manifest).

## `Update failed: trusted signer configuration contains placeholder or missing key material`

Expected on the current release. The shipped `trusted_signers.json` holds
`REPLACE_WITH_…` placeholders, and the update engine refuses to operate against
placeholder key material — a correct fail-closed refusal, not a bug. Nothing was
fetched and nothing was applied. Update the tool the way you installed it.

## `Refusing to apply -- not enough maintainer approvals yet`

A content update exists but does not carry signed tags from two distinct
trusted, non-revoked signers. The tool exits `1` and keeps your current content.
That is the designed behaviour; wait for the approvals. If you deliberately
revoked a signer, `rescue trust list-revoked` shows who.

## `rescue validate --strict` exits 1

Expected on the current tree. One warning remains — an aggregate reporting that
264 of 287 modules have no docstring — and `--strict` promotes warnings to
failures. Plain `rescue validate` exits `0` and prints `Catalog is consistent.`
See [Contributing](contributing.md#validating-the-catalog).

## `--copilot` does nothing

```text
--copilot requested but no AI provider is configured.
Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST, then try again.
```

Set one of those variables. If you want a specific provider when several are
configured, set `RESCUE_AI_PROVIDER` to `anthropic`, `openai`, or `ollama`. For
a fully local setup, `RESCUE_AI_PROVIDER=ollama` defaults to
`http://localhost:11434`. If the provider SDK is not installed, run
`pip install ".[ai]"` **from your checkout**.

The error each provider prints when its SDK is missing names the SDK itself
(`pip install anthropic`, `openai`, or `httpx`) and the source-checkout extra.
It deliberately does not name a PyPI package for this project, because there
isn't one — an error message that sends people to install
`multiverse-device-rescue` from PyPI would be telling them to install whatever
an unrelated party has uploaded under that name.

An AI request that fails is reported as a warning and never affects the scan
results printed above it.

## `pip install` fails with "externally-managed-environment"

Your distribution's Python refuses installs into the system environment (PEP
668). Use a virtual environment:

```console
$ git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
$ cd multiverse-device-rescue
$ python3 -m venv .venv
$ .venv/bin/pip install .
$ .venv/bin/rescue scan
```

(There is no PyPI package to install — see the
[install instructions](quickstart.md#1-install).)

## The scan takes a very long time

A full desktop scan runs every module for your platform and some read
substantial state. To narrow it:

```console
$ rescue --auto --profile home_for_the_holidays   # a scenario's modules only
$ rescue run disk_space disk_smart_check          # exactly what you want
```

Estimated per-module durations are in the [module catalog](modules.md).

## Something else

Open an issue with a redacted case attached:

```console
$ rescue export
```

Send the `.md` file, after reading it — redaction removes credential-shaped
strings, emails, your username, home path, and hostname, but module output is
free text. Please do not attach `rescue scan --json`, which is not redacted.
