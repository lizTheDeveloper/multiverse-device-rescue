# FAQ

## Is it going to change something on my computer?

Not unless you tell it to. `rescue scan` and `rescue export` never apply a fix
at all. `rescue --auto` is read-only on the shipped tree: unattended repair
requires a module to set `auto_apply = True`, and none of the 287 shipped
modules do. You can check in one command:

```console
$ grep -rn "auto_apply" modules/ | wc -l
0
```

The two ways to actually change something are answering `y` at a
`Apply fixes for <module>?` prompt, or passing `--yes` to `rescue run`. Full
chain of evidence in
[Trust and safety](trust-and-safety.md#auto-mode-is-read-only).

## Will it ever ask for my password or a 2FA code?

No. There is no prompt in the tool for an account password, a one-time code, a
recovery code, a seed phrase, or a password-manager master password. If
something claiming to be this tool asks you to type one, it is not this tool.

Your **operating system** may ask for your administrator password on its own
dialog (macOS authorisation, `sudo`, Windows UAC). That is the OS, and the tool
never sees what you type.

## Does it send my data anywhere?

No, unless you turn on the optional AI layer, which requires both an API key in
the environment *and* an explicit `--copilot` / `rescue explain` /
`rescue recommend`. There is no telemetry, no analytics, no crash reporting,
and no version ping. See [Privacy](privacy.md).

## Do I need to run it as administrator or with sudo?

No, and mostly you should not. The tool works unprivileged; some checks will
report that they could not read something, which is a normal result, not a
failure. See [Troubleshooting](troubleshooting.md#permissions-and-sudo) for
which checks benefit from elevation and how to decide.

## "Check unavailable" — is that bad?

It means the check **errored or timed out**, so it looked at nothing. It is not
a clean bill of health and it is not necessarily a problem — most often it
means a required command is missing or a path is unreadable. Treat that area as
unexamined. The related message "Not supported here" means the check cannot run
on this machine at all. Neither is ever reported as "No issues found", by
design. Details in
[Troubleshooting](troubleshooting.md#check-unavailable-versus-no-issues-found).

## Why did it find 20 "issues"? Am I hacked?

Almost certainly not. Most findings are `[info]` — inventories that exist so a
human can spot the one entry they do not recognise. That is the detection
mechanism for anything novel: no signature list can know what is unusual *for
you*. Read the severities, not the count. `[warning]` means something is worth
changing; `[critical]` means today.

## Does it replace antivirus?

No. It looks for indicators and misconfiguration. Keep your endpoint protection.

## Can it scan my phone?

Only an iPhone or iPad **backup that already exists on your computer**, via the
[iPhone/iPad spyware check](scenarios/iphone-spyware-check.md), which uses
Amnesty International's Mobile Verification Toolkit. There are no desktop
modules for Android or iOS device internals; mobile steps in the guides are
human-led.

## Which platform gets the most coverage?

macOS, then Windows, then Linux. Of the 287 shipped modules, 199 run on macOS,
100 on Windows, and 26 on Linux (a module can support more than one). Linux
support is real but narrower — see the [module catalog](modules.md) for the
exact list.

## Where does it store things?

| Path | What |
| --- | --- |
| `~/.rescue/sessions/<profile>.json` | Guide progress |
| `~/.rescue/cases/` | Exported case reports |
| `~/.local/share/rescue/content/` | Applied content updates |
| `~/.config/rescue/revoked_signers.json` | Locally revoked update signers |

`rescue scan` writes nothing at all.

## What is a "profile"?

A scenario. It picks the relevant modules, configures them for that threat, and
pairs them with a phased human walkthrough. `rescue profiles` lists the seven
built-in ones; [Scenarios](scenarios/index.md) helps you choose.

## What is the difference between `--auto --profile X` and `rescue guide X`?

`--auto --profile X` runs the device checks for that scenario. `rescue guide X`
walks you through the human work — the phone calls, the account changes, the
router settings — and tracks which steps you have finished. For most scenarios
the guide is the substance and the modules only answer "is this device itself
the problem?"

## Can I run a single check?

```console
$ rescue run <module_name>
```

Names are in the [module catalog](modules.md). It prompts before applying
anything; answer `N` and nothing happens.

## How do I share my results with someone who can help?

```console
$ rescue export
```

That writes a redacted JSON file and a Markdown summary to `~/.rescue/cases/`.
Send the Markdown one. Read it first — redaction removes credential-shaped
strings, emails, your username, home path, and hostname, but module output is
free text. Do **not** share `rescue scan --json`, which is not redacted.

## Why does it warn about the integrity manifest?

```text
WARNING: rescue's own installed files do not match the expected integrity manifest.
```

The tool hashes its own Python files at launch and compares them to a shipped
manifest. On a release install this means files changed after installation —
reinstall. In a development checkout it usually just means you edited the code
and have not regenerated the manifest
(`python scripts/generate_integrity_manifest.py`). It warns and continues; it
never blocks.

## `rescue update` says the signer configuration has placeholders

That is correct and expected on the current release. The shipped
`trusted_signers.json` contains `REPLACE_WITH_…` placeholders, and the software
refuses to run an update against placeholder key material. The update channel is
effectively closed until real maintainer keys are published (roadmap P0#3). Get
new versions the way you got this one. See
[Trust and safety](trust-and-safety.md#signed-content-updates).

## Can an update push new code to my machine?

Not through the sanctioned path. Content updates carry data files only —
`.json`, `.md`, `.toml`, `.txt`, `.yaml`, `.yml` under `modules/`, `guides/`, or
`profiles/` — and a commit containing anything else is rejected before checkout.
Updates also require signed tags from two distinct trusted maintainers.

## Is my data safe if my machine is actually compromised?

Assume not. A machine you believe is compromised cannot be trusted to report on
itself: malware with sufficient privilege can hide from any local tool,
including this one. Use this for triage and for evidence of what *is* visible,
do the account recovery from a device you trust, and get professional incident
response if the stakes are high.

## Someone I know may be monitoring me. Should I just remove it?

Please read the safety framing first. Removing monitoring software can escalate
a dangerous situation, and the safety plan comes before the technical cleanup.
The [home network intrusion](scenarios/home-network-intrusion.md) guide opens
with this. In the US: National Domestic Violence Hotline, 1-800-799-7233.
Internationally: <https://stopstalkerware.org>.

## How do I contribute a check?

[Writing a module](writing-a-module.md) has the full contract and a complete
copy-pasteable example with tests. [Contributing](contributing.md) covers dev
setup and what CI enforces.
