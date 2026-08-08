# Multiverse Device Rescue

[![tests](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/tests.yml/badge.svg)](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/tests.yml)
[![docs](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/docs.yml/badge.svg)](https://github.com/lizTheDeveloper/multiverse-device-rescue/actions/workflows/docs.yml)
![Python 3.11 | 3.12 | 3.13](https://img.shields.io/badge/python-3.11%20%7C%203.12%20%7C%203.13-blue)
![Platforms: macOS | Windows | Linux](https://img.shields.io/badge/platforms-macOS%20%7C%20Windows%20%7C%20Linux-lightgrey)

A local diagnostic, maintenance, and guided-recovery toolkit for macOS, Windows,
and Linux. It runs read-only checks by default, and it keeps three things
strictly apart: what it observed, what it is telling *you* to do, and what it
actually changed on the machine.

**Documentation:** <https://lizthedeveloper.github.io/multiverse-device-rescue/>
(published by the `docs` workflow; the link only resolves once GitHub Pages is
enabled for the repository) ·
[Roadmap](docs/ROADMAP.md) ·
[Roadmap status](docs/ROADMAP_STATUS.md) ·
[Threat → remediation map](docs/THREAT_REMEDIATION.md) ·
[Security policy](SECURITY.md) ·
[Contributing](CONTRIBUTING.md)

---

## What this is

You, or someone you are helping, thinks something is wrong with a computer.
Maybe an account was broken into. Maybe the machine got slow and something in
the startup list looks unfamiliar. Maybe a partner or a housemate installed
something. Multiverse Device Rescue is a program you run on that machine to find
out what is observably true about it, and then to walk you through fixing it.

Two halves:

- **Modules** — 287 individual checks (disk health, firewall state, SSH
  configuration, browser extensions, persistence entries, startup items, mercenary
  spyware indicators in phone backups, and so on). A module reports findings.
  Fixing is a separate, confirmed step.
- **Guides** — human-led walkthroughs for situations that are mostly *not* on the
  computer: recovering from identity theft, doing a full digital security reset
  after a compromise, reclaiming a home network. The tool tracks which steps you
  have finished; the steps themselves are yours to do.

### Who it's for

- Someone who has been hacked and needs a checklist that does not assume they
  are a security engineer.
- The relative who ends up as everyone's tech support at the holidays.
- People helping others in a domestic-abuse, stalking, or harassment context,
  where the question "is there monitoring software on this device" needs a
  concrete answer.
- Sysadmins and responders who want a fast, scriptable read-only sweep
  (`rescue scan --json`) before deciding what to do next.

### Who it isn't for

If you are dealing with a live, active compromise on a machine you depend on,
this is not a substitute for professional incident response. See
[Project status](#project-status) for the safety boundary.

---

## Install

Requires Python 3.11, 3.12, or 3.13. The project is **not on PyPI**; install
from a source checkout.

```bash
git clone https://github.com/lizTheDeveloper/multiverse-device-rescue.git
cd multiverse-device-rescue
python -m pip install .
rescue version
```

`modules/`, `profiles/`, and `guides/` live outside the Python package and ship
as `data_files` (see `setup.py`), so a normal `pip install .` gets a complete,
working tool rather than an engine with nothing to run. Verified here on Linux
by installing into a fresh venv and running `rescue profiles` and
`rescue run disk_space --yes` from `/tmp`, outside the source tree. The
`package` job in `.github/workflows/tests.yml` does the same on Linux, macOS,
and Windows.

### Development install

```bash
python -m venv .venv
.venv/bin/python -m pip install -e ".[dev]"
```

Optional extras: `.[ai]` pulls in the Anthropic / OpenAI / httpx clients used by
the opt-in AI layer. Nothing in the core tool needs them.

### Desktop app

There is an Electron wrapper in `desktop/` that drives the same engine. It is
built in two stages — a PyInstaller single-file `rescue` binary, then the
Electron installer:

```bash
./scripts/build-macos-app.sh     # builds dist/rescue, stages desktop/engine/rescue
scripts\build-windows.bat        # Windows: engine + Electron installer
```

`scripts/build.py` wraps `pyinstaller rescue.spec` directly if you only want the
standalone binary. There are no prebuilt release artifacts yet; you build them
yourself.

---

## Usage

Every command below was run against this checkout. Output is real, trimmed for
length where noted.

### `rescue` — interactive TUI

Running `rescue` with no subcommand launches a Textual TUI: it scans, groups
findings by category, and lets you drill into a finding and open the remediation
walkthrough attached to it. `g` opens the guides, `q` quits. Progress is stored
in `~/.rescue/sessions` and is shared with `rescue guide` on the command line,
so marking a step done in one place shows up in the other.

### `rescue scan` — read-only checks

```console
$ rescue scan
=== process_scanner ===
No issues found.
=== linux_journal_errors ===
No issues found.
=== linux_service_health ===
Found 1 issue(s):
  [warning] No time-synchronisation service appears to be running: Nothing on this machine is keeping the clock correct. A drifted clock breaks HTTPS certificate validation, two-factor codes, and scheduled jobs — and it does it in ways that look like a network fault rather than a clock fault, so people chase the wrong problem for hours.

Checked for: systemd-timesyncd, chronyd, ntpd, ntpsec
=== arp_spoof_check ===
Check unavailable: The neighbour table could not be read, or is empty. Check that this machine is connected to the network.
=== disk_space ===
Found 4 issue(s):
  [critical] Disk /opt/rclone is 100% full: /dev/vdb mounted at /opt/rclone: 9.8 MB used of 9.8 MB (0.0 B free)
  [warning] Disk /opt/claude-code is 90% full: /dev/vdc mounted at /opt/claude-code: 274.1 MB used of 304.8 MB (24.6 MB free)
...
```

`scan` runs checks only. It never calls a module's `fix()`. Note the third
outcome in that output: `Check unavailable: …` is *not* "healthy" — a check that
could not run says so, because an unsupported or failed check silently reading
as clean is the single worst bug a tool like this can have.

### `rescue scan --json` — machine-readable output

```console
$ rescue scan --json | head -40
{
  "schema_version": 1,
  "platform": "linux",
  "modules": [
    {
      "name": "process_scanner",
      "status": "ok",
      "error": null,
      "findings": []
    },
```

A finding, in full:

```json
{
  "name": "linux_service_health",
  "status": "ok",
  "error": null,
  "findings": [
    {
      "title": "No time-synchronisation service appears to be running",
      "description": "Nothing on this machine is keeping the clock correct. …",
      "severity": "warning",
      "category": "integrity",
      "data": { "check": "time_sync_inactive" },
      "confidence": 0.7,
      "collected_at": null,
      "code": "integrity.linux_service_health.time_sync_inactive"
    }
  ]
}
```

`code` is the stable finding-type identifier that links a finding to a
remediation walkthrough in `guides/remediation/`. `status` is `"ok"` or
`"error"`; `error` carries the reason a check could not run. Serializer:
`rescue/serialize.py`.

### `rescue run <module> --yes` — run specific modules

```console
$ rescue run disk_space --yes
System: Ubuntu 24.04.4 LTS 6.18.5-fc-v18 | Intel(R) Xeon(R) Processor @ 2.10GHz | x86_64
Running 1 module(s)...

=== disk_space ===
Found 4 issue(s):
  [critical] Disk /opt/rclone is 100% full: /dev/vdb mounted at /opt/rclone: 9.8 MB used of 9.8 MB (0.0 B free)
  [warning] Disk /opt/claude-code is 90% full: /dev/vdc mounted at /opt/claude-code: 274.1 MB used of 304.8 MB (24.6 MB free)
  [critical] Disk /mnt/skills/public is 100% full: /dev/vde mounted at /mnt/skills/public: 768.0 KB used of 768.0 KB (0.0 B free)
  [critical] Disk /mnt/skills/examples is 100% full: /dev/vdf mounted at /mnt/skills/examples: 5.5 MB used of 5.5 MB (0.0 B free)

Actions taken: 4
  Disk space report for /opt/rclone: MANUAL ACTION REQUIRED
  Disk space report for /opt/claude-code: MANUAL ACTION REQUIRED
  Disk space report for /mnt/skills/public: MANUAL ACTION REQUIRED
  Disk space report for /mnt/skills/examples: MANUAL ACTION REQUIRED
```

`--yes` skips the confirmation prompt. Without it, `rescue run` prints the check
result and then asks `Apply fixes for disk_space? [y/N]` before calling `fix()`
at all (`rescue/cli.py`, the `run` command).

`MANUAL ACTION REQUIRED` is what an `ActionKind.GUIDANCE` action prints. The
module is telling you what to do; it has changed nothing. Only actions of kind
`MUTATION` that ran and succeeded count as changes to the system — see
[the safety section](#will-this-download-something-malicious) below.

### `rescue profiles` — list threat-model profiles

```console
$ rescue profiles
ai_worm_response — AI Worm & Spyware Response
    Comprehensive scan for AI-led worm compromise (Shai Halud, Miasma, SANDWORM_MODE, SesameOp) and mobile spyware. …
digital_security_reset — Digital Security Reset
    Post-compromise recovery for someone who has been hacked or suspects their accounts or device have been compromised. …
home_for_the_holidays — Home for the Holidays
    Help a family member get their device cleaned up, secured, and documented in one visit. …
home_network_intrusion — Home Network Intrusion & Cryptojacking Response
    Response for a household whose Wi-Fi has been broken into, and for the cryptojacking and monitoring software that tends to arrive with it. …
identity_theft_recovery — Identity Theft Recovery
    Step-by-step recovery for someone whose identity has been stolen: credit and account freezes, the official reports that unlock legal protections, disputing fraudulent accounts, and the long tail of monitoring afterwards. …
iphone_spyware_check — iPhone / iPad Spyware Check
    Scans a local iPhone or iPad backup for known mercenary-spyware indicators (Pegasus, Predator, and similar) using Amnesty International's Mobile Verification Toolkit (MVT). …
linux_security_checkup — Linux Security Checkup
    A read-only security and health review of a Linux machine, in one command. … Nothing is changed: every module reports what it found and, where there is something to do, tells you the exact command to do it yourself. A check that needs root and does not have it says so rather than reporting a clean result.
```

(Descriptions trimmed at `…`; the real output prints them in full.) A profile
narrows the modules that run and names the guides that go with them:
`rescue --auto --profile iphone_spyware_check`, for instance, is the one-command
form of `docs/CHECK_IPHONE_FOR_SPYWARE.md`.

On Linux, `rescue --auto --profile linux_security_checkup` is the whole review
in one command — firewall state, SSH exposure, who can become root, disk
encryption, boot persistence, pending security updates, failed services, and the
journal errors that precede a drive or memory failure:

```console
$ rescue --auto --profile linux_security_checkup
...
--- Skipped (requires confirmation) ---
  [safe] linux_package_updates: 2 issue(s)
  [safe] linux_service_health: 1 issue(s)
  [safe] disk_space: 4 issue(s)
  [safe] linux_account_audit: 2 issue(s)
  [safe] linux_disk_encryption_check: 1 issue(s)
  [safe] linux_firewall_check: 1 issue(s)
  [safe] linux_persistence_audit: 1 issue(s)

Run 'rescue run <module>' to address these individually.
```

Note what auto mode did with those: nothing. It found them and stopped.

### `rescue guide <profile>` — resume a walkthrough

```console
$ rescue guide digital_security_reset
=== Digital Security Reset: Phase 0 — Emergency Grounding ===
Estimated time: 10 minutes

[human] [pending] Step 1: Ground yourself
[human] [pending] Step 2: Check whether you can still get in
[human] [pending] Step 3: Write down what you've already noticed

Run again with --complete <step number> to mark a step done.
```

```console
$ rescue guide digital_security_reset --complete 1
Marked step 1 complete for phase 0.

=== Digital Security Reset: Phase 0 — Emergency Grounding ===
Estimated time: 10 minutes

[human] [done] Step 1: Ground yourself
[human] [pending] Step 2: Check whether you can still get in
[human] [pending] Step 3: Write down what you've already noticed

Run again with --complete <step number> to mark a step done.
```

Steps are tagged `[human]` or `[automatable]`. A step may only be tagged
automatable if a registered module can actually perform it — `rescue validate`
enforces that (`rescue/validate.py`, `validate_guides`). Finishing every step in
a phase advances you to the next one on the following run.

### `rescue export` — redacted case report

```console
$ rescue export
Wrote /root/.rescue/cases/case-20260805T230525Z.json
Wrote /root/.rescue/cases/case-20260805T230525Z.md

Both files are redacted, but module output is free text — read them before sharing.
```

Two files: JSON for tooling, Markdown for people. The Markdown starts like this:

```markdown
# Rescue case report

- Generated: 2026-08-05T23:04:03+00:00
- Profile: none (full scan)
- System: Ubuntu 24.04.4 LTS 6.18.5-fc-v18 (x86_64)

## Summary

- Modules run: 26
- Modules reporting findings: 11
- Checks that failed to run: 3
- Checks not supported here: 0
- Total findings: 16
- System changes made: 0
- Manual actions still required: 0
```

Redaction runs on the way out, not as a review step you might forget:
private-key blocks, `Authorization:` headers, `api_key=`/`token=`/`password=`
assignments, GitHub/OpenAI/Slack/AWS/JWT token shapes, email addresses, your
account name, and your home-directory path are all replaced before anything is
written (`rescue/case.py`). Use `--stdout` to print the JSON instead of writing
files, `--output DIR` to write elsewhere, `--profile NAME` to scope it.

### `rescue validate` — check the shipped catalog

```console
$ rescue validate
[warning] registry:documentation: 264 of 287 modules have no docstring explaining what they check or why (accessibility_check, accessibility_permissions, ai_threat_indicators, ai_worm_filesystem, ai_worm_git_ssh, and 259 more)

287 modules, 7 profiles, 110 guide phases checked: 0 error(s), 1 warning(s).
Catalog is consistent.
```

Errors mean the catalog is internally broken — duplicate module names, a profile
naming a module that does not exist, a dependency cycle, `auto_apply` on a
non-SAFE module, a guide advertising a step as automatable that nothing can do.
There are currently **0 errors**, and CI gates on that.

`rescue validate --strict` promotes warnings to failures. **It currently exits
1**, on the one outstanding warning: 264 of 287 modules carry no docstring. That
is a real documentation debt, and `--strict` will keep failing until it is paid
down — which is why CI runs the plain form for now, with the workflow comment
saying exactly what has to be true before `--strict` goes back on.

### `rescue threat-remediation` — regenerate the threat map

```console
$ rescue threat-remediation
Wrote /home/user/multiverse-device-rescue/docs/THREAT_REMEDIATION.md (8 threats)
```

Generated from `docs/threat_remediation_map.yaml`, and validated against the
live registry first: every module name, profile, and finding code the map
references must exist, or the command prints errors and exits 1 without writing.
The sibling command `rescue remediation-catalog` regenerates
`docs/REMEDIATION_CATALOG.md` the same way.

### Other commands

| Command | What it does |
| --- | --- |
| `rescue --auto` | Run all checks unattended. Read-only in practice — see below. |
| `rescue --auto --profile NAME` | Same, scoped to one profile's modules. |
| `rescue update [--check\|--dry-run\|--yes\|--sideload FILE]` | Fetch signed **data** content updates. |
| `rescue update --rollback` | Return to the content version applied before the current one. |
| `rescue update --use-bundled` | Deactivate downloaded content; use what shipped with the install. |
| `rescue trust revoke ID --reason …` / `rescue trust list-revoked` | Stop trusting a content signer on this machine. |
| `rescue explain`, `rescue recommend`, `--copilot` | Opt-in AI layer. Off unless you set an API key or `OLLAMA_HOST`. |
| `rescue version` | `multiverse-device-rescue 0.1.0` |

---

## Will this download something malicious?

Fair question. It is a security tool that asks you to run it on a machine you
are already worried about. Here is what you can check for yourself, with the
file to read in each case.

### It does not change anything unless you say so

`ModuleBase.auto_apply` defaults to `False` (`rescue/module_base.py`). A module
is only mutated-by-default in unattended mode if it *both* sets
`auto_apply = True` *and* declares `RiskLevel.SAFE`.

**Zero shipped modules set `auto_apply = True`.** Verify it yourself:

```bash
grep -rn "auto_apply" modules/ --include='*.py' | grep -v __pycache__
# (no output)
```

The only occurrences anywhere in the tree are the default in
`rescue/module_base.py`, the validator that rejects `auto_apply=True` on a
non-SAFE module (`rescue/validate.py`), and test fixtures. So `rescue --auto` is
read-only today, not by policy but by the absence of any opt-in.

In `rescue run`, a fix runs without asking only when you passed `--yes` or the
module opted in. Otherwise you get `Apply fixes for <module>? [y/N]` first
(`rescue/cli.py`).

### Advice is never reported as a change

`FixResult` has two separate properties (`rescue/models.py`):

```python
@property
def executed_mutations(self) -> list[Action]:
    """Actions that actually changed the system: executed MUTATIONs only.

    Guidance is never a system change, so it is excluded here regardless of
    any ``executed``/``success`` flags a module may set on it.
    """
    return [a for a in self.actions
            if a.kind == ActionKind.MUTATION and a.executed and a.success]

@property
def guidance_actions(self) -> list[Action]:
    return [a for a in self.actions if a.kind == ActionKind.GUIDANCE]
```

A module that writes instructions and marks them `success=True` cannot inflate
the change count: `executed_mutations` filters on `kind` first. The auto-mode
summary reports the two separately — "made 0 system change(s); N manual
action(s) require you" — and the per-module report prints guidance as
`MANUAL ACTION REQUIRED` rather than `OK` (`rescue/module_base.py`, `report()`).

### It checks its own files at launch

`rescue/security/integrity.py` ships a SHA-256 manifest of every `.py` file in
the `rescue/` package — currently 56 entries in
`rescue/security/integrity_manifest.json` — and recomputes it on every launch.
Modified, missing, *and* unexpectedly added files all fail the check. Module
data and guide Markdown are deliberately excluded, because those are exactly
what `rescue update` is allowed to change.

Check it yourself, without trusting the tool's own report:

```bash
python - <<'PY'
from pathlib import Path
from rescue.security.integrity import IntegrityManifest, verify_package_integrity
m = IntegrityManifest.from_json_bytes(Path("rescue/security/integrity_manifest.json").read_bytes())
r = verify_package_integrity(Path("rescue"), m)
print("ok:", r.ok, "| tampered:", r.tampered, "| missing:", r.missing, "| added:", r.added)
PY
# ok: True | tampered: [] | missing: [] | added: []
```

Or recompute it and diff:

```bash
python scripts/generate_integrity_manifest.py && git diff --stat rescue/security/integrity_manifest.json
```

**Honest limit:** the launch-time check *warns and continues*. Here is a real
warning, captured from this checkout while a file under `rescue/tui/` had been
changed without regenerating the manifest:

```
WARNING: rescue's own installed files do not match the expected integrity manifest.
  modified: tui/app.py
  missing:  tui/screens/guide_placeholder.py
Consider reinstalling the tool. Continuing with existing files.
```

That goes to stderr, and the tool then runs anyway (`_run_startup_integrity_check` in
`rescue/cli.py` catches every exception and never blocks). It is a tripwire, not
a gate. It is also skipped entirely inside a PyInstaller bundle, where the loose
`.py` files it hashes do not exist on disk. And the manifest is only as good as
the copy you have — it detects post-install tampering, not a bad download.

### Content updates are data, signed by two people

`rescue update` pulls from a git content repository. Three things constrain it:

1. **Two distinct maintainer approvals.** `required_approvals = 2`
   (`rescue/update/config.py`). A commit is accepted only when at least two
   *different* trusted, non-revoked signers each have a validly-signed git tag
   pointing at that exact commit (`rescue/update/verify.py`,
   `verify_commit_approval`). Verification uses a throwaway keyring built solely
   from the public keys shipped in the package, never your ambient GPG keyring or
   SSH allowed-signers file. Anything unexpected is treated as "does not count".
2. **Placeholder keys are rejected.** `validate_trusted_signers`
   (`rescue/security/signers.py`) raises if any signer has empty or
   `REPLACE_WITH_…` key material, and the update engine calls it at construction.
3. **Data only, never Python.** `validate_content_paths`
   (`rescue/update/manifest.py`) restricts updated paths to `modules/`,
   `guides/`, `profiles/` with suffixes in `.json .md .toml .txt .yaml .yml` —
   no absolute paths, no `..`. At runtime, `rescue/runtime.py` resolves *data*
   from applied content (`content_file`, `content_directory`) while executable
   module code always comes from `bundled_root()`. An update cannot ship you new
   Python.

**Honest limit:** `rescue/security/trusted_signers.json` in this repository
contains three placeholder entries. There is no real key material yet. The
practical consequence, verified:

```console
$ rescue update --check
Update failed: trusted signer configuration contains placeholder or missing key material
Continuing with existing content.
$ echo $?
1
```

`rescue update` cannot do anything at all until real maintainer keys exist. The
software guard works; the trust root is not populated. Roadmap P0#3.

### An update you can back out of

Two recovery paths, neither of which needs the network
(`rescue/update/engine.py`, `rescue/update/repo.py`):

```console
$ rescue update --rollback      # return to the previously applied content version
$ rescue update --use-bundled   # deactivate downloaded content entirely
```

`--rollback` re-verifies maintainer approval rather than trusting that the
earlier version was approved when it was applied — a signer can be revoked in
between, and revocation that did not apply to content already on the machine
would just be a note about future downloads. If the previous version no longer
passes, it refuses and points at the other path.

`--use-bundled` clears the applied-content marker so `rescue/runtime.py` falls
back to the modules, profiles, and guides that shipped inside the install. It
deliberately does not construct the update engine, so it works even when the
trusted-signer configuration is broken or — as in this repository today — not
populated at all. Verified:

```console
$ rescue update --use-bundled
Updated content is deactivated. The tool will use the modules, profiles and guides
that shipped with the installed package. Nothing was deleted; `rescue update` can
activate downloaded content again.
$ echo $?
0
```

An escape hatch that depends on the thing that failed is not an escape hatch.

### It does not phone home

The read-only path — `scan`, `run`, `export`, `validate`, `guide`, `profiles`,
`--auto` — makes no network connections. Nothing is uploaded, no telemetry, no
analytics, no crash reporting. There is no HTTP client anywhere in `rescue/`
outside the AI package — the one hit is the lazy `httpx` import in the Ollama
provider:

```bash
grep -rn "import httpx\|import requests\|urllib.request" rescue/ --include='*.py'
# rescue/ai/providers/ollama_provider.py:4:    import httpx
```

Exactly two code paths can reach the network, and both need you to act first:

- **`rescue update`** runs `git fetch` against the content repo
  (`rescue/update/repo.py`). It only ever downloads; it uploads nothing. Today
  it fails closed on the placeholder trust config, above.
- **The AI layer** — `--copilot`, `rescue explain`, `rescue recommend` — is off
  unless you set `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, or `OLLAMA_HOST`
  (`rescue/ai/factory.py` returns `None` otherwise, and the CLI prints
  "requested but no AI provider is configured"). When you do turn it on, be
  clear-eyed about what it sends: a summary line per finding
  (`[category/module] (severity) title: description`, see
  `rescue/ai/explainer.py`) goes to the provider you configured. Point
  `OLLAMA_HOST` at a local model if you would rather that never leaves the
  machine.

### It never asks for a password, a 2FA code, or a recovery key

There is no `getpass` prompt and no `hide_input` prompt anywhere in the tool.
The only interactive input in the CLI is `click.confirm` (a y/N question) and
the free-text chat in `rescue recommend`, which is part of the opt-in AI layer.
The one `getpass` import, in `rescue/case.py`, calls `getpass.getuser()` — it
reads your username so it can *redact* it from exports.

The `digital_security_reset` profile says so in its own description, and it is
structural: changing passwords, enabling 2FA, and revoking sessions all happen
at the provider, in the guide, done by you. The tool reports what is observable
on the device and nothing more.

### Read any module before you run it

Every module is a single readable file:

```bash
less modules/security/linux_ssh_hardening/__init__.py
less modules/performance/disk_space/__init__.py
```

Path convention: `modules/<category>/<name>/__init__.py`, exporting a class named
`Module`. `check()` gathers, `fix()` acts. If a module reads a path or shells
out, you will see it there. For a bulk view, `rescue scan --json` gives you every
finding with its module name, severity, and code, so you can diff runs or feed
them to your own tooling.

### What is *not* yet true

Overstating this section would make the rest of it worthless, so:

- **Module discovery imports arbitrary local Python in-process.**
  `discover_modules` (`rescue/registry.py`) does
  `spec.loader.exec_module(py_module)` for every `modules/*/*/__init__.py` on
  disk. There is no sandbox, no signature check on module code, no subprocess
  isolation. Anything that can write into `modules/` gets code execution in the
  rescue process the next time it runs — which matters most in exactly the
  situation the tool is for. This is roadmap P0#10 and it is not fixed.
- **The trust root is unpopulated.** As above: placeholder signers, so signed
  updates cannot be exercised end to end.
- **Command bounding is written but not adopted.** `rescue/command.py` provides
  a timeout- and output-capped runner and `rescue/fsbounds.py` provides bounded
  traversal, and the orchestrator enforces a 60-second per-module timeout with
  daemon-thread isolation (`rescue/orchestrator.py`). But 758 direct
  `subprocess.run` calls remain inside `modules/`, and only 14 module files
  import `rescue.command`. The session is bounded; individual calls inside a
  module often are not.
- **`rescue validate --strict` fails today** — 0 errors, but 264 of 287 modules
  have no docstring. CI gates on errors only until that is paid down.
- **CI has not run on this repository yet.** The badges at the top point at real
  workflow files; until a push to `main` triggers them they will render as "no
  status".

---

## Repository map

```
rescue/                  The engine. Everything here is bundled, never updatable.
├── cli.py               Every command on this page.
├── models.py            Finding, CheckResult, FixResult, Action, RiskLevel, Severity.
├── module_base.py       ModuleBase: check(), fix(), report(), auto_apply=False.
├── registry.py          Module discovery (imports module Python — see P0#10).
├── orchestrator.py      Runs checks with a per-module timeout + session budget.
├── command.py           Bounded subprocess runner (timeout + output cap).
├── fsbounds.py          Bounded filesystem traversal; 3.11-safe no-follow stats.
├── validate.py          Whole-catalog validation behind `rescue validate`.
├── case.py              Redacted rescue-case export behind `rescue export`.
├── profiles.py, guides.py, session.py, remediation.py, threat_map.py
├── runtime.py           Resolves bundled vs. applied content; data-only updates.
├── serialize.py         `scan --json` schema.
├── security/            SHA-256 self-integrity manifest + trusted signer config.
├── update/              Signed git content updates: repo, manifest, verify, engine.
├── ai/                  Opt-in AI layer (providers, explainer, recommender).
├── profiler/            Per-platform system profile collection.
└── tui/                 Textual interface: screens, styles.

modules/<category>/<name>/__init__.py    One check per directory; class `Module`.
modules/<category>/<name>/data/*.json    Signature/IOC data — updatable content.
profiles/*.yaml          Threat-model profiles: which modules run, which guides go with them.
guides/<profile>/phase_N.md              Multi-phase human walkthroughs.
guides/remediation/*.md                  Per-finding-code fix walkthroughs.
tests/                   The pytest suite, one file per module or subsystem.
desktop/                 Electron wrapper (main.js, renderer/) around the engine.
scripts/                 build.py (PyInstaller), build-macos-app.sh,
                         build-windows.bat, generate_integrity_manifest.py.
site/                    Static landing page + Dockerfile.
docs/                    Roadmap, status, threat map, catalogs, design docs.
.github/workflows/       tests.yml, docs.yml.
```

### Coverage, by the numbers

From `rescue validate` and the registry (`rescue/registry.py`) on this checkout:

| | Count |
| --- | ---: |
| Modules discovered | **287** |
| — declaring macOS support | 199 |
| — declaring Windows support | 100 |
| — declaring Linux support | 26 |
| — supporting all three | 17 |
| Profiles | 7 |
| Guide phases + remediation walkthroughs | 110 |

By category: security 118, integrity 106, performance 51, network 8,
bloatware 4.

macOS has the deepest coverage; Windows is next. Linux is newly real rather than
broad — 9 Linux-specific modules (`modules/security/linux_ssh_hardening`,
`linux_firewall_check`, `linux_account_audit`, `linux_persistence_audit`,
`linux_disk_encryption_check`, `modules/integrity/linux_service_health`,
`linux_journal_errors`, `linux_package_updates`, and
`modules/performance/linux_memory_pressure`) plus the cross-platform modules
that declare Linux. Mobile is human-guided only; there are no Android or iOS
device modules, and the iPhone spyware check works on a *backup* stored on the
computer, not on the phone.

Reproduce the numbers:

```bash
python -m rescue.cli validate | tail -2
python -c "
from pathlib import Path
from collections import Counter
from rescue.registry import discover_modules
m = discover_modules(Path('modules'))
print(len(m), Counter(p.value for x in m for p in x.platforms), Counter(x.category for x in m))"
```

---

## Project status

Version 0.1.0. Read [docs/ROADMAP_STATUS.md](docs/ROADMAP_STATUS.md) before
trusting anything here — it is candid about which roadmap items were recorded as
done and later turned out not to be, and it is the document this README defers
to.

**Works today:** read-only scanning on macOS, Windows, and Linux; profile- and
guide-driven walkthroughs with saved progress; the TUI; redacted case export;
whole-catalog validation; the self-integrity manifest; a `pip install .` that
carries its own content.

**In progress:** routing module subprocess calls through the bounded runner
(758 direct calls remain); remediation-code coverage (~38% of pre-existing
modules declare `emits_codes`); populating `confidence`/`collected_at`/
`supported` on findings; docstrings for the 264 modules that lack them; process
isolation for module discovery.

**Needs people, not code:** real maintainer signing keys with custody and
rotation; signed release artifacts and SBOMs; smoke tests on real hardware at
standard and elevated privilege.

### Safety boundary

- Run this on a **known-clean device** where you can. A compromised machine can
  lie to any tool running on it, this one included.
- If you are dealing with an **active compromise** — money moving, an attacker
  currently in your accounts, a business at risk — get professional incident
  response. This tool is for finding and cleaning up, not for fighting someone
  in real time.
- Review results before changing security settings or deleting anything. A
  finding is an observation, not a verdict.
- Do not enter account passwords, recovery codes, or API tokens into this tool.
  It will never ask.
- `rescue export` output is redacted but module output is free text. Read a case
  file before you paste it anywhere.

---

## Contributing and security

[CONTRIBUTING.md](CONTRIBUTING.md) covers dev setup, the test suite, catalog
validation, regenerating the integrity manifest (required whenever `rescue/*.py`
changes, or CI fails), and module authoring rules.

[SECURITY.md](SECURITY.md) covers how to report a vulnerability privately, and
what counts as one here — note that a check reporting a false healthy result is
a security bug in this project, not a cosmetic one.
