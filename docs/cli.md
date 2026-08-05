# CLI reference

Every command and flag below is taken from
[`rescue/cli.py`](https://github.com/lizTheDeveloper/multiverse-device-rescue/blob/main/rescue/cli.py).
If a flag is not on this page, it does not exist.

```console
$ rescue --help
Usage: rescue [OPTIONS] [COMMAND] [ARGS]...

  Multiverse Device Rescue — system diagnostic and repair toolkit.

Options:
  --auto          Run all checks and apply safe fixes automatically.
  --profile TEXT  Threat-model profile to apply (filters/configures modules).
  --copilot       Enable AI-powered plain-language explanations (requires an
                  API key or local Ollama).
  --help          Show this message and exit.

Commands:
  explain              Run all diagnostic checks and print an AI...
  export               Run read-only checks and write a redacted...
  guide                Render the guide walkthrough for a profile,...
  profiles             List available threat-model profiles.
  recommend            Answer a few questions to get a recommended...
  remediation-catalog  Regenerate docs/REMEDIATION_CATALOG.md from...
  run                  Run specific modules by name.
  scan                 Run read-only checks.
  threat-remediation   Regenerate docs/THREAT_REMEDIATION.md from the...
  trust                Manage locally-revoked content-repo signers.
  update               Update module data and guide content from the...
  validate             Validate the shipped catalog: modules, profiles,...
  version              Show version information.
```

If the `rescue` script is not on your `PATH`, every invocation below also works
as `python -m rescue.cli …`.

## Startup behaviour

Two things happen on **every** invocation, before any command runs.

**The self-integrity check.** The tool recomputes SHA-256 hashes of its own
installed `rescue/**/*.py` files and compares them to the manifest shipped with
the package. On a mismatch it prints, to stderr:

```text
WARNING: rescue's own installed files do not match the expected integrity manifest.
  modified: cli.py
  missing:  security/signers.py
Consider reinstalling the tool. Continuing with existing files.
```

It is deliberately **non-blocking**: it warns and continues, and any exception
inside the check itself is swallowed. It is also skipped entirely inside a
PyInstaller bundle, where there are no loose `.py` files to hash. Details in
[Trust and safety](trust-and-safety.md#the-self-integrity-manifest).

**Command dispatch.** With `--auto`, auto mode runs. With no subcommand and no
`--auto`, the interactive terminal UI launches. Otherwise the named subcommand
runs.

---

## `rescue` — the terminal UI

```console
$ rescue
```

With no subcommand and no `--auto`, launches the interactive TUI against the
installed modules and guides.

---

## `rescue --auto` — unattended scan

```console
$ rescue --auto [--profile <name>] [--copilot]
```

Runs every applicable check, then attempts fixes for modules that qualify.
**On the shipped tree nothing qualifies**, so this is a read-only whole-machine
scan with a summary. A module is only auto-fixed when it is `RiskLevel.SAFE`
*and* sets `auto_apply = True`; no shipped module does.

| Flag | Effect |
| --- | --- |
| `--auto` | Run all checks and attempt eligible fixes. |
| `--profile <name>` | Only run the modules the named profile selects, with the profile's per-module configuration applied. Exits `1` on an unknown or invalid profile. |
| `--copilot` | After the scan, send the findings to a configured AI provider for a plain-language narrative. Opt-in; see [Privacy](privacy.md). |

Output:

```console
$ rescue --auto
==================================================
Multiverse Device Rescue — Auto Mode
==================================================

Scanned 26 module(s), found 20 issue(s). Auto mode is read-only: made 0 system
change(s); 0 manual action(s) require you.

=== linux_service_health ===
Found 1 issue(s):
  [warning] No time-synchronisation service appears to be running: ...
```

Modules that found issues but were not eligible for an unattended fix are
listed under `--- Skipped (requires confirmation) ---` with their risk level,
and the tool tells you to run `rescue run <module>` for each. If the selected
profile ships a guide, the available walkthroughs are named at the end.

---

## `rescue scan` — read-only checks

```console
$ rescue scan [--json]
```

Runs every check that supports the current platform and prints one report per
module. Never applies a fix, never prompts, and takes no profile — for a
profile-scoped scan use `rescue --auto --profile <name>` or `rescue export
--profile <name>`.

| Flag | Effect |
| --- | --- |
| `--json` | Emit structured results to stdout instead of the human report. |

The JSON shape is `schema_version` 1:

```json
{
  "schema_version": 1,
  "platform": "linux",
  "modules": [
    {
      "name": "linux_package_updates",
      "status": "ok",
      "error": null,
      "findings": [
        {
          "title": "1 package update(s) available",
          "description": "Ordinary updates — bug fixes and new versions...",
          "severity": "info",
          "category": "integrity",
          "data": {"check": "updates_pending", "manager": "apt"},
          "confidence": 0.9,
          "collected_at": null,
          "code": "integrity.linux_package_updates.updates_pending"
        }
      ]
    }
  ]
}
```

!!! warning "`--json` output is not redacted"
    `scan --json` is the raw result stream, intended for tooling on the same
    machine. Finding descriptions and `data` payloads contain real paths and
    real hostnames. If you intend to send results to another person, use
    [`rescue export`](#rescue-export-redacted-case-report) instead, which
    redacts.

    Note also that `status` here is only `"ok"` or `"error"` — this serializer
    does not distinguish *unsupported* from *healthy*. The human report and the
    case export both do.

---

## `rescue run` — specific modules

```console
$ rescue run <module_name> [<module_name> ...] [--yes] [--copilot]
```

Runs one or more named modules in order. Unknown module names print the full
list of available names to stderr and exit `1`.

| Flag | Effect |
| --- | --- |
| `--yes` | Skip confirmation prompts and run each module's `fix()` when its check found issues. Also switches the run mode from `MANUAL` to `CLI`. |
| `--copilot` | Append an AI plain-language explanation of the findings. |

Without `--yes`, a module whose check found issues prompts:

```text
Apply fixes for linux_account_audit? [y/N]:
```

Answering anything but yes moves on without calling `fix()`. A module whose
check errored is reported and skipped — it is never offered a fix. If `fix()`
itself raises, the tool prints `Fix unavailable: <error>` and continues to the
next module rather than aborting the run.

!!! danger "`--yes` is the flag that can change your system"
    `--yes` applies fixes without asking, including for modules at `moderate`
    and `destructive` risk levels. Everything else in the tool asks first.

---

## `rescue export` — redacted case report

```console
$ rescue export [--profile <name>] [--output <dir>] [--stdout]
```

Runs read-only checks and writes a **rescue case**: a JSON record for tooling
and a Markdown summary for people. Both are redacted before anything is
written. This is the command to use when you want to hand your results to
someone who can help.

| Flag | Effect |
| --- | --- |
| `--profile <name>` | Only run the modules the named profile selects. Exits `1` on an unknown or invalid profile. |
| `--output <dir>` | Directory to write into. Default: `~/.rescue/cases`. |
| `--stdout` | Print the JSON case to stdout instead of writing any files. |

```console
$ rescue export
Wrote /home/you/.rescue/cases/case-20260805T230542Z.json
Wrote /home/you/.rescue/cases/case-20260805T230542Z.md

Both files are redacted, but module output is free text — read them before
sharing.
```

Files are named `case-<UTC timestamp>.{json,md}` and written with owner-only
permissions (`0600`) where the filesystem supports it. The case records
findings, actions, whether each action actually changed the system, rollback
and verification metadata where a module supplies it, and counts of failed and
unsupported checks. Redaction removes credential-shaped strings, email
addresses, your account name, your home directory path, and the hostname. See
[Privacy](privacy.md#the-redacted-case-export).

---

## `rescue profiles` — list scenarios

```console
$ rescue profiles
ai_worm_response — AI Worm & Spyware Response
    Comprehensive scan for AI-led worm compromise (Shai Halud, Miasma, ...
digital_security_reset — Digital Security Reset
    Post-compromise recovery for someone who has been hacked ...
```

No flags. Prints each profile's name, display name, and description. Prints
`No profiles found.` if profile discovery came up empty — which on a normal
install means the packaged content is missing.

---

## `rescue guide` — phased walkthrough

```console
$ rescue guide <profile_name> [--complete <step number>]
```

Renders the current phase of a profile's guide and remembers where you were.

| Flag | Effect |
| --- | --- |
| `--complete <n>` | Mark step `n` of the current phase complete before rendering. |

```console
$ rescue guide identity_theft_recovery
=== Identity Theft Recovery: Phase 0 — The First Hour ===
Estimated time: 1 hour

[human] [pending] Step 1: Start a recovery log before you do anything else
[human] [pending] Step 2: Write down what you already know
...

Run again with --complete <step number> to mark a step done.
```

Each step is tagged `[automatable]` (a module can do this part) or `[human]`
(only you can), and `[done]` or `[pending]`. When every step of a phase is
marked complete, the next invocation announces `Phase N complete! Moving to
Phase N+1.` and renders the next phase; after the last one it prints `All
phases complete!`.

State lives in `~/.rescue/sessions/<profile>.json`. Profiles with no guide
content — `ai_worm_response` and `iphone_spyware_check` — print `No guide
content found for profile: <name>`. An unknown profile name exits `1`.

---

## `rescue validate` — check the shipped catalog

```console
$ rescue validate [--strict]
```

Validates everything the installation ships, without executing any module's
`check()`. Useful to confirm an install is complete and internally consistent.

| Flag | Effect |
| --- | --- |
| `--strict` | Treat warnings as failures. Used by CI. |

It verifies that module names are unique; that `depends_on` entries resolve and
form no cycles; that platforms and risk levels are real enum members; that
`priority` is within 0–100; that no module sets `auto_apply = True` at a
non-`SAFE` risk level; that every profile references only modules that exist
and names guide sets that have phases on disk; and that no guide advertises a
step as automatable when no such step exists.

Errors mean the catalog is inconsistent. Warnings mean metadata is legal but
degraded — a module with no `estimated_duration`, a module with no docstring, a
remediation walkthrough whose `remediates:` code no module emits.

```console
$ rescue validate
[warning] registry:documentation: 264 of 287 modules have no docstring explaining
what they check or why (accessibility_check, accessibility_permissions,
ai_threat_indicators, ai_worm_filesystem, ai_worm_git_ssh, and 259 more)

287 modules, 7 profiles, 110 guide phases checked: 0 error(s), 1 warning(s).
Catalog is consistent.
```

Exit `0` when `report.ok(strict)` holds, `1` otherwise. On the current tree
`rescue validate` exits `0` and `rescue validate --strict` exits `1`, because
264 of the 287 modules still carry no docstring.

---

## `rescue recommend` — AI profile suggestion

```console
$ rescue recommend
```

An interactive conversation that ends in a recommended profile name. **This
command is itself the opt-in to the AI layer** — it does nothing without a
configured provider:

```console
$ rescue recommend
This feature requires an AI provider.
Set ANTHROPIC_API_KEY, OPENAI_API_KEY, or OLLAMA_HOST, then try again.
```

Type `quit` or `exit` at the prompt to leave without a recommendation. A failed
AI request is reported and you are re-prompted rather than dropped. No flags.

---

## `rescue explain` — AI narrative of a fresh scan

```console
$ rescue explain
```

Runs every check fresh (never applies fixes) and hands the findings to the
configured AI provider for a plain-language narrative. Like `recommend`, this
command is itself the opt-in, and prints the same "requires an AI provider"
message when none is configured. No flags.

Note that `explain` runs modules directly rather than through the orchestrator,
so the orchestrator's per-module timeout does not apply to it.

---

## `rescue update` — signed content updates

```console
$ rescue update [--check] [--dry-run] [--yes] [--sideload <bundle>]
$ rescue update --rollback [--dry-run]
$ rescue update --use-bundled
```

Fetches and applies updates to **module data and guide content** from the
content repository. Content updates carry data only — `.json`, `.md`, `.toml`,
`.txt`, `.yaml`, `.yml` under `modules/`, `guides/`, or `profiles/`. Python code
is never updated this way.

| Flag | Effect |
| --- | --- |
| `--check` | Report what is available and stop. Does not apply. |
| `--dry-run` | Print what applying would do, without applying. |
| `--yes` | Apply without the interactive confirmation prompt. |
| `--sideload <path>` | Apply a signed update from a local git bundle file instead of the network (air-gapped). The path must exist and be a file. |
| `--rollback` | Return to the content version applied before the current one. Re-verifies approval first. |
| `--use-bundled` | Deactivate downloaded content and use what shipped inside the install. Needs no network and no working trust configuration. |

`--rollback` and `--use-bundled` cannot be combined; doing so exits `2`.

Outcomes:

- **Up to date** — prints `Content is already up to date.` and exits `0`.
- **Available** — prints the version, who approved it, and the commit
  subjects, then applies (after confirming, unless `--yes`).
- **Not enough approvals** — prints `Refusing to apply -- not enough
  maintainer approvals yet.` and exits `1`. An update needs signed tags from
  **two distinct trusted, non-revoked signers** by default.
- **Fetch/trust failure** — prints `Update failed: …` and `Continuing with
  existing content.` to stderr, then exits `1`. A failed update never degrades
  the tool you already have.
- **Rejected content** — a commit whose file list falls outside the allowed
  directories or file types is rejected with `Update rejected: …` and exits
  `1`.

Full trust model in
[Trust and safety](trust-and-safety.md#signed-content-updates).

### Backing out of an update

Neither recovery path fetches anything. Rolling back to a version this machine
already had, or falling back to what the install shipped with, has to work when
the network is the problem — or when the update is.

**`rescue update --rollback`** returns to the content version applied before the
current one, using the previous-version marker `ContentRepo.checkout` writes.
It **re-verifies maintainer approval** on that older commit rather than trusting
that it was approved when it was first applied — a signer may have been revoked
since, and the whole point of revocation is that content they approved stops
being trusted, including content already on the machine.

```console
$ rescue update --rollback --dry-run
Would roll back to a1b2c3d4e5f6.

$ rescue update --rollback
Rolled back to a1b2c3d4e5f6.
```

It exits `1`, without changing anything, in two cases:

- *No previous version recorded* — nothing to roll back to. The message points
  you at `--use-bundled`.
- *No longer approved* — "most likely a signer has been revoked since it was
  applied. Refusing to roll back to it." Again, `--use-bundled` is the way out.

If the content repository cannot be loaded at all (a git error, or a broken
trust configuration), it exits `1` and tells you that `--use-bundled` still
works because it needs no signature check.

**`rescue update --use-bundled`** is the escape hatch of last resort. It
deactivates the downloaded content by removing the applied marker that
`runtime.active_content_root()` gates on, so the tool falls back to the modules,
profiles, and guides that shipped inside the installed package.

```console
$ rescue update --use-bundled
Updated content is deactivated. The tool will use the modules, profiles and
guides that shipped with the installed package. Nothing was deleted; `rescue
update` can activate downloaded content again.
```

Two properties make this the reliable path: **nothing is deleted** (the
checkout stays on disk and a later `rescue update` can reactivate it), and it
deliberately **does not construct an `UpdateEngine`**. Constructing one would
validate the trusted-signer configuration — and a machine whose trust config is
broken or unpopulated is exactly the machine that most needs to get back to
known-good content. An escape hatch that depends on the thing that failed is
not an escape hatch. It exits `0`, and it works today on this repository, where
the shipped signer keys are still placeholders. `--dry-run` has no effect on
this path.

---

## `rescue trust` — local signer revocation

```console
$ rescue trust revoke <signer_id> --reason "<why>"
$ rescue trust list-revoked
```

Stops trusting a content-repo signer's approvals **on this machine**,
immediately, without waiting for a new threshold-approved commit to remove
them.

| Command | Flag | Effect |
| --- | --- | --- |
| `trust revoke <signer_id>` | `--reason` (**required**) | Record the revocation with its reason. |
| `trust list-revoked` | — | Print revoked signer IDs, one per line, or `No signers revoked on this machine.` |

```console
$ rescue trust revoke maintainer-a --reason "key rotation announced 2026-08-01"
Revoked signer 'maintainer-a': key rotation announced 2026-08-01
```

Revocations persist to `~/.config/rescue/revoked_signers.json`. Revoking below
the approval threshold means updates stop applying — which is the safe failure.

---

## `rescue version`

```console
$ rescue version
multiverse-device-rescue 0.1.0
```

No flags.

---

## Maintainer commands

These regenerate documentation in the source tree and are meant for people
working on the project, not for end users.

### `rescue remediation-catalog`

```console
$ rescue remediation-catalog
Wrote /path/to/docs/REMEDIATION_CATALOG.md (510 codes)
```

Rebuilds [the remediation catalog](REMEDIATION_CATALOG.md) by joining every
module's `emits_codes` against the walkthroughs in `guides/remediation/`. No
flags. Writes into the project root's `docs/` directory.

### `rescue threat-remediation`

```console
$ rescue threat-remediation
Wrote /path/to/docs/THREAT_REMEDIATION.md (N threats)
```

Rebuilds [the threat map](THREAT_REMEDIATION.md) from
`docs/threat_remediation_map.yaml`. Validates the map against the live registry
first: any threat referencing an unknown profile, code, or module prints
`ERROR: …` to stderr and exits `1` without writing. No flags.

---

## Exit codes

| Code | Meaning |
| --- | --- |
| `0` | Success. Also used when an AI command exits early because no provider is configured, and when `rescue update` cancels at the confirmation prompt. |
| `1` | Unknown or invalid profile; unknown module name; `validate` found errors (or, with `--strict`, warnings); `update` was refused, failed, or had its content rejected; `update --rollback` found no previous version, found it no longer approved, or could not load the content repository; `threat-remediation` found an invalid threat map. |
| `2` | `rescue update --rollback --use-bundled` — the two recovery flags cannot be combined. |

A failing module never fails the process: a check that raises is caught and
reported as `Check unavailable: …`, and a `fix()` that raises is reported as
`Fix unavailable: …`. The run continues either way.

## Environment variables

| Variable | Used by | Effect |
| --- | --- | --- |
| `ANTHROPIC_API_KEY` | AI layer | Enables the Anthropic provider. |
| `OPENAI_API_KEY` | AI layer | Enables the OpenAI provider. |
| `OLLAMA_HOST` | AI layer | Enables the local Ollama provider. |
| `RESCUE_AI_PROVIDER` | AI layer | Force `anthropic`, `openai`, or `ollama`. Naming `ollama` explicitly also lets it default to `http://localhost:11434`. |
| `RESCUE_CONTENT_DIR` | Runtime | Override where applied content updates are read from. |
| `RESCUE_ASSETS_DIR` | Runtime | Override where bundled modules/profiles/guides are found. |

No AI provider is used unless one of the AI environment variables is set **and**
you invoke `--copilot`, `explain`, or `recommend`.
