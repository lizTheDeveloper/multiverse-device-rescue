# Trust and safety

This page exists to answer one question: **can this thing hurt my computer, or
download something that will?**

Every claim below names the file that implements it, so you can check rather
than believe. Where a guarantee is partial, it says so. A security tool that
overstates its own guarantees is teaching you the wrong habit.

## The short version

| Question | Answer |
| --- | --- |
| Does `rescue --auto` change my system? | No. Zero shipped modules opt in to unattended change. |
| Does it ever ask for a password, 2FA code, or recovery key? | No. There is no such prompt anywhere in the tool. |
| Does it send anything anywhere? | Only if you explicitly turn on the AI layer. Otherwise nothing leaves the machine. |
| Can an update push new Python code to my machine? | Not through the sanctioned path. Updates carry data files only, and content commits containing anything else are rejected. |
| Can I read what a check does before running it? | Yes. Every module is one plain Python file in the source tree. |
| Does it verify it has not been tampered with? | Yes, at every launch, with a SHA-256 manifest — but the check warns and continues rather than blocking. |

## What it reads, and what it writes

**Reads.** Local system state: process lists, disk and mount information,
network interfaces and the neighbour table, systemd units and cron entries and
launch agents, installed package lists, log and journal output, firewall and
SSH configuration, browser extension manifests, startup items, keychain
*metadata*. It does this by reading files and running standard system query
commands (`systemctl`, `ip`, `defaults`, `powershell`, `ufw`, and friends).

**Never reads.** The tool has no code path that opens a password manager
vault, extracts keychain or Credential Manager *contents*, reads browser
history or page contents, or opens your documents and photos. The
`evidence_bundle` module prints this list explicitly when it runs, under
"Never collected, under any circumstances".

**Writes.** Only these, and only when you ask:

| Path | Written by |
| --- | --- |
| `~/.rescue/sessions/<profile>.json` | `rescue guide` recording your progress |
| `~/.rescue/cases/case-<timestamp>.{json,md}` | `rescue export` |
| `~/.config/rescue/revoked_signers.json` | `rescue trust revoke` |
| `~/.local/share/rescue/content/` | `rescue update`, after signature verification |

Case files are written `0600` where the filesystem supports it, because even a
redacted case describes a machine's security posture and lands in a home
directory other local accounts may be able to read.

## Auto mode is read-only

This is the claim people most want proven, so here is the whole chain.

**1. The default.** `rescue/module_base.py`:

```python
class ModuleBase(ABC):
    ...
    # Opt-in to unattended mutation in auto mode. Default False keeps auto mode
    # read-only: a module is only auto-applied once its fix() is known to be an
    # idempotent, low-impact, reversible SAFE mutation and it sets this True.
    auto_apply: bool = False
```

**2. The gate.** `rescue/orchestrator.py`, in `run_fixes`:

```python
if mode == Mode.AUTO and (
    mod.risk_level != RiskLevel.SAFE
    or not getattr(mod, "auto_apply", False)
):
    # Auto mode is read-only unless a module has explicitly opted
    # in to unattended, idempotent SAFE mutation via `auto_apply`.
    continue
```

Both conditions must hold: `SAFE` **and** `auto_apply = True`. `SAFE` alone is
not enough, deliberately.

**3. The count.** Verify it yourself:

```console
$ grep -rn "auto_apply" modules/ | wc -l
0
```

**Zero.** Not zero set to `True` — zero mentions of the attribute at all across
all 287 shipped modules, so every one of them inherits `False`. As long as that
number is zero, `rescue --auto` cannot change anything, and the summary line
reflects it:

```text
Scanned 26 module(s), found 20 issue(s). Auto mode is read-only: made 0 system
change(s); 0 manual action(s) require you.
```

**4. The guardrail on the flag.** If a module ever does set `auto_apply = True`
at a non-`SAFE` risk level, `rescue validate` reports it as an **error**
(`rescue/validate.py`), and CI runs `rescue validate` on every pull request —
errors fail the build.

**5. What is *not* covered.** `rescue run <module> --yes` and answering `y` to a
confirmation prompt both call `fix()` regardless of `auto_apply`, and `fix()`
may mutate. That is the point of those flags. The read-only guarantee is about
*unattended* operation.

### Guidance is not a change

The data model separates the two, in `rescue/models.py`:

```python
class ActionKind(str, Enum):
    GUIDANCE = "guidance"
    MUTATION = "mutation"
```

and a system change is only counted when a mutation actually executed and
succeeded:

```python
@property
def executed_mutations(self) -> list[Action]:
    return [
        a for a in self.actions
        if a.kind == ActionKind.MUTATION and a.executed and a.success
    ]
```

A module cannot make "here is what you should do" appear in a report as
something that was done, even by setting `executed`/`success` flags on a
guidance action. The case export applies the same rule
(`rescue/case.py`), so a report you hand to someone else cannot overstate what
happened either.

## It never asks for your secrets

There is no prompt in the tool for an account password, a one-time code, a
recovery code, a seed phrase, or a password-manager master password. The only
interactive prompts that exist are:

- `Apply fixes for <module>?` (yes/no)
- `Apply this update?` (yes/no)
- the free-text conversation in `rescue recommend`, which is optional and only
  runs when you have configured an AI provider

Profiles state this explicitly. `digital_security_reset` ends its description
with: *"This tool never asks for an account password, a one-time code, or a
recovery code."* Account work — password changes, enabling 2FA, revoking
sessions — happens on each provider's own website, done by you, in the guide.

Some system checks may cause **your operating system** to prompt for your
administrator password (macOS authorisation dialogs, `sudo`, Windows UAC).
That is the OS asking, on its own dialog, and the tool never sees or stores
what you type. If something claiming to be this tool asks you to *type a
password into it*, it is not this tool.

## The self-integrity manifest

`rescue/security/integrity.py` ships a SHA-256 manifest of the tool's own
installed Python files — 56 entries covering `rescue/**/*.py`, stored in
`rescue/security/integrity_manifest.json`. Every launch recomputes those hashes
and compares.

```console
$ rescue update --check
WARNING: rescue's own installed files do not match the expected integrity manifest.
  modified: cli.py
Consider reinstalling the tool. Continuing with existing files.
```

That is real output from a development checkout where `cli.py` changed after
the manifest was last regenerated. It detects modified, missing, and *added*
files, and it needs no network access and no trust in anything beyond the local
filesystem.

**Be precise about what this is and is not.**

- It is **advisory, not blocking**. `_run_startup_integrity_check` in
  `rescue/cli.py` prints the warning and continues; the whole function is
  wrapped in a bare `except Exception: pass`. It is a tripwire, not a lock.
  Malware with write access to the install could equally rewrite the manifest.
- It covers the `rescue/` package's Python files **only**. Module data
  (`modules/*/data/*.json`)
  and guide content (`guides/**/*.md`) are deliberately excluded, because those
  are exactly the files `rescue update` is designed to legitimately change —
  hashing them would make every successful content update look like tampering.
  Module *code* under `modules/` is likewise not covered by this manifest.
- It is **skipped inside a PyInstaller bundle**, where there are no loose `.py`
  files on disk to hash.
- CI keeps it honest: the `integrity` job regenerates the manifest and fails
  the build on any diff, because a stale manifest prints a tamper warning on
  every launch and trains users to ignore the one signal that matters.

## Signed content updates

`rescue update` is the only command that brings anything onto your machine from
outside. Four separate properties constrain it.

**1. Data only, never Python.** A content commit is rejected unless every path
in it passes `validate_content_paths` (`rescue/update/manifest.py`):

- the first path segment must be `modules/`, `guides/`, or `profiles/`
- the extension must be one of `.json`, `.md`, `.toml`, `.txt`, `.yaml`, `.yml`
- anything under `guides/` must be `.md`; anything under `profiles/` must be
  YAML
- absolute paths and `..` traversal are rejected outright

A `.py` file cannot satisfy that list, so an approved update cannot deliver
executable code through the sanctioned path.

**2. Two independent maintainer approvals.** `rescue/update/config.py` sets
`required_approvals = 2`. Approval means a maintainer has pushed a git tag,
signed with GPG or SSH, named `approved/<signer_id>/<content_version>` and
pointing at the exact commit. A commit is only accepted once **two distinct**
trusted, non-revoked signers have valid signatures on it.

**3. Verification never trusts your local keyring.**
`rescue/update/verify.py` builds a throwaway `GNUPGHOME` and a scratch
`allowed_signers` file per call, populated *only* with the public keys shipped
in `rescue/security/trusted_signers.json`, and points `git verify-tag` at that.
Trust is decided by what the deployment ships, never by what happens to be
configured on your machine. It does no cryptography of its own — `git
verify-tag` does all of it — and any nonzero exit, unexpected output, or parse
failure is treated as "this tag does not count". Fail closed, always.

**4. Placeholder keys are rejected.** `validate_trusted_signers` in
`rescue/security/signers.py` raises if any signer's ID, key ID, or public key
starts with `REPLACE_WITH_`, or if the public key is missing, or if there are
fewer signers than required approvals. The update engine runs that check on
construction.

!!! warning "On the current release, `rescue update` cannot apply anything"
    The shipped `trusted_signers.json` contains three placeholder entries with
    `REPLACE_WITH_…` key material. Real key custody and rotation are a human
    task the project has not completed (roadmap P0#3: *"real signer key
    material, custody, rotation, revocation, threshold approvals, and the
    release-signing procedure"*). The result today:

    ```console
    $ rescue update --check
    Update failed: trusted signer configuration contains placeholder or missing key material
    Continuing with existing content.
    ```

    Exit code `1`, nothing fetched, nothing applied. The software guard works;
    the keys behind it are not real yet. Until they are, treat the update
    channel as closed and get new versions the way you got this one.

**Revoking a signer locally.** If a maintainer's key is compromised, you do not
have to wait for a new threshold-approved commit:

```console
$ rescue trust revoke maintainer-a --reason "key compromise announced 2026-08-01"
$ rescue trust list-revoked
maintainer-a
```

Revoking below the threshold means updates stop applying — which is the correct
failure.

**Air-gapped updates.** `rescue update --sideload <bundle>` takes a local git
bundle instead of a network fetch and runs it through the identical
verification and apply pipeline. There is exactly one place signatures are
checked and exactly one place a checkout happens, regardless of transport.

### An update you can back out of

A safety property that matters as much as verification: **you can undo an
update without the network and without a working trust root.** Two commands,
neither of which fetches anything.

`rescue update --rollback` returns to the content version applied before the
current one. Notably it **re-verifies approval on the older commit** rather
than trusting that it was approved when it was applied — because you may have
revoked a signer since, and revocation is meaningless if content that signer
approved stays trusted just by virtue of already being on the machine. If the
previous version no longer clears the threshold, it refuses and says so, rather
than quietly rolling forward or back.

`rescue update --use-bundled` deactivates downloaded content entirely and
returns to what shipped inside the installed package. It removes the applied
marker that `runtime.active_content_root()` gates on; **nothing is deleted**,
so `rescue update` can reactivate content later. Crucially, it does *not*
construct an `UpdateEngine`, because doing so would validate the
trusted-signer configuration — and the machine whose trust config is broken is
precisely the one that most needs to get back to known-good content. It works
on this repository today, where the shipped signer keys are still placeholders.

Together with the fetch/apply separation, that means no state a content update
can put your machine into is a state you cannot leave locally.

## Nothing is sent anywhere unless you opt in

There is no telemetry, no analytics, no crash reporting, and no update ping in
the tool. `rescue update` contacts a git remote when you run it, and the AI
layer contacts a provider when you enable it. That is the complete list of
outbound network activity initiated by the tool itself. (Individual checks read
local state; some, like a network speed test, use the network by their nature —
read the module if you care.)

The AI layer requires **both** an environment variable to be set *and* an
explicit opt-in on the command line: `--copilot`, `rescue explain`, or
`rescue recommend`. Without a provider configured it prints "This feature
requires an AI provider" and stops. What is sent is one line per finding —
`[category/module] (severity) title: description` — and nothing else. See
[Privacy](privacy.md#what-the-ai-layer-sends) for the full payload.

## Read the source of any check

There is no plugin marketplace and no runtime code download. Every check is one
file:

```console
$ ls modules/security/linux_firewall_check/
__init__.py
$ less modules/security/linux_firewall_check/__init__.py
```

What you will find, in order: a docstring explaining what the check looks at
and why; a class body declaring `name`, `category`, `platforms`, `risk_level`,
`estimated_duration`, and `emits_codes`; a `check()` method that only reads;
and a `fix()` method that builds `Action` objects. Anything that runs an
external command goes through `rescue.command.run`, which enforces a timeout,
caps captured output, refuses shell strings, and never raises. Anything that
walks the filesystem goes through `rescue.fsbounds.bounded_walk`, which enforces
depth, file-count, byte, and deadline limits and does not follow symlinks by
default.

The [module catalog](modules.md) lists all 287 with their platforms, risk
level, and duration.

## Where the guarantees are partial

Stated plainly, because you should know before you rely on them.

!!! warning "Module discovery imports Python from your install directory"
    `rescue/registry.py` loads every `modules/*/*/__init__.py` with
    `importlib` and executes it in-process, at discovery time — before you
    choose anything to run. That means anything with write access to your
    `modules/` directory can execute code as you, and it means a scan's blast
    radius is the whole tree, not just the module you picked.

    This is tracked as roadmap **P0#10** ("Discovery executes arbitrary
    Python"), and the fix — running modules in an isolated process — is a
    Phase-4 architecture change that has not been done. Until then: install
    from a source you trust, keep the install directory writable only by you,
    and read modules you have reason to doubt.

!!! warning "`load_content_module` resolves a `.py` helper through the content path"
    A few network and cryptojacking modules share a helper
    (`modules/network/lan_common/neighbors.py`) loaded by path via
    `rescue.runtime.load_content_module`, which resolves through `content_file`
    — and `content_file` prefers an applied content checkout over the bundled
    tree. The sanctioned update path cannot put a `.py` file there, because
    `validate_content_paths` rejects it before checkout. But if something wrote
    directly into `~/.local/share/rescue/content/`, bypassing `rescue update`
    entirely, that helper would be loaded from there. Treat that directory with
    the same care as the install directory.

!!! warning "Not every module uses the bounded runner yet"
    `rescue/command.py` and `rescue/fsbounds.py` exist because modules
    historically called `subprocess.run` directly, often with no timeout.
    Migrating every remaining call site is an in-progress mechanical follow-up
    (roadmap P0#7). The orchestrator's per-module 60-second timeout bounds the
    *session* regardless — but note the comment in `rescue/orchestrator.py`:
    Python cannot forcibly kill a thread blocked in a syscall, so a timed-out
    check is *abandoned* on a daemon thread, not killed.

!!! warning "`rescue explain` bypasses the orchestrator"
    It calls `mod.check(profile)` directly in a loop, so the per-module timeout
    does not apply to it. `scan`, `--auto`, and `export` all go through the
    orchestrator and are bounded.

!!! warning "Detection is indicators, not proof"
    Findings are observations. An inventory finding exists so *you* can spot
    the entry you do not recognise — that is the detection mechanism for
    anything novel, and it depends on you reading it. Nothing here replaces
    professional incident response for a real, active compromise.

## Verifying what you installed

!!! danger "There is no official package or binary to download"
    This project is **not published on PyPI**, and nothing in CI builds or
    publishes a release artifact. The only supported way to get it is a git
    checkout of
    <https://github.com/lizTheDeveloper/multiverse-device-rescue>.

    That means: a PyPI package named `multiverse-device-rescue` is **not this
    project** and should not be installed; and an installer or binary someone
    hands you was built by that person, not published by this project. The
    repository does contain packaging scripts (`scripts/build-macos-app.sh`,
    `scripts/build-windows.bat`) so a maintainer — or you — can build a desktop
    app locally, but a build is only as trustworthy as whoever ran it.

1. **Install from source you can read.** `git clone`, then `pip install .`. You
   can `git log`, `git diff`, and inspect every module before anything runs.
2. **Check the integrity manifest after install.** Launch any command (e.g.
   `rescue version`) and confirm no `WARNING: rescue's own installed files do
   not match…` appears. That compares your installed `rescue/**/*.py` against
   the shipped hashes.
3. **Regenerate and compare, if you want to be sure the manifest matches the
   source you read:**

    ```console
    $ python scripts/generate_integrity_manifest.py
    $ git diff --exit-code -- rescue/security/integrity_manifest.json
    ```

    No diff means the committed manifest describes exactly the source in your
    tree. This is the same check CI runs.
4. **Validate the catalog.** `rescue validate` confirms module names are
   unique, dependencies resolve without cycles, no module claims unattended
   mutation at a dangerous risk level, and every profile and guide reference
   resolves. It executes no module's `check()`.
5. **Confirm auto mode is read-only on your copy:**

    ```console
    $ grep -rn "auto_apply" modules/ | wc -l
    0
    ```
6. **Run one module at a time first.** `rescue run <name>` and answer `N` at
   the prompt. You lose nothing by looking before you leap.
