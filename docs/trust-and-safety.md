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
| Does it send anything anywhere? | Only when you ask: the AI layer when you turn it on, `rescue update` when you run it, and the "who runs this address" lookups after a connection watch you start or for addresses you give `rescue lookup`. Those send only the public addresses: to RIPE NCC, to rdap.org, which redirects your computer to the regional registry that holds each address (ARIN, RIPE NCC, APNIC, LACNIC or AFRINIC) to ask it directly, and to reverse DNS through your computer's own resolver. Each service also sees your computer's public IP address, as any website does, and the app's name and version. `rescue watch --no-lookups` turns them off. One download happens during a normal scan: the AI tools check fetches HackMyAgent from the npm registry once, pinned by integrity hash. The registry sees your IP address and npm's own User-Agent (npm and Node.js versions, operating system, processor type); nothing else about your computer is sent. `--no-downloads` on `scan`, `export` or `run` turns it off. |
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
| `~/.rescue/known_items.json` | `rescue known add` / `remove`, or "It's mine" in the app ("I did this" writes nothing). A scan may also **remove** a mark from this file when the check that reported the item no longer sees it (see below); it never adds one and never touches anything else on the system. |
| `~/.config/rescue/revoked_signers.json` | `rescue trust revoke` |
| `~/.local/share/rescue/content/` | `rescue update`, after signature verification |
| `<user cache>/ReclaimCity/hackmyagent-<version>/` | `rescue scan`, once: the AI tools check's downloaded copy of HackMyAgent (see below) |

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
the tool. `rescue update` contacts a git remote when you run it, the AI
layer contacts a provider when you enable it, and a connection watch you start
(unless you pass `--no-lookups`), or `rescue lookup` for the addresses you
give it, looks up who runs each public address: the address is sent to RIPE
NCC (`stat.ripe.net`); to `rdap.org`, which redirects your computer to the
regional registry that holds the address (ARIN, RIPE NCC, APNIC, LACNIC or
AFRINIC), which your computer then asks directly; and to reverse DNS through
your computer's own resolver (which asks your DNS provider), once for the
address and once to confirm the name that comes back. Only addresses are
sent, never private ones. Each service also sees your computer's public IP
address, as any website does, and the app's name and version (in the
User-Agent, and RIPEstat's `sourceapp`). The registry hosts are listed in
[What each check runs](commands.md). The one exception to "only when you
ask" is the AI tools check's one-time download, described below. That is the
complete list of outbound network activity initiated by the tool itself. (Individual checks read
local state; some, like a network speed test, use the network by their nature —
read the module if you care.)

The AI layer requires **both** an environment variable to be set *and* an
explicit opt-in on the command line: `--copilot`, `rescue explain`, or
`rescue recommend`. Without a provider configured it prints "This feature
requires an AI provider" and stops. What is sent is one line per finding —
`[category/module] (severity) title: description` — and nothing else. See
[Privacy](privacy.md#what-the-ai-layer-sends) for the full payload.

### The AI tools check downloads one tool

`ai_agent_audit` lists the AI assistants on the computer, the add-ons (MCP
servers) they can use, and AI settings files holding a secret key. It does
this with HackMyAgent (OpenA2A, Apache-2.0,
<https://github.com/opena2a-org/hackmyagent>), which is not bundled:

- **What is fetched.** `npm ci --ignore-scripts --no-audit --no-fund
  --registry=https://registry.npmjs.org/` against
  `vendor/hackmyagent/package-lock.json`, which pins HackMyAgent 0.33.2 and
  every package under it with an integrity hash. npm refuses anything that
  doesn't match. `--ignore-scripts` means no package's install script runs.
  The AI runtime HackMyAgent can optionally use (`onnxruntime-node`) is
  replaced by a two-file local stub that throws if loaded; `detect` never
  loads it.
- **Where it goes.** A temp folder beside
  `<user cache>/ReclaimCity/hackmyagent-0.33.2`, renamed into place only when
  complete. A failed or partial download is deleted. npm's own cache is a
  temp folder, deleted afterwards. Later scans reuse the copy after checking
  its version.
- **Checked before and after every run.** `vendor/hackmyagent/tree.sha256`
  lists the sha256 of every file a clean `npm ci` installs (made by
  `scripts/generate_hackmyagent_manifest.py`). For each run, also with
  `--no-downloads`, the saved copy is copied into a new private temp folder,
  and every file of that copy is compared with the list; HackMyAgent runs
  from the copy, which is compared again when it finishes and then deleted.
  A changed, missing or extra file, or any link other than the AI-runtime
  stub, means nothing is run (before) or the results are thrown away
  (after). A saved copy that doesn't match is deleted; it is downloaded once
  more if downloads are allowed, and otherwise the check says the copy had
  changed. So a copy changed between scans isn't run, and one changed during
  a run is caught afterwards as long as it is left changed. A file that
  can't be read counts as changed. `npm ci --no-bin-links` keeps npm from
  adding links.
- **A clean environment.** node and npm get only an allow-listed set of
  environment variables (`PATH`, `HOME`/`USERPROFILE`, the temp-folder,
  locale, Windows system and proxy variables, and the ones the check sets).
  Variables such as `NODE_OPTIONS`, `NODE_PATH` or `npm_config_*` that could
  make node or npm load other code never reach them.
- **What runs.** Only `detect <home> --json --depth 0 --no-contribute`, with
  `OPENA2A_TELEMETRY=off`, and `OPENA2A_HOME`, `XDG_CONFIG_HOME` and the temp
  folder (`TMPDIR`, `TMP`, `TEMP`) all set to one temp folder deleted
  afterwards. Its start-up self-check appends to
  `~/.nanomind/integrity-events.jsonl`, which can't be redirected. Right
  after the run Reclaim City removes those lines, but only when it is the
  same file, not a link, and every new line is one of HackMyAgent's
  self-check events from this run; otherwise it leaves the file alone and
  says so in the finding. Never `secure`, `--fix`,
  `attack` or any other command. It reads AI settings files and the list of
  running programs; it masks any key
  values it finds, and Reclaim City keeps only the variable name, never the
  value. See [Privacy](privacy.md#what-leaves-the-machine) for everything it
  looks at.
- **When it doesn't run.** If the scan has administrator rights (root, `sudo`,
  or "Run as administrator"), the check runs neither node nor npm and says
  so: both, and the saved copy, live in folders any program running as you
  can change. If HackMyAgent's own settings (`~/.hackmyagent/config.json`)
  are on the computer, it doesn't run either, because HackMyAgent would move
  and rewrite them at start.
- **Off switch.** `rescue scan --no-downloads` or `RESCUE_NO_DOWNLOADS=1`.
- **What it needs.** Node.js 18 or newer, already installed. Reclaim City
  never installs Node.js; without it the check reports "couldn't check".
  `node` and `npm` are looked up only in absolute folders on `PATH` and in
  the usual install places, never in the current folder. On Windows npm is
  run as `node npm-cli.js`, not through `npm.cmd` and `cmd.exe`, and npm
  gets empty `.npmrc` files on every platform.

!!! warning "What the check can't protect against"
    Your own `node` and `npm` run with the same permissions Reclaim City has,
    including Full Disk Access on a Mac if you gave the app that. If they are
    in a folder any program running as you can change (Homebrew, nvm, Volta,
    `~/.local/bin`), a program running as you could replace them, and the
    next scan would run the replacement. The file check above covers the
    saved HackMyAgent copy, not your Node.js. In the same way, a program
    already running as you could race a single run: swap a file in the
    private copy after it is checked and put it back before the check that
    follows the run. Turn the check off with `--no-downloads` and delete the
    saved copy if that matters to you.

Updating the pinned version is a reviewed change to the lockfile, never
automatic.

## Read the source of any check

There is no plugin marketplace, and no runtime code download apart from the
pinned HackMyAgent fetch above. Every check is one file:

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

!!! warning "Marking something as yours can be misused by whoever installed it"
    `rescue known add` (and "It's mine" in the app) lets the person at the
    keyboard quiet a warning about something they set up themselves: a
    background task, a sharing setting, a proxy, a system or browser
    extension, a list of apps with powerful permissions, the list of
    remote-login keys, or an AI tool setting. Someone
    who installed stalkerware and has the computer in their hands could use it
    the same way. What limits that:

    - A marked item is never removed from the results. It is listed on every
      scan, and in exports, as "Background task you marked as yours", with
      `marked_by_user`, `marked_at` and the original title and severity in its
      data. An advocate or helper reviewing a scan should read every one of
      these and ask the person whether they marked it.
    - Critical findings (known viruses, programs in folders anyone can change,
      a proxy file loaded from elsewhere) are never downgraded, and only
      warnings are ever offered.
    - Nothing from the monitoring-software checks (`stalkerware_scan`,
      `mvt_spyware_scan`, `keylogger_indicators`) can be marked at all. The
      engine refuses it, and the app never offers it, whatever the code. The
      only answer on those cards is "I did this", which lasts for that
      checkup only.
    - For anything that could be used to watch someone (screen sharing,
      remote login and management, proxies, system and browser extensions,
      apps with accessibility, screen, camera or microphone access,
      remote-login keys, background tasks), and for every mark when the
      person chose "I think someone is watching me", the app's confirmation
      says "Only do this if you set this up yourself. If you're not sure,
      leave it as it is." and why it asks.
    - A mark pins the finding code, label, plist path, program path and a hash
      of the full program arguments, and the content of the program and the
      script it runs (see below), not just a name. Changing any of them
      brings the warning back. There is no shipped allowlist of names to copy.
    - In the app, only the engine's mark id travels back from the page; the
      main process uses what its own scan offered, and the engine re-reads the
      task and refuses if it no longer matches that id.
    - Marking needs a typed confirmation in a terminal, or the app's own
      confirmation; a script with no terminal is refused.

    Settings and installed items pin the concrete evidence the check saw
    (see `docs/cli.md` for the table): a proxy's host and port, an
    extension's id and team, a SHA-256 of the list of apps or keys. When the
    evidence changes, the finding comes back at its normal severity with
    `mark_stale` and "has changed since you marked it". When a mark is saved,
    the engine runs the check again and refuses unless it still reports the
    same item.

    A mark on a setting or item only lasts while the item does. When a check
    that reports it runs cleanly and no longer sees it (Screen Sharing turned
    off, the proxy or extension removed, the key list emptied, the app list
    back under the warning threshold), the scan removes that mark and says so
    in an info finding ("No longer marked as yours: ..."). If the thing comes
    back later, someone turning Screen Sharing on again for example, it is
    flagged like any new warning. We chose to retire the mark rather than pin
    something that changes on re-enable: macOS keeps no reliable "when was
    this turned on" for these services, and anything like a process id would
    also change on every restart, bringing the warning back for no reason.

    That removal is the one write a scan makes, and only to Reclaim City's
    own list: it goes through the same checks as `rescue known remove` (no
    symlinks, owned by you, not writable by others, valid JSON) and an atomic
    replace. If the list is not trusted, nothing is written and no mark
    applies. It only ever removes; a check that wrongly reports nothing can
    only bring a warning back, never hide one. A check that could not run
    (an error, a timeout, or not supported here) retires nothing. Background
    task marks are not retired this way; they pin the content of what runs
    instead.

    Some things are deliberately not markable: VPN configurations (the checks
    record no server address, and the only warning is about an insecure
    protocol), certificates (no check records a fingerprint per
    certificate), kernel extensions (no team ID), MDM enrollment (the
    warnings name no server, so a mark would cover enrollment by anyone), and
    remote-access apps such as TeamViewer or AnyDesk (on macOS only the
    monitoring-software check reports them; on Windows only by name).

    "I did this" in the app is different: it moves a card into "Cleared" for
    that checkup only. Nothing is written anywhere, and the next checkup
    checks again for real. "Copy for any AI" and the technical details say
    "the person said they did this", never that it was confirmed.

    What it does not stop: software already running as the person can rewrite
    `~/.rescue/known_items.json` itself, just as it can rewrite the plist. The
    scan ignores the file (and says so) if it is a symlink, damaged, or another
    user owns it or can write to it, but
    against something running as you, the protection is that marks stay
    visible, not that they cannot be forged.

    What runs is pinned too, not just where it is. A mark records a SHA-256 of
    the program file (and its resolved path, so swapping a symlink shows), and
    of every script file the arguments name in the home folder or a hidden
    folder (executable files and files like `.py`, `.sh`, `.js`; logs and
    configs are left out because they change on their own). Without this,
    someone could mark a harmless-looking task and later replace the program or
    the script behind it, and the warning would stay quiet. If the content
    changes, the finding is shown again at its normal severity with
    `data["mark_stale"] = true` and a sentence saying it changed since it was
    marked. That is noisy for developers (rebuilding a virtualenv or updating
    a tool brings the warning back until they mark it again), and that noise is
    the intended trade for people who may be being watched. A program that
    cannot be hashed (missing, unreadable, or over 200 MB) cannot be marked,
    and never matches a mark. Code loaded indirectly, such as a module run with
    `python -m`, is not hashed.

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
