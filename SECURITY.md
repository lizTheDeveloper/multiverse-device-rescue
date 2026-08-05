# Security Policy

## Supported versions

| Version | Supported |
| --- | --- |
| 0.1.x (`main`) | Yes — fixes land on `main` |
| Anything older | No |

There are no tagged releases or published binaries yet, so "supported" means the
current `main` branch. When releases begin, this table will name the versions
that receive fixes.

Supported Python versions are 3.11, 3.12, and 3.13 (`pyproject.toml`,
`requires-python = ">=3.11"`). All three are exercised on Linux, macOS, and
Windows by `.github/workflows/tests.yml`.

## Reporting a vulnerability

**Do not open a public issue for a security report.**

Use GitHub's private vulnerability reporting on this repository:
<https://github.com/lizTheDeveloper/multiverse-device-rescue/security/advisories/new>.
That creates a private advisory only the maintainers can see, and it lets us
coordinate a fix and a disclosure with you.

Please include, as far as you can:

- What the flaw is, and which file or module it lives in.
- How to reproduce it. A failing test is the best possible report.
- Operating system, Python version, and how the tool was installed (source
  checkout, `pip install .`, PyInstaller binary, desktop app).
- What an attacker gets out of it, and what they need first (local access? the
  ability to write into `modules/`? a network position?).
- Whether it is already public anywhere.

If you have not heard back within a week, escalate by opening a public issue
that says only "I sent a private security report on <date>" — no details.

We will tell you what we found, what we changed, and when. If you want credit,
say so and how you want to be named; if you would rather stay anonymous, that is
fine too.

## Threat model, in brief

This tool exists to be run on a machine somebody already distrusts. That shapes
what it defends against and what it cannot.

**What it defends against**

- *Tampering with the tool itself after install.* Every `.py` file in `rescue/`
  is hashed into `rescue/security/integrity_manifest.json` and re-verified at
  launch; modified, missing, and unexpected added files all fail
  (`rescue/security/integrity.py`).
- *A malicious content update.* Content updates require signed git tags from at
  least two distinct trusted, non-revoked maintainers
  (`rescue/update/verify.py`, `required_approvals = 2` in
  `rescue/update/config.py`), verified against a throwaway keyring built only
  from the keys shipped in the package — never the operator's ambient GPG
  keyring or SSH allowed-signers file.
- *An update that ships code.* Updated content is restricted to `modules/`,
  `guides/`, and `profiles/` with data suffixes only
  (`validate_content_paths`, `rescue/update/manifest.py`), and executable module
  code is always loaded from the bundled root regardless of applied content
  (`rescue/runtime.py`).
- *Accidental damage by the tool.* `ModuleBase.auto_apply` defaults `False`, no
  shipped module sets it `True`, and `rescue run` confirms before calling
  `fix()` unless you passed `--yes`.
- *Leaking secrets through a shared report.* `rescue export` redacts private-key
  blocks, authorization headers, key/token/password assignments, common token
  shapes, email addresses, the account name, and the home-directory path on the
  way out (`rescue/case.py`).
- *A hung or runaway check.* Per-module timeout and session budget in
  `rescue/orchestrator.py`; bounded command execution in `rescue/command.py`;
  bounded traversal in `rescue/fsbounds.py`.

**What it does not defend against, and you should assume**

- *A compromised host lying to it.* Every check reads the system through the
  system. A rootkit or a kernel-level implant can make this tool report a clean
  machine. Nothing in this tool changes that.
- *Malicious Python inside `modules/`.* Module discovery imports every
  `modules/*/*/__init__.py` in-process with no sandbox and no signature check
  (`rescue/registry.py`). Write access to that directory is code execution in
  the rescue process. Roadmap P0#10; not fixed.
- *A malicious install source.* The integrity manifest detects tampering after
  install; it cannot tell you that the copy you downloaded was genuine. There
  are no signed release artifacts yet.
- *The AI layer's provider.* If you enable `--copilot`, `rescue explain`, or
  `rescue recommend`, finding titles and descriptions are sent to whichever
  provider you configured. That is a deliberate opt-in with an obvious data
  boundary; use `OLLAMA_HOST` for a local model if you need it to stay on the
  machine.
- *Anything outside the device.* Password changes, 2FA enrollment, and session
  revocation happen at the provider. The tool reports what is observable locally
  and never asks for a password, a one-time code, or a recovery key.

## What counts as a vulnerability in this tool

Beyond the usual (command injection, path traversal, privilege escalation,
insecure temporary files, credential exposure), this project treats the
following as security bugs, because the whole product is a claim about what is
true on a machine:

- **A check that reports healthy when it is not.** A false negative — a module
  returning "No issues found" when the condition it is meant to detect is
  present — is a security bug of the highest severity here. Someone made a
  decision about their safety based on that output.
- **An unsupported or failed check reading as a pass.** `CheckStatus` separates
  `HEALTHY`, `ISSUES`, `FAILED`, and `UNSUPPORTED` on purpose
  (`rescue/models.py`). Anything that collapses `FAILED` or `UNSUPPORTED` into
  `HEALTHY`, in the CLI, the TUI, the JSON output, or a case export, is a bug in
  this class.
- **Guidance reported as a completed change.** An action of kind `GUIDANCE`
  counted in `executed_mutations`, or rendered as `OK` instead of
  `MANUAL ACTION REQUIRED`, tells a user their machine was fixed when it was
  not.
- **A mutation running without confirmation.** Any code path where a module's
  `fix()` changes the system without `--yes` or an explicit confirmation.
- **Redaction failure in `rescue export`.** A credential, token, email address,
  or home path surviving into a case file.
- **Trust verification that can be bypassed.** Anything that accepts a content
  update with fewer than the required distinct approvals, accepts a revoked
  signer, falls back to the ambient keyring, or lets updated content place a
  file outside `modules/`, `guides/`, `profiles/` or with an executable suffix.
- **Integrity verification that can be defeated** without detection.

High-severity false *positives* — a check that tells someone they are
compromised when they are not — are also taken seriously. They are reported as
bugs rather than through this policy, using the false-positive/false-negative
issue template.

## Out of scope

- The absence of features the roadmap already lists as missing. Signed release
  artifacts, real signer key material, and sandboxed module discovery are known
  gaps documented in [docs/ROADMAP_STATUS.md](docs/ROADMAP_STATUS.md) and this
  file; a report saying they are missing tells us nothing new. A report showing
  a *concrete exploitation* of one of them is welcome.
- Findings that require an attacker who already has root or administrator
  privileges on the machine, unless the tool makes that meaningfully worse.
- Vulnerabilities in third-party dependencies with no exploitable path through
  this project. Report those upstream; tell us if we need to pin or drop
  something.
- Social-engineering scenarios that involve convincing a user to run an
  attacker-supplied module. That is the P0#10 gap above, already documented.
