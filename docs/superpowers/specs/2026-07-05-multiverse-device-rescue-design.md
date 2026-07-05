# Multiverse Device Rescue — Design Spec

## Overview

A modern, open-source system diagnostic, repair, and maintenance toolkit — a spiritual successor to the Geek Squad MRI disk. Built as a Python + shell hybrid with a plugin-based module architecture. Works across Windows, macOS, and Linux.

The tool combines automated system repair with threat-model-driven privacy guides and security walkthroughs, serving both IT professionals and everyday users through a two-tier UX.

## Delivery Model

- **Phase 1 (MVP):** Run-from-OS CLI tool and TUI. User downloads and runs it on a live system.
- **Phase 2 (Future):** Bootable USB/ISO based on a minimal Linux environment. Boots directly into the TUI, can mount and scan drives from outside the OS for machines that won't start.

## Target Audience

Two-tier UX serving two personas:

- **IT professionals / power users:** Full manual control, CLI scripting mode, structured JSON output, individual module selection.
- **Everyday users / "family tech support":** Opinionated auto-mode that runs applicable checks, presents findings in plain language, and applies safe fixes with a single confirmation.

## Supported Platforms

- Windows (10+)
- macOS (13+)
- Linux (major distros: Ubuntu, Fedora, Arch)

Each module declares which platforms it supports. Platform-specific work is handled by shell scripts (Bash, PowerShell) called from the Python orchestrator.

## Architecture

Four-layer Plugin Registry architecture:

### Layer 1: System Profiler

Runs first to gather facts about the machine. Each platform has its own fact-gathering scripts (shell), and the profiler normalizes them into a common `SystemProfile` data structure.

Facts gathered:
- OS name, version, architecture
- Hardware: CPU, RAM, storage type (SSD/HDD), disk capacity and usage
- Installed software (package managers, app directories)
- Running processes
- Network configuration
- Startup items
- User accounts

### Layer 2: Module Registry

Self-contained modules organized by category. Each module lives in its own directory with a Python class and platform-specific shell scripts.

**Module directory structure:**
```
modules/<category>/<module_name>/
  __init__.py           # Module class
  scripts/
    darwin.sh           # macOS-specific shell commands
    win32.ps1           # Windows PowerShell
    linux.sh            # Linux-specific
  data/
    known_bloatware.json  # Static data files (curated lists, signatures, etc.)
```

**Module interface:**
```python
class Module:
    name: str                    # Unique identifier
    category: str                # Category slug
    platforms: list[str]         # ["darwin", "win32", "linux"]
    risk_level: str              # "safe" | "moderate" | "destructive"
    priority: int                # 0-100, higher runs first within category
    depends_on: list[str]        # Other module names that must run first
    estimated_duration: str      # Human-readable estimate ("30s", "2m")

    def check(self, profile: SystemProfile) -> CheckResult:
        """Inspect system state. Returns findings. Never changes anything."""

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        """Apply remediations. Respects mode (auto skips destructive, manual prompts)."""

    def report(self, check: CheckResult, fix: FixResult) -> str:
        """Human-readable summary of findings and actions taken."""
```

`CheckResult` and `FixResult` are structured dataclasses containing lists of findings/actions with severity levels, enabling consistent TUI rendering and AI layer consumption.

### Layer 3: Orchestrator

The brain of the tool. Responsibilities:
1. Run the System Profiler
2. Discover modules by scanning the `modules/` directory (no central registration file)
3. Filter modules by platform compatibility
4. If a threat-model profile is active, further filter/configure modules per the profile
5. Topologically sort modules by dependencies
6. Execute `check()` on all applicable modules (parallel where dependencies allow)
7. Present findings to the user
8. Execute `fix()` according to the selected mode
9. Queue human tasks and render walkthroughs

### Layer 4: UI Layer

Three interfaces to the same orchestrator engine:

**Auto Mode** (`rescue --auto`):
1. Profile system → discover modules → run all checks
2. Present summary: "Found 12 issues across 4 categories"
3. Single confirmation for all `safe` fixes
4. Individual prompts for `moderate` and `destructive` fixes
5. Print queued human tasks at the end

**Interactive TUI** (`rescue`):
- Built with `textual` (Python TUI framework)
- Category menu → module selection → findings → fix selection
- Progress bars, color-coded severity, interactive checklists for walkthroughs
- Guide/walkthrough rendering with step-by-step progress tracking

**CLI/Scripting Mode** (`rescue run <module> [<module>...] --yes`):
- Non-interactive, structured JSON output
- For IT pros managing multiple machines or scripting into other tools

## Module Categories

### Malware & Bloatware Cleanup
- **Process scanner:** Flag known-bad and known-bloatware processes, offer to kill
- **Startup item auditor:** Find unnecessary startup entries (OEM junk, trial software), offer to disable
- **Browser extension auditor:** Flag suspicious or resource-hogging extensions
- **Adware/PUP scanner:** Check common adware install locations and registry keys (Windows)

### Performance & Storage
- **Disk space reclaimer:** Caches, temp files, old logs, package manager caches, stale `node_modules`, Docker images, old iOS backups
- **Resource hog identifier:** Processes consuming excessive CPU/RAM/disk I/O
- **Startup time optimizer:** Measure boot time, identify slow startup items
- **SSD/disk health checker:** SMART data, wear leveling, health predictions

### System Integrity & Updates
- **System file verifier:** Wraps `sfc /scannow` (Windows), `diskutil verifyVolume` (macOS), `fsck` hints (Linux)
- **Update checker:** Pending OS updates, outdated packages, stale Homebrew/apt/chocolatey
- **Driver health (Windows):** Missing or outdated drivers
- **Broken symlink/permission fixer**

### Security Hardening
- **Firewall audit:** Is it enabled? Unexpected rules?
- **Disk encryption check:** FileVault, BitLocker, LUKS status
- **Password policy check:** Account lockout settings, guest accounts
- **Software vulnerability scan:** Known CVEs in installed software versions
- **Open port scanner:** Unexpected listening services

### Privacy Profiles & Guides
- **OS telemetry configurator:** Adjust telemetry settings per profile
- **Browser privacy configurator:** Auto-configure what's possible, guide the rest
- **Social media privacy walkthroughs:** Step-by-step guides tailored to user's profile
- **Human task scheduler:** Queue tasks requiring manual action with reminders

## Threat-Model Profiles

Profiles are scenario-driven, not generic security levels. Based on existing guide content from lizthe.dev/cybersecurity-guides:

### Built-in Profiles

**Digital Security Reset** — Post-compromise recovery. For someone who's been hacked or suspects compromise. Automates: password manager check, 2FA audit, session revocation scan. Guides through: the 6-phase recovery process (Phase 0: Emergency Grounding → Phase 1: Reality Check → Phase 2: Immediate Protective Actions → Phase 3: Systematic Cleanup → Phase 4: Rebuilding Security → Phase 5: Mental Health Maintenance).

**Six Roses** — Partner/stalking threat model. Automates: stalkerware scanning with elevated sensitivity, shared account detection, location sharing audit across apps. Guides through: safe device compartmentalization, account separation, evidence preservation.

**Activist Security** — State-level threat model. Automates: hardened OS configuration, encrypted communications check, metadata scrubbing. Guides through: operational security practices, secure communication setup, compartmentalization.

**Journalist Security** — Source protection. Automates: secure communication tool verification, device compartmentalization checks. Guides through: source protection protocols, secure drop setup, metadata risks.

**Home for the Holidays** — Help your family. Automates: the 13-point checklist (data removal, password manager setup, device maintenance, account hardening). Generates: the "Help Me" document for the family member to keep.

**Personal Lockdown** — Maximum privacy for everyday use. Disable telemetry, tighten permissions, restrict tracking, harden browser.

**Creator / Public Figure** — Selective openness. Social media stays visible, personal data locked down. Separates public persona from private life.

**Family Shared Device** — Kid-safe defaults, parental controls guidance, guest account setup, restricted installs.

**Work Machine** — Respect corporate policies, harden what you control. VPN check, disk encryption, screen lock timeout.

### Profile Mechanics

- Each profile is a YAML file in `profiles/` that maps to module configurations
- Profile selects which modules to activate, configures sensitivity levels, and defines which guide content to present
- Profiles filter out irrelevant modules (e.g., "Six Roses" skips bloatware cleanup)
- Findings are presented with threat-context explanations ("We found location sharing enabled on 3 apps — given your situation, here's why this matters")
- Progress persists across sessions — "You completed phases 1-3 last time, picking up at Phase 4"

### Guide Content Format

Guides stored as structured markdown with frontmatter:

```markdown
---
profile: digital_security_reset
phase: 3
title: "Systematic Cleanup"
automatable_steps: [1, 2, 5]
human_only_steps: [3, 4, 6]
estimated_time: "45 minutes"
---

## Step 1: Reset your primary email password
...
```

The tool parses frontmatter to determine which steps can be automated (linked to module actions) and which require human walkthrough (rendered as interactive checklists in the TUI).

Existing guide content from lizthe.dev serves as seed content. The directory structure makes it natural to expand — new guides drop in with the right frontmatter and are automatically available.

## Optional AI Layer

The tool works fully without any AI integration. When an API key or local model is available, three capabilities unlock:

### Diagnostic Explainer
Synthesizes module findings into plain-language narratives: "Your computer is slow mainly because Spotify, Adobe Creative Cloud, and OneDrive are all starting at boot and fighting for resources. The 47GB of old iOS backups in your home folder are why you're low on disk space."

### Profile Recommender
Short conversational intake: "What brings you in today?" Based on answers, recommends the right threat-model profile. "It sounds like you're dealing with a situation where someone you used to trust may have access to your accounts. I'd recommend the Digital Security Reset profile."

### Walkthrough Copilot
During guided walkthroughs, answers questions in context: "Why do I need to change this setting?" — grounded in the guide content and the user's specific system state.

### AI Boundaries
- Activated via `--copilot` flag or TUI toggle. Never mentioned if no API key is configured.
- Supports cloud APIs (Anthropic, OpenAI) and local models (Ollama).
- The AI layer only reads module results and guide content. It never executes fixes — remediation stays deterministic.

## Secure Update System

The tool must work out of the box but stay current against evolving threats. The update system assumes adversaries — bloatware vendors, stalkerware authors, state actors — may actively try to compromise or evade the tool over time.

### Update Layers

Three layers update at different cadences:

1. **Core orchestrator** — Slow-moving, infrequent. The binary/package itself. Updated via package managers or standalone binary replacement.
2. **Module data** — Fast-moving. Bloatware signatures, stalkerware detection patterns, CVE lists, known-bad process lists. This is the primary update path.
3. **Guide content** — Medium cadence. New walkthroughs, updated steps when platforms change their settings UIs.

Module data and guide content update independently of the core — no full reinstall needed to get new detection signatures.

### Trust Model

- All updates are cryptographically signed. Trusted public keys are baked into the binary at build time.
- **Threshold signing:** No single key can push an update. Require M-of-N signatures (e.g., 2-of-3 maintainer keys) so a single compromised maintainer cannot poison the pipeline.
- Updates are downloaded as signed bundles with SHA-256 checksums verified before extraction.
- **TLS certificate pinning** on the update server to prevent MITM. Graceful fallback (runs with stale data, warns the user) if the connection looks wrong.
- **Key revocation** is built into the protocol — a new signed manifest (meeting the M-of-N threshold) can revoke a compromised key.

### Hostile Environment Assumptions

- **Bloatware/stalkerware vendors will adapt.** Detection signatures must update frequently. Module data files (`known_bloatware.json`, stalkerware signatures) are the fast-update path, updating independently of code.
- **Adversaries may target the update channel.** Signed bundles + checksum verification + cert pinning. If any verification check fails, the tool refuses the update and tells the user why.
- **A maintainer could be compromised.** Threshold signing means one key is not enough. Key revocation handles the aftermath.
- **The tool itself could be targeted for removal.** Phase 2 (bootable USB) addresses this by running from read-only media. Phase 1 should at minimum detect if its own files have been tampered with on launch (self-integrity check).

### Offline-First Operation

- The tool works fully offline with whatever modules and guides it shipped with or last updated to.
- Updates are opportunistic — check on launch if online, never block on it.
- **Air-gapped sideloading:** Users can manually load signed update bundles (e.g., from a USB stick) for environments without internet. IT pros managing multiple machines benefit from this.

### Update Transparency

- Every update includes a changelog rendered in the TUI before applying.
- The user can inspect exactly what changed before accepting module updates.
- `rescue update --dry-run` shows what would change without applying anything.
- `rescue update --check` reports whether updates are available without downloading.

## Project Structure

```
multiverse_device_rescue/
  rescue/                       # Python package — the orchestrator
    __init__.py
    cli.py                      # CLI entry point (click or typer)
    tui/                        # Textual-based TUI
      app.py
      screens/
    orchestrator.py             # Module discovery, dependency sort, execution
    profiler/                   # System fact-gathering
      base.py                  # SystemProfile dataclass
      darwin.py
      win32.py
      linux.py
    models.py                  # CheckResult, FixResult, Mode, etc.
    ai/                        # Optional AI layer
      __init__.py
      explainer.py
      recommender.py
      copilot.py
  modules/                     # Plugin modules
    bloatware/
      startup_auditor/
      process_scanner/
      browser_extension_auditor/
      adware_scanner/
    performance/
      disk_reclaimer/
      resource_hog_identifier/
      startup_optimizer/
      disk_health/
    integrity/
      system_file_verifier/
      update_checker/
      driver_health/
      symlink_fixer/
    security/
      firewall_audit/
      encryption_check/
      password_policy/
      vulnerability_scan/
      port_scanner/
    privacy/
      telemetry_configurator/
      browser_privacy/
  guides/                      # Markdown walkthroughs
    digital_security_reset/
    six_roses/
    activist_security/
    journalist_security/
    home_for_the_holidays/
  profiles/                    # Threat-model profile YAML configs
    digital_security_reset.yaml
    six_roses.yaml
    activist_security.yaml
    journalist_security.yaml
    home_for_the_holidays.yaml
    personal_lockdown.yaml
    creator.yaml
    family_device.yaml
    work_machine.yaml
  tests/
  docs/
  pyproject.toml
  README.md
```

## Distribution

### Phase 1: Run-from-OS
- **Package managers:** `pip install multiverse-device-rescue`, `brew install mdr`, `choco install mdr`
- **Standalone binary:** PyInstaller/Nuitka bundles for each platform — no Python install required
- **Command:** `rescue` (TUI), `rescue --auto` (auto-mode), `rescue run <module>` (CLI)
- **Self-update:** Module definitions and guide content update independently of the orchestrator

### Phase 2: Bootable USB (Future)
- Minimal Linux environment (Alpine or Arch-based) preloaded with the tool
- Boots directly into TUI
- Can mount and scan Windows/macOS drives from outside the OS
- Separate build pipeline using `mkosi` or custom ISO builder

## Technology Choices

- **Python 3.11+** for the orchestrator, TUI, and AI layer
- **Textual** for the TUI (rich terminal UI framework)
- **Click or Typer** for CLI argument parsing
- **Shell scripts** (Bash/PowerShell) for platform-specific system operations
- **YAML** for profile configurations
- **Markdown with frontmatter** for guide content
- **pytest** for testing
- **PyInstaller or Nuitka** for standalone binary packaging

## Open Source Strategy

- **License:** MIT or Apache 2.0 for the tool itself. CC-BY-SA for guide content (preserves attribution on authored guides while allowing community contributions).
- **Contribution surface:** Module contributions are the primary community entry point. Clear contributing guide with a module template/scaffolder.
- **Guide contributions:** Community can submit new guides or expand existing ones following the frontmatter format.
