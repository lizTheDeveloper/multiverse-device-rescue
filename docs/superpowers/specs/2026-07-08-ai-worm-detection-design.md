# AI Worm Detection & Spyware Scanning — Design Spec

## Overview

A module pack for Multiverse Device Rescue that detects AI-led worms (Shai Halud family, Miasma, SesameOp, and future variants), behavioral indicators of AI agent compromise, and mobile spyware (via MVT integration). Designed as a blue-team initiative for rescuing developer machines and environments that may have been compromised.

## Motivation

AI-led worms are an active, escalating threat to developer environments:

- **Shai Halud** (TeamPCP, Sep 2025–present): Self-propagating supply chain worm targeting npm/PyPI ecosystems. Five known variants culminating in Megalodon (May 2026), which pushed 5,718 malicious commits to 5,561 GitHub repos in six hours. Source code was publicly released May 2026, converting it into commodity attack infrastructure.
- **Miasma Toolkit** (2026): Disabled 73 Microsoft/Azure GitHub repos in 105 seconds. Features a dead-man switch that executes `rm -rf ~/` if stolen tokens are revoked.
- **SANDWORM_MODE** (Feb 2026): Injects rogue MCP servers into AI coding assistants (Claude Code, Cursor, Gemini CLI).
- **SesameOp** (Nov 2025): Routes all C2 traffic through `api.openai.com` using the OpenAI Assistants API.

The existing `ai_threat_indicators` module checks for API connections and environment variables but lacks worm-specific behavioral analysis, known IOC matching, and forensic depth.

## Architecture: Detection-Domain Module Pack

Six new modules under `modules/security/`, all cross-platform (macOS, Linux, Windows), plus a shared IOC data directory. Each module is an expert in one domain of the system.

| Module | Domain | Priority | Est. Duration |
|---|---|---|---|
| `ai_worm_filesystem` | Filesystem anomalies & payload detection | 55 | 10-15s |
| `ai_worm_git_ssh` | Git, SSH, and AI tool config integrity | 54 | 5-10s |
| `ai_worm_persistence` | Persistence mechanisms & dead-man switches | 53 | 5-10s |
| `ai_worm_network` | C2 channels, exfiltration, beaconing | 52 | 5-10s |
| `ai_worm_lateral` | Lateral movement & supply chain compromise | 51 | 5-10s |
| `mvt_spyware_scan` | Mobile spyware detection via MVT | 50 | 30-120s |

No dependencies between the AI worm modules — they all run in parallel. `mvt_spyware_scan` is independent. The existing `ai_threat_indicators` module stays as-is for lightweight API-presence checks.

### Shared IOC Database

All five AI worm modules share a common IOC data directory at `modules/security/ai_worm_iocs/`:

```
modules/security/ai_worm_iocs/
  loader.py               # Shared loader, caches IOC data per run
  known_hashes.json       # SHA256 hashes of known payloads
  known_domains.json      # C2 domains, exfil endpoints
  known_ips.json          # Malicious infrastructure IPs
  known_paths.json        # Payload locations, credential targets, persistence paths
  known_git_patterns.json # Commit signatures, branch patterns, hook indicators
  known_mcp_servers.json  # Rogue MCP server names and config patterns
  manifest.json           # Version, last-updated timestamp, source attribution
```

**IOC entry format** (example from `known_paths.json`):
```json
{
  "version": "1.0.0",
  "last_updated": "2026-07-08",
  "source": "Multiverse Device Rescue IOC Database",
  "entries": [
    {
      "path": "~/.config/index.js",
      "threat": "miasma",
      "type": "payload",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma primary worm payload"
    }
  ]
}
```

**What goes in IOC files vs. code:**
- **IOC files:** Specific hashes, domains, IPs, file paths, git patterns, MCP server names — anything that changes as new variants appear. Updated independently of code via the existing content-repo update system (network fetch or air-gapped USB sideload via git bundles).
- **Module code:** Detection logic, behavioral heuristics, system inspection methods — the *how* of detection.

The IOC loader (`loader.py`) exposes a simple API:
```python
from modules.security.ai_worm_iocs.loader import load_iocs

iocs = load_iocs()  # cached per process
iocs.hashes        # dict keyed by SHA256
iocs.domains       # set of known malicious domains
iocs.ips           # set of known malicious IPs
iocs.paths         # list of PathIOC entries
iocs.git_patterns  # list of GitPatternIOC entries
iocs.mcp_servers   # list of MCPServerIOC entries
```

---

## Module 1: `ai_worm_filesystem`

Scans for artifacts that AI worms leave on disk.

### Checks

**Known payload detection:**
- Match files at known payload paths from IOC database (e.g., `~/.config/index.js`, `/tmp/tmp.0144018410.lock`, `/tmp/.bun_ran`, `/var/tmp/.gh_update_state`, `~/.local/share/updater/update.py`, `~/.local/bin/gh-token-monitor.sh`, `~/.config/gh-token-monitor/token`)
- SHA256 hash matching against known payload hashes (Shai Halud `setup_bun.js`, `bun_environment.js` variants, Miasma dropper/payload)
- Detect `.github/setup.js` dropper files in git repos

**Self-modifying code detection:**
- Scan `~/.local/bin`, `/usr/local/bin`, temp dirs for scripts with mtime much newer than ctime (injection indicator)
- Detect scripts containing encoded/obfuscated payloads: base64 blocks over 500 bytes, `eval()`/`exec()` wrapping encoded strings
- Python/Node/shell scripts in unexpected locations referencing AI APIs or containing LLM prompt patterns

**Suspicious file creation patterns:**
- Burst detection: many new executable/script files created in a short window in temp or hidden directories
- Hidden directories mimicking legitimate tools (`.claude-cache`, `.gpt-helper`, `.copilot-data` that aren't from real tools)
- Executable files in `~/.config/*/`, `~/.cache/*/` with execute permissions

**Payload staging indicators:**
- Large base64 blobs in dotfiles or config files
- curl/wget piped to shell patterns in script files
- Files with randomized/hashed names in temp directories containing code

### Fix Actions (destructive, user-confirmed)

- Quarantine suspicious files to `~/.rescue_quarantine/` with metadata
- Remove execute permissions from suspicious scripts
- Delete confirmed staging payloads matching known hashes

### Platform Implementation

- macOS/Linux: `find`-based scanning, `stat` for timestamps, `file` for type detection, `shasum` for hashing
- Windows: PowerShell `Get-ChildItem`, `Get-FileHash`, scanning `%TEMP%`, `%APPDATA%`

---

## Module 2: `ai_worm_git_ssh`

Detects compromise of developer version control and remote access.

### Checks

**SSH key and config manipulation:**
- New/modified entries in `~/.ssh/authorized_keys` — detect keys added recently that the user didn't authorize
- `~/.ssh/config` changes — new Host entries, ProxyCommand injection, unexpected IdentityFile references
- Private key access indicators — recent atimes on `~/.ssh/id_*` from non-ssh/git processes
- Windows: `%USERPROFILE%\.ssh\` equivalents

**Git hook tampering:**
- Scan repos under common dev paths for unexpected hooks in `.git/hooks/` (especially `post-checkout`, `pre-push`, `post-merge`)
- Check `git config --global core.hooksPath` and `init.templateDir` for hijacking (Shai Halud persistence vector)
- Detect `.npmrc` containing `git=node` override (bypasses `--ignore-scripts`)

**AI tool config injection (major Shai Halud / SANDWORM_MODE vector):**
- Rogue MCP server entries in `~/.claude/settings.json`, `~/.cursor/mcp.json`, `~/.continue/config.json`
- `.claude/setup.mjs` SessionStart hooks in repos (CVE-2026-25725)
- `.gemini/settings.json` hooks, `.cursor/rules/setup.mdc`, `.vscode/tasks.json` folderOpen triggers
- Known malicious MCP server names from IOC database: `index_project`, `lint_check`, `scan_dependencies`

**Suspicious git state:**
- Unsigned commits with author `github-actions <[email protected]>` and message `chore: update dependencies [skip ci]`
- Commits adding `.claude/`, `.gemini/`, `.cursor/`, `.vscode/` files with `skip-checks:true` trailer
- Orphan commits pointed to by semver tags (ActionMutator signature)
- Unexpected git remotes matching IOC naming patterns (`(stygian|tartarean|erebean|infernal)-*-[0-9]{5}`)

### Fix Actions (destructive, user-confirmed)

- Remove unauthorized SSH keys from `authorized_keys`
- Reset `core.hooksPath` and `init.templateDir` to defaults
- Delete rogue git hooks and MCP config entries
- Remove malicious `.npmrc` overrides

---

## Module 3: `ai_worm_persistence`

Finds how AI worms survive reboots and session restarts.

### Checks

**macOS (launchd):**
- Known malicious LaunchAgents from IOC database: `com.user.update-monitor.plist`, `com.user.gh-token-monitor.plist`
- Scan `~/Library/LaunchAgents/` and `/Library/LaunchDaemons/` for plists referencing AI endpoints, `bun`, `node`, or `python` with suspicious arguments
- **Dead-man switch detection (critical):** Identify the Miasma `gh-token-monitor` service that polls `api.github.com/user` every 60s and runs `rm -rf ~/` on 4xx response

**Linux (systemd + cron):**
- Rogue units in `~/.config/systemd/user/` (e.g., `update-monitor.service`)
- `~/.local/share/updater/update.py` (Miasma GITHUB_MONITOR)
- `~/.local/bin/gh-token-monitor.sh` (dead-man switch)
- User crontabs calling AI endpoints or running scripts from temp/hidden dirs

**Windows (Scheduled Tasks + Registry):**
- Scheduled tasks running scripts from `%TEMP%`, `%APPDATA%`, or referencing AI endpoints
- Run/RunOnce registry keys with suspicious entries
- `%TEMP%\Netapi64.dll` and `OpenAIAgent.*` files (SesameOp artifacts)

**Shell profile injection (all platforms):**
- Scan `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile`, `/etc/bash.bashrc` for injected curl/wget-to-shell, eval of encoded strings, sourcing from temp/hidden dirs
- Recently modified shell configs adding PATH entries to attacker-controlled directories

**AI tool SessionStart hooks:**
- `~/.claude/settings.json` hooks (CVE-2026-25725)
- Per-repo `.claude/settings.json` and `.claude/setup.mjs`

### Fix Actions (destructive, user-confirmed)

- **Dead-man switch disablement FIRST** with prominent warning: "The Miasma dead-man switch must be disabled BEFORE revoking any tokens. Revoking tokens while the switch is active triggers `rm -rf ~/`."
  - macOS: `launchctl unload ~/Library/LaunchAgents/com.user.gh-token-monitor.plist`
  - Linux: `systemctl --user stop gh-token-monitor`
- Remove malicious LaunchAgents/systemd units/scheduled tasks
- Clean injected lines from shell profiles
- Remove rogue SessionStart hooks

---

## Module 4: `ai_worm_network`

Detects active C2 channels and data exfiltration.

### Checks

**Known C2 patterns:**
- Miasma: HTTPS POST to domains mimicking Anthropic API using `/v1/api` path (legitimate is `/v1/messages`)
- Miasma GitHub C2: processes querying GitHub commit search API for trigger strings from IOC database (`DontRevokeOrItGoesBoom`, `TheBeautifulSandsOfTime`, `firedalazer`)
- SesameOp: non-browser processes communicating with `api.openai.com` using Assistants API
- Shai Halud: webhook exfil to `webhook.site` domains

**Known malicious infrastructure (from IOC database):**
- Domains: `cdn[.]cloudfront-js[.]com`, `lastpass-login-help[.]com`, etc.
- IPs: `161.97.129.25`, `161.97.135.154`, `161.97.163.87`, `161.97.186.175`, `38.242.204.245`, `83.171.249.231`

**Exfiltration channel detection:**
- Shai Halud three-channel cascade: Cloudflare Workers POST, double-base64 GitHub repo uploads, DNS tunneling via base32 queries
- DNS queries with abnormally long subdomain labels (encoded data tunneling)
- Processes making HTTP POST with large payloads to uncommon endpoints

**Behavioral heuristics:**
- Beaconing: processes making regular-interval outbound connections (60s poll pattern)
- `bun`/`node`/`python` spawning `gh auth token` (Miasma token harvesting signature)
- Non-browser processes connecting to AI API endpoints with process tree analysis
- Unusual outbound from `git`, `npm`, `pip` processes

**StepSecurity bypass:**
- `/etc/hosts` entries redirecting `agent.stepsecurity.io`

### Fix Actions (destructive, user-confirmed)

- Kill processes with active C2 connections
- Block known malicious IPs/domains via hosts file (reversible)
- Remove StepSecurity bypass entries
- Terminate beaconing processes

### Platform Implementation

- macOS/Linux: `lsof -i -n -P`, `netstat`, DNS resolver logs
- Windows: `netstat -b`, `Get-NetTCPConnection` with owning process

---

## Module 5: `ai_worm_lateral`

Detects how AI worms spread to other machines, repos, and infrastructure.

### Checks

**Credential harvesting detection:**
Check access times on ~100+ known credential hotspots:
- Cloud: `~/.aws/credentials`, `~/.aws/config`, `~/.azure/accessTokens.json`, `~/.kube/config`
- Package managers: `~/.npmrc`, `~/.pypirc`, `~/.gem/credentials`
- AI/LLM: `~/.claude.json`, `~/.claude/*`, `~/.anthropic/`
- Docker: `~/.docker/config.json`, `/var/run/docker.sock` permissions
- Secrets managers: HashiCorp Vault tokens, 1Password service accounts
- History: `~/.bash_history`, `~/.zsh_history` (searched for host/user combos)
- Env files: `.env`, `.env.local`, `.env.production` in project dirs
- GitHub PATs: `~/.config/gh/hosts.yml`
- Miasma-specific: `~/.config/gh-token-monitor/token` (mode 600)

**Package manager poisoning indicators:**
- Recent npm publishes from this machine — check `npm whoami` + publish history
- `setup_bun.js` and `bun_environment.js` in local packages (hash-matched from IOC database)
- `.github/workflows/shai-hulud-workflow.yml` in any repo
- Remote dynamic dependencies in `package.json` (PhantomRaven pattern)

**CI/CD pipeline tampering:**
- GitHub Actions workflows with `OIDC_PACKAGES` env var, `"Dependabot Updates"` name with unexpected content, `snapshot-<8 hex>` branch patterns
- Forged CI bot commit identities

**IDE plugin compromise:**
- VS Code: known malicious extension IDs (GlassWorm), invisible Unicode in extension source
- Extensions accessing every opened file (MaliciousCorgi pattern)
- JetBrains: fake AI assistant plugins harvesting API keys

**Container escape indicators:**
- Unexpected mount operations, `setns` calls
- Unusual procfs access patterns
- Capability escalation (CAP_SYS_ADMIN, CAP_SYS_PTRACE, CAP_SYS_MODULE)
- AI tool configs mounted read-write inside containers

**Cloud metadata access:**
- Processes querying IMDS (`169.254.169.254`)
- Unexpected AWS STS `AssumeRole` calls

### Fix Actions (destructive, user-confirmed)

- Guided credential rotation per provider
- Remove malicious workflow files and package payloads
- Uninstall compromised IDE extensions
- Revoke npm/PyPI tokens (with dead-man switch warning if Miasma detected)
- Block IMDS access for unauthorized processes

---

## Module 6: `mvt_spyware_scan`

Wraps the Mobile Verification Toolkit (MVT) by Amnesty International for mobile spyware detection (Pegasus, Predator, and other commercial spyware).

### Design

MVT is an external tool (`pip install mvt`) with its own CLI. This module wraps it rather than reimplementing its detection logic.

**What it checks:**
- iOS device backups (iTunes/Finder backups) for spyware indicators
- Android device backups and APK analysis
- IOCs from Amnesty International's regularly updated indicator sets

**How it works:**
- Detect available device backups on the host machine (standard backup locations per platform)
- Check if MVT is installed; if not, offer to install it (`pip install mvt`)
- Run MVT's check commands against discovered backups
- Parse MVT's JSON output and present findings through the standard `CheckResult`/`Finding` model

**Backup discovery locations:**
- macOS: `~/Library/Application Support/MobileSync/Backup/`
- Windows: `%APPDATA%\Apple Computer\MobileSync\Backup\`
- Linux: `~/.config/mvt/` (if backups were manually placed)

### Fix Actions (informational + guided)

Mobile spyware remediation requires device-level action that this tool can't perform remotely. Fix actions are informational:
- Guided steps to factory reset the affected device
- Instructions to update device OS
- Links to Amnesty International's Security Lab resources
- Recommendation to consult security professionals for targeted spyware

---

## Threat Model Profile

A new profile `ai_worm_response.yaml` that activates all six modules together:

```yaml
name: ai_worm_response
display_name: "AI Worm & Spyware Response"
description: >
  Comprehensive scan for AI-led worm compromise (Shai Halud, Miasma,
  SANDWORM_MODE, SesameOp) and mobile spyware. Checks filesystem
  artifacts, git/SSH integrity, persistence mechanisms, network C2,
  lateral movement indicators, and mobile device backups.
modules:
  include:
    - ai_worm_filesystem
    - ai_worm_git_ssh
    - ai_worm_persistence
    - ai_worm_network
    - ai_worm_lateral
    - mvt_spyware_scan
  exclude: []
module_config:
  ai_worm_filesystem:
    sensitivity: elevated
  ai_worm_git_ssh:
    sensitivity: elevated
  ai_worm_persistence:
    sensitivity: elevated
  ai_worm_network:
    sensitivity: elevated
  ai_worm_lateral:
    sensitivity: elevated
guides:
  - ai_worm_response
```

## Sensitivity Configuration

Modules accept a `sensitivity` config via profile YAML (applied through `configure()`):

- **normal** (default): Only flag findings that match known IOCs or high-confidence behavioral heuristics. Minimizes false positives.
- **elevated**: Expand heuristic thresholds — flag more ambiguous signals (e.g., any recently modified shell config, any non-standard LaunchAgent, any process connecting to uncommon endpoints). Appropriate for active incident response where false positives are acceptable.

## Risk Levels

| Module | risk_level | Rationale |
|---|---|---|
| `ai_worm_filesystem` | MODERATE | Quarantines/deletes files |
| `ai_worm_git_ssh` | MODERATE | Modifies git config, removes SSH keys |
| `ai_worm_persistence` | DESTRUCTIVE | Removes LaunchAgents/systemd units, dead-man switch handling |
| `ai_worm_network` | MODERATE | Kills processes, modifies hosts file |
| `ai_worm_lateral` | MODERATE | Revokes credentials, removes extensions |
| `mvt_spyware_scan` | SAFE | Read-only scanning of backups |

## Testing Strategy

Each module gets a test file following the existing pattern (`tests/test_module_<name>.py`). Tests mock system calls (`subprocess.run`, `os.environ`, file I/O) and verify:
- Correct findings are generated for known IOC matches
- No false positives on clean systems
- Fix actions execute in the correct order (especially dead-man switch sequencing)
- Cross-platform code paths are exercised
- IOC loader correctly parses and caches data files

## Key References

- Agent Threat Rules (ATR): 683 detection rules, available via npm/PyPI
- Miasma Toolkit scanner: YARA rules and IOC database
- OWASP Top 10 for Agentic Applications (2026)
- MITRE ATLAS framework
- Amnesty International MVT: Mobile spyware detection
- CVE-2026-25725 (Claude Code sandbox escape), CVE-2026-45321 (GitHub Actions), CVE-2026-3854 (Git Push RCE)
