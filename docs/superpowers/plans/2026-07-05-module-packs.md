# Module Packs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Ship seven high-value diagnostic/repair modules across the Performance, Bloatware, System Integrity, and Security Hardening categories, following the `disk_space` module pattern established in the core framework, so `rescue --auto` and `rescue run <module>` gain real macOS coverage beyond disk space.

**Architecture:** Each module is a self-contained `Module(ModuleBase)` class in `modules/<category>/<module_name>/__init__.py`, discovered automatically by `rescue.registry.discover_modules`. Modules gather system facts either from the already-populated `SystemProfile` (disks, processes) or via their own `subprocess.run` calls to platform shell commands (`launchctl`, `softwareupdate`, `brew`, `socketfilterfw`, `fdesetup`) when the profiler doesn't already collect that data. Two modules (`startup_auditor`, `process_scanner`) cross-reference system state against curated JSON data files under `data/known_bloatware.json`.

**Tech Stack:** Python 3.11+, pytest + `unittest.mock` for subprocess mocking, stdlib `subprocess`/`json`/`pathlib` only — no new dependencies.

## Global Constraints

- Follow the exact module pattern from `modules/performance/disk_space/__init__.py`: a `Module` class subclassing `rescue.module_base.ModuleBase` with `name`, `category`, `platforms`, `risk_level`, `priority`, `depends_on`, `estimated_duration` class attributes, and `check(profile) -> CheckResult` / `fix(findings, mode) -> FixResult` methods.
- macOS (`Platform.DARWIN`) only for this plan. Every module still declares `platforms` as a list so Windows/Linux support can be added later without changing the interface.
- Every `subprocess.run` call uses list-form arguments, `capture_output=True`, `text=True`, and never `shell=True`.
- Tests mock `subprocess.run` (patched as `"subprocess.run"`, which patches the single shared stdlib module object regardless of which file imports it) — no test depends on real system state or actually runs shell commands.
- `risk_level=SAFE` for read-only/informational modules; `risk_level=MODERATE` for modules whose `fix()` disables a startup item, kills a process, or flips a security setting requiring elevated privileges.
- Curated data files live at `modules/<category>/<module_name>/data/known_bloatware.json` and are loaded with `json.load` at check-time (no caching needed — this tool runs occasionally, not in a hot loop).
- Each module is independently discoverable and testable via `rescue.registry.discover_modules` — no module depends on another (`depends_on = []` for all seven).
- Every new category directory (`modules/bloatware/`, `modules/integrity/`, `modules/security/`) gets an empty `__init__.py` marker file, matching the existing `modules/performance/__init__.py` convention.
- Test files follow the `tests/test_module_disk_space.py` convention: `sys.path.insert(0, str(Path(__file__).parent.parent))`, then discover the module by name via `discover_modules(modules_dir)` and assert on `check()`/`fix()` behavior with mocked subprocess results.
- Assume `pip install -e ".[dev]"` has already been run (per Task 1 of the core framework plan) so `rescue` and `pytest` are available.

---

### Task 1: Resource Hog Identifier

**Files:**
- Create: `modules/performance/resource_hog_identifier/__init__.py`
- Test: `tests/test_module_resource_hog_identifier.py`

**Interfaces:**
- Consumes: `ModuleBase` from `rescue.module_base`; `SystemProfile`, `ProcessInfo`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; stdlib `subprocess`.
- Produces: `Module` class, `name = "resource_hog_identifier"`, `category = "performance"`, `risk_level = RiskLevel.MODERATE`. Reads `profile.processes` (already populated by the profiler via `ps aux`) — no subprocess call needed in `check()`. `fix()` terminates offending processes via `subprocess.run(["kill", "-9", str(pid)], capture_output=True, text=True)`.

- [ ] **Step 1: Write failing tests**

Create `tests/test_module_resource_hog_identifier.py`:

```python
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile, Platform, ProcessInfo, Severity, RiskLevel, Mode,
)
from rescue.registry import discover_modules


def _make_profile(processes):
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,  # 16 GB
        processes=processes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "resource_hog_identifier")


def test_resource_hog_identifier_discovered():
    mod = _get_module()
    assert mod.name == "resource_hog_identifier"
    assert mod.risk_level == RiskLevel.MODERATE


def test_resource_hog_healthy():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=1, name="launchd", cpu_percent=0.5,
                    memory_bytes=10 * 1024**2, command="/sbin/launchd"),
        ProcessInfo(pid=200, name="Finder", cpu_percent=2.0,
                    memory_bytes=200 * 1024**2,
                    command="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ])
    result = mod.check(profile)
    assert not result.has_issues


def test_resource_hog_warning_cpu():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=500, name="Spotify", cpu_percent=65.0,
                    memory_bytes=300 * 1024**2,
                    command="/Applications/Spotify.app/Contents/MacOS/Spotify"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING


def test_resource_hog_critical_cpu():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=600, name="Chrome Helper", cpu_percent=95.0,
                    memory_bytes=500 * 1024**2,
                    command="/Applications/Google Chrome.app/Contents/Frameworks/Chrome Helper"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_resource_hog_critical_memory():
    mod = _get_module()
    ram = 16 * 1024**3
    profile = _make_profile([
        ProcessInfo(pid=700, name="Docker", cpu_percent=5.0,
                    memory_bytes=int(ram * 0.30),
                    command="/Applications/Docker.app/Contents/MacOS/Docker"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_resource_hog_fix_kills_process():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=500, name="Spotify", cpu_percent=65.0,
                    memory_bytes=300 * 1024**2,
                    command="/Applications/Spotify.app/Contents/MacOS/Spotify"),
    ])
    check = mod.check(profile)

    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stderr = ""

    with patch("subprocess.run", return_value=fake_result) as mock_run:
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) == 1
    called_cmd = mock_run.call_args[0][0]
    assert called_cmd == ["kill", "-9", "500"]


def test_resource_hog_fix_handles_failure():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=500, name="Spotify", cpu_percent=65.0,
                    memory_bytes=300 * 1024**2,
                    command="/Applications/Spotify.app/Contents/MacOS/Spotify"),
    ])
    check = mod.check(profile)

    fake_result = MagicMock()
    fake_result.returncode = 1
    fake_result.stderr = "kill: 500: no such process"

    with patch("subprocess.run", return_value=fake_result):
        fix = mod.fix(check, Mode.MANUAL)

    assert not fix.all_succeeded
    assert fix.actions[0].error == "kill: 500: no such process"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_resource_hog_identifier.py -v`
Expected: FAIL — module "resource_hog_identifier" not found (`StopIteration` from the generator expression).

- [ ] **Step 3: Implement the module**

Create `modules/performance/resource_hog_identifier/__init__.py`:

```python
import subprocess

from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    ProcessInfo,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

CPU_WARNING_PCT = 50.0
CPU_CRITICAL_PCT = 90.0
MEM_WARNING_RATIO = 0.10
MEM_CRITICAL_RATIO = 0.25


class Module(ModuleBase):
    name = "resource_hog_identifier"
    category = "performance"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.MODERATE
    priority = 70
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        mem_warning_bytes = profile.ram_bytes * MEM_WARNING_RATIO
        mem_critical_bytes = profile.ram_bytes * MEM_CRITICAL_RATIO
        for proc in profile.processes:
            is_critical = (
                proc.cpu_percent >= CPU_CRITICAL_PCT
                or proc.memory_bytes >= mem_critical_bytes
            )
            is_warning = (
                proc.cpu_percent >= CPU_WARNING_PCT
                or proc.memory_bytes >= mem_warning_bytes
            )
            if is_critical:
                findings.append(self._make_finding(proc, Severity.CRITICAL))
            elif is_warning:
                findings.append(self._make_finding(proc, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            pid = finding.data.get("pid")
            name = finding.data.get("name", "unknown")
            try:
                result = subprocess.run(
                    ["kill", "-9", str(pid)],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip() or "kill command failed"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title=f"Terminate {name} (pid {pid})",
                    description=(
                        f"Sent SIGKILL to process {name} (pid {pid}) for "
                        "excessive resource usage."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(self, proc: ProcessInfo, severity: Severity) -> Finding:
        return Finding(
            title=f"{proc.name} is consuming excessive resources",
            description=(
                f"{proc.name} (pid {proc.pid}): {proc.cpu_percent:.1f}% CPU, "
                f"{_fmt_bytes(proc.memory_bytes)} RAM"
            ),
            severity=severity,
            category=self.category,
            data={
                "pid": proc.pid,
                "name": proc.name,
                "cpu_percent": proc.cpu_percent,
                "memory_bytes": proc.memory_bytes,
                "command": proc.command,
            },
        )


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_resource_hog_identifier.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/performance/resource_hog_identifier/ tests/test_module_resource_hog_identifier.py
git commit -m "feat: add resource_hog_identifier module for CPU/RAM hog detection"
```

---

### Task 2: Startup Time Optimizer

**Files:**
- Create: `modules/performance/startup_optimizer/__init__.py`
- Test: `tests/test_module_startup_optimizer.py`

**Interfaces:**
- Consumes: `ModuleBase`; `SystemProfile`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; `subprocess.run(["launchctl", "list"], capture_output=True, text=True)`.
- Produces: `Module` class, `name = "startup_optimizer"`, `category = "performance"`, `risk_level = RiskLevel.SAFE` (diagnostic only — disabling items is `startup_auditor`'s job). Also produces module-level `_parse_launchctl_list(output: str) -> list[str]`.

- [ ] **Step 1: Write failing tests**

Create `tests/test_module_startup_optimizer.py`:

```python
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "startup_optimizer")


def _fake_run(launchctl_output):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = launchctl_output
        result.returncode = 0
        return result
    return fake_run


def test_startup_optimizer_discovered():
    mod = _get_module()
    assert mod.name == "startup_optimizer"
    assert mod.risk_level == RiskLevel.SAFE


def test_startup_optimizer_healthy():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.apple.cfprefsd.agent
1234\t0\tcom.spotify.webhelper
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_startup_optimizer_warning():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.google.keystone.agent
-\t0\tcom.citrixonline.GoToMeeting.G2MUpdate
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["count"] == 5


def test_startup_optimizer_critical():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.google.keystone.agent
-\t0\tcom.citrixonline.GoToMeeting.G2MUpdate
9999\t0\tcom.oracle.java.Java-Updater
-\t0\tcom.real.player.helper
1111\t0\tcom.example.bloat1
2222\t0\tcom.example.bloat2
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["count"] == 9


def test_startup_optimizer_fix_is_informational():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.google.keystone.agent
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert "startup_auditor" in fix.actions[0].description
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_startup_optimizer.py -v`
Expected: FAIL — module "startup_optimizer" not found.

- [ ] **Step 3: Implement the module**

Create `modules/performance/startup_optimizer/__init__.py`:

```python
import subprocess

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

WARNING_COUNT = 3
CRITICAL_COUNT = 8


class Module(ModuleBase):
    name = "startup_optimizer"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 65
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_launchctl_list()
        labels = _parse_launchctl_list(output)
        third_party = [
            label for label in labels if not label.startswith("com.apple.")
        ]

        findings = []
        if len(third_party) >= CRITICAL_COUNT:
            findings.append(self._make_finding(third_party, Severity.CRITICAL))
        elif len(third_party) >= WARNING_COUNT:
            findings.append(self._make_finding(third_party, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            labels = finding.data.get("third_party_labels", [])
            preview = ", ".join(labels[:5])
            if len(labels) > 5:
                preview += ", ..."
            actions.append(
                Action(
                    title="Startup items report",
                    description=(
                        f"{finding.data.get('count', len(labels))} third-party "
                        f"startup item(s) detected: {preview}. Run the "
                        "startup_auditor module to review and disable the ones "
                        "you don't need."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(self, third_party: list[str], severity: Severity) -> Finding:
        return Finding(
            title=f"{len(third_party)} third-party startup items detected",
            description=(
                f"{len(third_party)} non-Apple launchd job(s) start "
                "automatically, which can slow down boot and login time."
            ),
            severity=severity,
            category=self.category,
            data={"third_party_labels": third_party, "count": len(third_party)},
        )

    def _run_launchctl_list(self) -> str:
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
        )
        return result.stdout


def _parse_launchctl_list(output: str) -> list[str]:
    labels = []
    lines = output.strip().split("\n")
    for line in lines[1:]:  # skip header row
        parts = line.split()
        if len(parts) >= 3:
            labels.append(parts[-1])
    return labels
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_startup_optimizer.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add modules/performance/startup_optimizer/ tests/test_module_startup_optimizer.py
git commit -m "feat: add startup_optimizer module for boot-time diagnostics"
```

---

### Task 3: Startup Item Auditor

**Files:**
- Create: `modules/bloatware/__init__.py` (empty category marker)
- Create: `modules/bloatware/startup_auditor/__init__.py`
- Create: `modules/bloatware/startup_auditor/data/known_bloatware.json`
- Test: `tests/test_module_startup_auditor.py`

**Interfaces:**
- Consumes: `ModuleBase`; `SystemProfile`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; `subprocess.run(["launchctl", "list"], ...)` and `subprocess.run(["launchctl", "unload", "-w", plist_path], ...)`; `json.load` on the curated data file.
- Produces: `Module` class, `name = "startup_auditor"`, `category = "bloatware"`, `risk_level = RiskLevel.MODERATE` (disabling a startup item is a real system change). Module-level `_parse_launchctl_list`, `_load_known_bloatware`, `_match_bloatware`.

- [ ] **Step 1: Create the bloatware category marker**

Create `modules/bloatware/__init__.py` — empty file.

- [ ] **Step 2: Write failing tests**

Create `tests/test_module_startup_auditor.py`:

```python
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "startup_auditor")


def _fake_run_factory(launchctl_output, unload_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        if cmd[0] == "launchctl" and cmd[1] == "list":
            result.stdout = launchctl_output
            result.returncode = 0
        elif cmd[0] == "launchctl" and cmd[1] == "unload":
            result.stdout = ""
            result.stderr = "" if unload_returncode == 0 else "operation not permitted"
            result.returncode = unload_returncode
        return result
    return fake_run


LAUNCHCTL_OUTPUT = """PID\tStatus\tLabel
415\t0\tcom.apple.something
-\t0\tcom.adobe.acc.installer.v2
1234\t0\tcom.microsoft.autoupdate.helper
-\t0\tcom.spotify.webhelper
5678\t0\tcom.random.unrelated.app
"""


def test_startup_auditor_discovered():
    mod = _get_module()
    assert mod.name == "startup_auditor"
    assert mod.risk_level == RiskLevel.MODERATE


def test_known_bloatware_data_file_valid():
    data_file = (
        Path(__file__).parent.parent
        / "modules" / "bloatware" / "startup_auditor" / "data" / "known_bloatware.json"
    )
    with open(data_file) as f:
        data = json.load(f)
    assert len(data) >= 5
    for entry in data:
        assert "label_pattern" in entry
        assert "name" in entry
        assert "description" in entry


def test_startup_auditor_finds_known_bloatware():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(LAUNCHCTL_OUTPUT)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 3  # adobe, microsoft, spotify — not the random app
    titles = [f.title for f in result.findings]
    assert any("Adobe" in t for t in titles)


def test_startup_auditor_no_matches():
    output = """PID\tStatus\tLabel
415\t0\tcom.apple.something
5678\t0\tcom.random.unrelated.app
"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(output)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_startup_auditor_fix_unloads_job():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(LAUNCHCTL_OUTPUT)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 3


def test_startup_auditor_fix_handles_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_factory(LAUNCHCTL_OUTPUT, unload_returncode=1)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert fix.actions[0].error == "operation not permitted"
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_startup_auditor.py -v`
Expected: FAIL — module "startup_auditor" not found, and the data file doesn't exist yet.

- [ ] **Step 4: Create the curated bloatware data file**

Create `modules/bloatware/startup_auditor/data/known_bloatware.json`:

```json
[
  {
    "label_pattern": "com.adobe.acc",
    "name": "Adobe Creative Cloud Helper",
    "description": "Adobe Creative Cloud background helper that auto-launches at login and consumes background resources."
  },
  {
    "label_pattern": "com.microsoft.autoupdate",
    "name": "Microsoft AutoUpdate",
    "description": "Microsoft's auto-update agent for Office apps; safe to run on-demand instead of at every login."
  },
  {
    "label_pattern": "com.oracle.java.Java-Updater",
    "name": "Java Update Checker",
    "description": "Oracle Java auto-update checker; rarely needed unless actively developing with Java."
  },
  {
    "label_pattern": "com.real.player",
    "name": "RealPlayer Helper",
    "description": "Legacy RealPlayer background helper, considered bloatware by most users."
  },
  {
    "label_pattern": "com.citrixonline.gotomeeting",
    "name": "GoToMeeting Helper",
    "description": "GoToMeeting background helper that launches at login even when not in a meeting."
  },
  {
    "label_pattern": "com.google.keystone",
    "name": "Google Software Update (Keystone)",
    "description": "Google's background updater for Chrome and other Google apps; can be safely limited to manual updates."
  },
  {
    "label_pattern": "com.spotify.webhelper",
    "name": "Spotify Helper",
    "description": "Spotify background helper that keeps the app ready to launch instantly; disable if you don't need instant startup."
  }
]
```

- [ ] **Step 5: Implement the module**

Create `modules/bloatware/startup_auditor/__init__.py`:

```python
import json
import os
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

DATA_FILE = Path(__file__).parent / "data" / "known_bloatware.json"


class Module(ModuleBase):
    name = "startup_auditor"
    category = "bloatware"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.MODERATE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_launchctl_list()
        labels = _parse_launchctl_list(output)
        known_bloatware = _load_known_bloatware()

        findings = []
        for label in labels:
            entry = _match_bloatware(label, known_bloatware)
            if entry is not None:
                findings.append(
                    Finding(
                        title=f"Startup item: {entry['name']}",
                        description=entry["description"],
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"label": label, "name": entry["name"]},
                    )
                )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            label = finding.data["label"]
            name = finding.data.get("name", label)
            plist_path = os.path.expanduser(f"~/Library/LaunchAgents/{label}.plist")
            try:
                result = subprocess.run(
                    ["launchctl", "unload", "-w", plist_path],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip() or "launchctl unload failed"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title=f"Disable startup item: {name}",
                    description=(
                        f"Unloaded launchd job '{label}'. If it reappears at "
                        f"next login, remove the file at {plist_path}."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_launchctl_list(self) -> str:
        result = subprocess.run(
            ["launchctl", "list"],
            capture_output=True,
            text=True,
        )
        return result.stdout


def _parse_launchctl_list(output: str) -> list[str]:
    labels = []
    lines = output.strip().split("\n")
    for line in lines[1:]:
        parts = line.split()
        if len(parts) >= 3:
            labels.append(parts[-1])
    return labels


def _load_known_bloatware() -> list[dict]:
    with open(DATA_FILE) as f:
        return json.load(f)


def _match_bloatware(label: str, known_bloatware: list[dict]) -> dict | None:
    label_lower = label.lower()
    for entry in known_bloatware:
        if entry["label_pattern"].lower() in label_lower:
            return entry
    return None
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_startup_auditor.py -v`
Expected: All 6 tests PASS

- [ ] **Step 7: Commit**

```bash
git add modules/bloatware/__init__.py modules/bloatware/startup_auditor/ tests/test_module_startup_auditor.py
git commit -m "feat: add startup_auditor module with curated launchd bloatware list"
```

---

### Task 4: Process Scanner

**Files:**
- Create: `modules/bloatware/process_scanner/__init__.py`
- Create: `modules/bloatware/process_scanner/data/known_bloatware.json`
- Test: `tests/test_module_process_scanner.py`

**Interfaces:**
- Consumes: `ModuleBase`; `SystemProfile`, `ProcessInfo`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; `profile.processes` (no subprocess in `check()`); `subprocess.run(["kill", "-9", str(pid)], ...)` in `fix()`; `json.load` on the curated data file.
- Produces: `Module` class, `name = "process_scanner"`, `category = "bloatware"`, `risk_level = RiskLevel.MODERATE`.

- [ ] **Step 1: Write failing tests**

Create `tests/test_module_process_scanner.py`:

```python
import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile, Platform, ProcessInfo, Severity, RiskLevel, Mode,
)
from rescue.registry import discover_modules


def _make_profile(processes):
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        processes=processes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "process_scanner")


def test_process_scanner_discovered():
    mod = _get_module()
    assert mod.name == "process_scanner"
    assert mod.risk_level == RiskLevel.MODERATE


def test_known_bloatware_data_file_valid():
    data_file = (
        Path(__file__).parent.parent
        / "modules" / "bloatware" / "process_scanner" / "data" / "known_bloatware.json"
    )
    with open(data_file) as f:
        data = json.load(f)
    assert len(data) >= 5
    for entry in data:
        assert "process_pattern" in entry
        assert "name" in entry
        assert "category" in entry
        assert "description" in entry


def test_process_scanner_healthy():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=1, name="Finder", cpu_percent=1.0, memory_bytes=50 * 1024**2,
                    command="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ])
    result = mod.check(profile)
    assert not result.has_issues


def test_process_scanner_finds_scareware():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=42, name="MacKeeper Helper", cpu_percent=8.0,
                    memory_bytes=150 * 1024**2,
                    command="/Applications/MacKeeper.app/Contents/MacOS/MacKeeper Helper"),
        ProcessInfo(pid=1, name="Finder", cpu_percent=1.0, memory_bytes=50 * 1024**2,
                    command="/System/Library/CoreServices/Finder.app/Contents/MacOS/Finder"),
    ])
    result = mod.check(profile)
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["pid"] == 42


def test_process_scanner_fix_kills_process():
    mod = _get_module()
    profile = _make_profile([
        ProcessInfo(pid=42, name="MacKeeper Helper", cpu_percent=8.0,
                    memory_bytes=150 * 1024**2,
                    command="/Applications/MacKeeper.app/Contents/MacOS/MacKeeper Helper"),
    ])
    check = mod.check(profile)

    fake_result = MagicMock()
    fake_result.returncode = 0
    fake_result.stderr = ""

    with patch("subprocess.run", return_value=fake_result) as mock_run:
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    mock_run.assert_called_once_with(["kill", "-9", "42"], capture_output=True, text=True)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_process_scanner.py -v`
Expected: FAIL — module "process_scanner" not found, data file missing.

- [ ] **Step 3: Create the curated bloatware process list**

Create `modules/bloatware/process_scanner/data/known_bloatware.json`:

```json
[
  {"process_pattern": "MacKeeper", "name": "MacKeeper", "category": "scareware", "description": "Scareware utility known for aggressive fake-issue popups and high resource usage."},
  {"process_pattern": "Genieo", "name": "Genieo", "category": "adware", "description": "Adware/browser hijacker bundled with free software installers."},
  {"process_pattern": "InstallMac", "name": "InstallMac Installer", "category": "pup", "description": "Bundleware installer framework commonly used to distribute potentially unwanted programs."},
  {"process_pattern": "Advanced Mac Cleaner", "name": "Advanced Mac Cleaner", "category": "scareware", "description": "Fake system cleaner that pressures users into paying for a license to fix invented problems."},
  {"process_pattern": "SearchProtect", "name": "Conduit SearchProtect", "category": "adware", "description": "Browser hijacker that locks in a hijacked search engine and homepage."},
  {"process_pattern": "MacBooster", "name": "MacBooster", "category": "scareware", "description": "Fake performance-optimization utility that exaggerates system issues to sell upgrades."},
  {"process_pattern": "Genio", "name": "Genio", "category": "adware", "description": "Adware variant that injects ads into browser sessions."}
]
```

- [ ] **Step 4: Implement the module**

Create `modules/bloatware/process_scanner/__init__.py`:

```python
import json
import subprocess
from pathlib import Path

from rescue.models import (
    Action,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    ProcessInfo,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

DATA_FILE = Path(__file__).parent / "data" / "known_bloatware.json"
CRITICAL_CATEGORIES = {"scareware"}


class Module(ModuleBase):
    name = "process_scanner"
    category = "bloatware"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.MODERATE
    priority = 75
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        known_bloatware = _load_known_bloatware()
        findings = []
        for proc in profile.processes:
            entry = _match_bloatware(proc, known_bloatware)
            if entry is not None:
                severity = (
                    Severity.CRITICAL
                    if entry["category"] in CRITICAL_CATEGORIES
                    else Severity.WARNING
                )
                findings.append(self._make_finding(proc, entry, severity))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            pid = finding.data.get("pid")
            name = finding.data.get("bloatware_name", "unknown")
            try:
                result = subprocess.run(
                    ["kill", "-9", str(pid)],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip() or "kill command failed"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title=f"Terminate {name} (pid {pid})",
                    description=(
                        f"Sent SIGKILL to {name} (pid {pid}), identified as "
                        f"{finding.data.get('bloatware_category')}."
                    ),
                    risk_level=RiskLevel.MODERATE,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(
        self, proc: ProcessInfo, entry: dict, severity: Severity
    ) -> Finding:
        return Finding(
            title=f"{entry['name']} detected running",
            description=entry["description"],
            severity=severity,
            category=self.category,
            data={
                "pid": proc.pid,
                "process_name": proc.name,
                "bloatware_name": entry["name"],
                "bloatware_category": entry["category"],
            },
        )


def _load_known_bloatware() -> list[dict]:
    with open(DATA_FILE) as f:
        return json.load(f)


def _match_bloatware(proc: ProcessInfo, known_bloatware: list[dict]) -> dict | None:
    haystack = f"{proc.name} {proc.command}".lower()
    for entry in known_bloatware:
        if entry["process_pattern"].lower() in haystack:
            return entry
    return None
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_process_scanner.py -v`
Expected: All 5 tests PASS

- [ ] **Step 6: Commit**

```bash
git add modules/bloatware/process_scanner/ tests/test_module_process_scanner.py
git commit -m "feat: add process_scanner module with curated bloatware process list"
```

---

### Task 5: Update Checker

**Files:**
- Create: `modules/integrity/__init__.py` (empty category marker)
- Create: `modules/integrity/update_checker/__init__.py`
- Test: `tests/test_module_update_checker.py`

**Interfaces:**
- Consumes: `ModuleBase`; `SystemProfile`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; `subprocess.run(["softwareupdate", "-l"], ...)` and `subprocess.run(["brew", "outdated"], ...)`.
- Produces: `Module` class, `name = "update_checker"`, `category = "integrity"`, `risk_level = RiskLevel.SAFE` (informational guidance only — installing OS/package updates is left to the user). Module-level `_parse_softwareupdate_output`, `_parse_brew_outdated`.

- [ ] **Step 1: Create the integrity category marker**

Create `modules/integrity/__init__.py` — empty file.

- [ ] **Step 2: Write failing tests**

Create `tests/test_module_update_checker.py`:

```python
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "update_checker")


SOFTWAREUPDATE_PENDING = """Software Update Tool

Finding available software
Software Update found the following new or updated software:
* Label: macOS Sequoia 15.3-24D60
\tTitle: macOS Sequoia 15.3, Version: 15.3, Size: 3193980KiB, Recommended: YES,
* Label: Safari18.3-18.3
\tTitle: Safari, Version: 18.3, Size: 43112KiB, Recommended: YES,
"""

SOFTWAREUPDATE_NONE = "No new software available.\n"

BREW_OUTDATED_SOME = """git (2.43.0) < 2.44.0
node (21.6.0) < 21.7.0
"""

BREW_OUTDATED_NONE = ""


def _fake_run(softwareupdate_output, brew_output, brew_missing=False):
    def fake_run(cmd, **kwargs):
        if cmd[0] == "softwareupdate":
            result = MagicMock()
            result.stdout = softwareupdate_output
            result.returncode = 0
            return result
        elif cmd[0] == "brew":
            if brew_missing:
                raise FileNotFoundError("brew not found")
            result = MagicMock()
            result.stdout = brew_output
            result.returncode = 0
            return result
        raise AssertionError(f"unexpected command {cmd}")
    return fake_run


def test_update_checker_discovered():
    mod = _get_module()
    assert mod.name == "update_checker"
    assert mod.risk_level == RiskLevel.SAFE


def test_update_checker_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_NONE, BREW_OUTDATED_NONE)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_update_checker_pending_os_updates():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_PENDING, BREW_OUTDATED_NONE)):
        result = mod.check(_make_profile())
    assert result.has_issues
    finding = next(f for f in result.findings if f.data["check"] == "os_updates")
    assert len(finding.data["updates"]) == 2
    assert finding.severity == Severity.WARNING


def test_update_checker_outdated_brew():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_NONE, BREW_OUTDATED_SOME)):
        result = mod.check(_make_profile())
    assert result.has_issues
    finding = next(f for f in result.findings if f.data["check"] == "brew_outdated")
    assert finding.data["packages"] == ["git", "node"]


def test_update_checker_brew_not_installed():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_NONE, "", brew_missing=True)):
        result = mod.check(_make_profile())
    assert not result.has_issues  # no crash — brew check silently skipped


def test_update_checker_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(SOFTWAREUPDATE_PENDING, BREW_OUTDATED_SOME)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert len(fix.actions) == 2
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_update_checker.py -v`
Expected: FAIL — module "update_checker" not found.

- [ ] **Step 4: Implement the module**

Create `modules/integrity/update_checker/__init__.py`:

```python
import subprocess

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


class Module(ModuleBase):
    name = "update_checker"
    category = "integrity"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "30s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        os_updates = _parse_softwareupdate_output(self._run_softwareupdate())
        if os_updates:
            findings.append(
                Finding(
                    title=f"{len(os_updates)} macOS update(s) available",
                    description="Pending updates: " + ", ".join(os_updates),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "os_updates", "updates": os_updates},
                )
            )

        brew_output = self._run_brew_outdated()
        if brew_output is not None:
            outdated_packages = _parse_brew_outdated(brew_output)
            if outdated_packages:
                findings.append(
                    Finding(
                        title=f"{len(outdated_packages)} outdated Homebrew package(s)",
                        description="Outdated packages: " + ", ".join(outdated_packages),
                        severity=Severity.WARNING,
                        category=self.category,
                        data={"check": "brew_outdated", "packages": outdated_packages},
                    )
                )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "os_updates":
                actions.append(
                    Action(
                        title="macOS update guidance",
                        description=(
                            "Run `sudo softwareupdate -i -a` to install all "
                            "pending updates, or open System Settings > "
                            "General > Software Update."
                        ),
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
            elif check == "brew_outdated":
                actions.append(
                    Action(
                        title="Homebrew update guidance",
                        description="Run `brew upgrade` to update all outdated packages.",
                        risk_level=RiskLevel.SAFE,
                        success=True,
                    )
                )
        return FixResult(module_name=self.name, actions=actions)

    def _run_softwareupdate(self) -> str:
        result = subprocess.run(
            ["softwareupdate", "-l"],
            capture_output=True,
            text=True,
        )
        return result.stdout

    def _run_brew_outdated(self) -> str | None:
        try:
            result = subprocess.run(
                ["brew", "outdated"],
                capture_output=True,
                text=True,
            )
        except OSError:
            return None
        return result.stdout


def _parse_softwareupdate_output(output: str) -> list[str]:
    labels = []
    for line in output.splitlines():
        stripped = line.strip()
        if stripped.startswith("* Label:"):
            labels.append(stripped.split("Label:", 1)[1].strip())
    return labels


def _parse_brew_outdated(output: str) -> list[str]:
    packages = []
    for line in output.strip().splitlines():
        line = line.strip()
        if line:
            packages.append(line.split()[0])
    return packages
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_update_checker.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Commit**

```bash
git add modules/integrity/__init__.py modules/integrity/update_checker/ tests/test_module_update_checker.py
git commit -m "feat: add update_checker module for pending macOS/Homebrew updates"
```

---

### Task 6: Firewall Audit

**Files:**
- Create: `modules/security/__init__.py` (empty category marker)
- Create: `modules/security/firewall_audit/__init__.py`
- Test: `tests/test_module_firewall_audit.py`

**Interfaces:**
- Consumes: `ModuleBase`; `SystemProfile`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; `subprocess.run(["/usr/libexec/ApplicationFirewall/socketfilterfw", "--getglobalstate"|"--getstealthmode"|"--setglobalstate"|"--setstealthmode", ...], ...)`.
- Produces: `Module` class, `name = "firewall_audit"`, `category = "security"`, `risk_level = RiskLevel.MODERATE` (flipping a firewall setting requires elevated privileges and is a real system change).

- [ ] **Step 1: Create the security category marker**

Create `modules/security/__init__.py` — empty file.

- [ ] **Step 2: Write failing tests**

Create `tests/test_module_firewall_audit.py`:

```python
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "firewall_audit")


def _fake_run(global_state_output, stealth_output, set_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "--getglobalstate" in cmd:
            result.stdout = global_state_output
        elif "--getstealthmode" in cmd:
            result.stdout = stealth_output
        elif "--setglobalstate" in cmd or "--setstealthmode" in cmd:
            result.stdout = ""
            result.returncode = set_returncode
            if set_returncode != 0:
                result.stderr = "Operation not permitted"
        return result
    return fake_run


def test_firewall_audit_discovered():
    mod = _get_module()
    assert mod.name == "firewall_audit"
    assert mod.risk_level == RiskLevel.MODERATE


def test_firewall_audit_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is enabled. (State = 1)\n", "Stealth mode is enabled.\n"
    )):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_firewall_audit_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is disabled. (State = 0)\n", "Stealth mode is enabled.\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["check"] == "global_state"


def test_firewall_audit_stealth_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is enabled. (State = 1)\n", "Stealth mode is disabled.\n"
    )):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["check"] == "stealth_mode"


def test_firewall_audit_fix_enables_firewall():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is disabled. (State = 0)\n", "Stealth mode is disabled.\n"
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 2


def test_firewall_audit_fix_handles_permission_failure():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(
        "Firewall is disabled. (State = 0)\n", "Stealth mode is enabled.\n", set_returncode=1
    )):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert "Operation not permitted" in fix.actions[0].error
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_firewall_audit.py -v`
Expected: FAIL — module "firewall_audit" not found.

- [ ] **Step 4: Implement the module**

Create `modules/security/firewall_audit/__init__.py`:

```python
import subprocess

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

SOCKETFILTERFW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


class Module(ModuleBase):
    name = "firewall_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.MODERATE
    priority = 60
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []

        global_state = self._run_socketfilterfw("--getglobalstate")
        if "disabled" in global_state.lower():
            findings.append(
                Finding(
                    title="Firewall is disabled",
                    description=(
                        "The macOS Application Firewall is currently disabled. "
                        "This leaves the system open to unsolicited incoming "
                        "connections."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"check": "global_state"},
                )
            )

        stealth_state = self._run_socketfilterfw("--getstealthmode")
        if "disabled" in stealth_state.lower():
            findings.append(
                Finding(
                    title="Stealth mode is disabled",
                    description=(
                        "Stealth mode is off, so this Mac responds to network "
                        "probes (e.g. ping) that could reveal it to attackers "
                        "scanning the network."
                    ),
                    severity=Severity.WARNING,
                    category=self.category,
                    data={"check": "stealth_mode"},
                )
            )

        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            check = finding.data.get("check")
            if check == "global_state":
                flag, label = "--setglobalstate", "Enable firewall"
            elif check == "stealth_mode":
                flag, label = "--setstealthmode", "Enable stealth mode"
            else:
                continue
            try:
                result = subprocess.run(
                    [SOCKETFILTERFW, flag, "on"],
                    capture_output=True,
                    text=True,
                )
                success = result.returncode == 0
                error = None if success else (
                    result.stderr.strip()
                    or "socketfilterfw command failed (may require sudo)"
                )
            except OSError as e:
                success = False
                error = str(e)
            actions.append(
                Action(
                    title=label,
                    description=f"Ran `socketfilterfw {flag} on`.",
                    risk_level=RiskLevel.MODERATE,
                    success=success,
                    error=error,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_socketfilterfw(self, flag: str) -> str:
        result = subprocess.run(
            [SOCKETFILTERFW, flag],
            capture_output=True,
            text=True,
        )
        return result.stdout
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_firewall_audit.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Commit**

```bash
git add modules/security/__init__.py modules/security/firewall_audit/ tests/test_module_firewall_audit.py
git commit -m "feat: add firewall_audit module for macOS Application Firewall status"
```

---

### Task 7: Disk Encryption Check

**Files:**
- Create: `modules/security/encryption_check/__init__.py`
- Test: `tests/test_module_encryption_check.py`

**Interfaces:**
- Consumes: `ModuleBase`; `SystemProfile`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`; `subprocess.run(["fdesetup", "status"], ...)`.
- Produces: `Module` class, `name = "encryption_check"`, `category = "security"`, `risk_level = RiskLevel.SAFE` (enabling FileVault requires an interactive setup flow and a reboot, so `fix()` gives guidance rather than acting).

- [ ] **Step 1: Write failing tests**

Create `tests/test_module_encryption_check.py`:

```python
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "encryption_check")


def _fake_run(output):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.stdout = output
        result.returncode = 0
        return result
    return fake_run


def test_encryption_check_discovered():
    mod = _get_module()
    assert mod.name == "encryption_check"
    assert mod.risk_level == RiskLevel.SAFE


def test_encryption_check_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("FileVault is On.\n")):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_encryption_check_off():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("FileVault is Off.\n")):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_encryption_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("FileVault is Off.\n")):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert "fdesetup enable" in fix.actions[0].description
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_encryption_check.py -v`
Expected: FAIL — module "encryption_check" not found.

- [ ] **Step 3: Implement the module**

Create `modules/security/encryption_check/__init__.py`:

```python
import subprocess

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


class Module(ModuleBase):
    name = "encryption_check"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    priority = 90
    depends_on = []
    estimated_duration = "3s"

    def check(self, profile: SystemProfile) -> CheckResult:
        output = self._run_fdesetup_status()
        findings = []
        if "off" in output.lower():
            findings.append(
                Finding(
                    title="FileVault disk encryption is disabled",
                    description=(
                        "FileVault is off. If this device is lost or stolen, "
                        "its contents can be read by anyone with physical "
                        "access to the disk."
                    ),
                    severity=Severity.CRITICAL,
                    category=self.category,
                    data={"fdesetup_output": output.strip()},
                )
            )
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for _finding in findings.findings:
            actions.append(
                Action(
                    title="Enable FileVault",
                    description=(
                        "FileVault must be enabled interactively. Run "
                        "`sudo fdesetup enable` in Terminal, follow the "
                        "prompts, and store the recovery key somewhere safe. "
                        "Initial encryption runs in the background and may "
                        "take a few hours."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _run_fdesetup_status(self) -> str:
        result = subprocess.run(
            ["fdesetup", "status"],
            capture_output=True,
            text=True,
        )
        return result.stdout
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_encryption_check.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Run the full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS — core framework tests plus all 7 new module test files (models, profiler, module_base, registry, orchestrator, cli, disk_space, resource_hog_identifier, startup_optimizer, startup_auditor, process_scanner, update_checker, firewall_audit, encryption_check).

- [ ] **Step 6: Smoke test discovery and auto mode end-to-end**

Run:
```bash
python -m rescue.cli run resource_hog_identifier startup_optimizer update_checker firewall_audit encryption_check --yes
```

Expected: The tool profiles the system, runs each named module against real system state (real `subprocess` calls this time, not mocks), and prints a report per module — no crashes even if e.g. Homebrew isn't installed or the firewall command needs `sudo` (fix actions will show `error` fields rather than raising exceptions).

- [ ] **Step 7: Commit**

```bash
git add modules/security/encryption_check/ tests/test_module_encryption_check.py
git commit -m "feat: add encryption_check module for FileVault status"
```

---

## Future Plans

Remaining Module Categories bullets not covered by this plan, to be picked up in a later module-pack plan:

- **Bloatware:** Browser extension auditor, adware/PUP location scanner (beyond the process-name matching done here)
- **Performance:** SSD/disk health checker (SMART data)
- **System Integrity:** System file verifier (`diskutil verifyVolume` wrapper), driver health (Windows), broken symlink/permission fixer
- **Security Hardening:** Password policy check, software vulnerability scan (CVE matching), open port scanner
- **Privacy:** OS telemetry configurator, browser privacy configurator, social media walkthroughs, human task scheduler
- **Cross-platform:** Windows (`win32`) and Linux implementations of all seven modules built in this plan, following the same `check()`/`fix()` shape but swapping the underlying shell commands (`Get-CimInstance`, `systemctl`, `apt`, `ufw`, `cryptsetup status`, etc.)
