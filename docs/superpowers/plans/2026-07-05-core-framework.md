# Core Framework Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the core framework — data models, system profiler, module system, orchestrator, and CLI — so that `rescue --auto` and `rescue run <module>` work end-to-end with at least one real module.

**Architecture:** Four-layer Plugin Registry. The System Profiler gathers platform facts into a `SystemProfile` dataclass. The Module Registry discovers modules by scanning the `modules/` directory and filtering by platform. The Orchestrator wires profiler + registry together, runs checks/fixes in dependency order. The CLI provides the user-facing entry point via Click.

**Tech Stack:** Python 3.11+, Click (CLI), pytest (testing), subprocess (shell script execution)

## Global Constraints

- Python 3.11+ required (uses `X | Y` union syntax and modern dataclass features)
- No external dependencies beyond Click for the CLI — the core framework uses only stdlib + Click
- All platform-specific work happens in shell scripts called via `subprocess.run`, never inline platform-conditional Python
- Module discovery is filesystem-based — no central registration file
- `risk_level` governs fix behavior: `safe` runs without prompting in auto mode, `moderate` and `destructive` prompt individually
- Every shell command executed via subprocess must use `capture_output=True` and must not use `shell=True` with user-controlled input

---

### Task 1: Project Scaffolding & Data Models

**Files:**
- Create: `pyproject.toml`
- Create: `rescue/__init__.py`
- Create: `rescue/models.py`
- Test: `tests/__init__.py`
- Test: `tests/test_models.py`

**Interfaces:**
- Consumes: nothing (first task)
- Produces:
  - `Platform` enum with values `DARWIN`, `WIN32`, `LINUX`
  - `RiskLevel` enum with values `SAFE`, `MODERATE`, `DESTRUCTIVE`
  - `Severity` enum with values `INFO`, `WARNING`, `CRITICAL`
  - `Mode` enum with values `AUTO`, `MANUAL`, `CLI`
  - `DiskInfo` dataclass: `device: str, mount_point: str, total_bytes: int, used_bytes: int, free_bytes: int, filesystem: str, is_ssd: bool | None`
  - `ProcessInfo` dataclass: `pid: int, name: str, cpu_percent: float, memory_bytes: int, command: str`
  - `SystemProfile` dataclass: `platform: Platform, os_name: str, os_version: str, architecture: str, cpu_model: str, cpu_cores: int, ram_bytes: int, disks: list[DiskInfo], processes: list[ProcessInfo], startup_items: list[str], installed_software: list[str], hostname: str`
  - `Finding` dataclass: `title: str, description: str, severity: Severity, category: str, data: dict[str, Any]`
  - `CheckResult` dataclass: `module_name: str, findings: list[Finding]` with property `has_issues -> bool`
  - `Action` dataclass: `title: str, description: str, risk_level: RiskLevel, success: bool, error: str | None, data: dict[str, Any]`
  - `FixResult` dataclass: `module_name: str, actions: list[Action]` with property `all_succeeded -> bool`

- [ ] **Step 1: Create pyproject.toml**

```toml
[build-system]
requires = ["setuptools>=68.0"]
build-backend = "setuptools.build_meta"

[project]
name = "multiverse-device-rescue"
version = "0.1.0"
description = "Modern system diagnostic, repair, and maintenance toolkit"
requires-python = ">=3.11"
dependencies = [
    "click>=8.0",
]

[project.optional-dependencies]
dev = ["pytest>=8.0"]

[project.scripts]
rescue = "rescue.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]

[tool.setuptools.packages.find]
include = ["rescue*"]
```

- [ ] **Step 2: Create rescue/__init__.py**

```python
"""Multiverse Device Rescue — system diagnostic and repair toolkit."""

__version__ = "0.1.0"
```

- [ ] **Step 3: Create tests/__init__.py**

Empty file.

- [ ] **Step 4: Write failing tests for data models**

Create `tests/test_models.py`:

```python
from rescue.models import (
    Platform,
    RiskLevel,
    Severity,
    Mode,
    DiskInfo,
    ProcessInfo,
    SystemProfile,
    Finding,
    CheckResult,
    Action,
    FixResult,
)


def test_platform_values():
    assert Platform.DARWIN == "darwin"
    assert Platform.WIN32 == "win32"
    assert Platform.LINUX == "linux"


def test_risk_level_ordering():
    assert RiskLevel.SAFE == "safe"
    assert RiskLevel.MODERATE == "moderate"
    assert RiskLevel.DESTRUCTIVE == "destructive"


def test_system_profile_creation():
    profile = SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )
    assert profile.platform == Platform.DARWIN
    assert profile.disks == []
    assert profile.processes == []
    assert profile.hostname == ""


def test_check_result_has_issues():
    empty = CheckResult(module_name="test")
    assert not empty.has_issues

    with_finding = CheckResult(
        module_name="test",
        findings=[
            Finding(
                title="Test",
                description="A test finding",
                severity=Severity.WARNING,
                category="test",
            )
        ],
    )
    assert with_finding.has_issues


def test_fix_result_all_succeeded():
    result = FixResult(
        module_name="test",
        actions=[
            Action(
                title="Action 1",
                description="Did something",
                risk_level=RiskLevel.SAFE,
                success=True,
            ),
            Action(
                title="Action 2",
                description="Did another thing",
                risk_level=RiskLevel.SAFE,
                success=True,
            ),
        ],
    )
    assert result.all_succeeded

    result.actions[1].success = False
    assert not result.all_succeeded


def test_finding_default_data():
    finding = Finding(
        title="Test",
        description="Desc",
        severity=Severity.INFO,
        category="test",
    )
    assert finding.data == {}


def test_disk_info_ssd_default():
    disk = DiskInfo(
        device="/dev/disk1",
        mount_point="/",
        total_bytes=500 * 1024**3,
        used_bytes=400 * 1024**3,
        free_bytes=100 * 1024**3,
        filesystem="apfs",
    )
    assert disk.is_ssd is None
```

- [ ] **Step 5: Run tests to verify they fail**

Run: `python -m pytest tests/test_models.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.models'`

- [ ] **Step 6: Implement data models**

Create `rescue/models.py`:

```python
from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class Platform(str, Enum):
    DARWIN = "darwin"
    WIN32 = "win32"
    LINUX = "linux"


class RiskLevel(str, Enum):
    SAFE = "safe"
    MODERATE = "moderate"
    DESTRUCTIVE = "destructive"


class Severity(str, Enum):
    INFO = "info"
    WARNING = "warning"
    CRITICAL = "critical"


class Mode(str, Enum):
    AUTO = "auto"
    MANUAL = "manual"
    CLI = "cli"


@dataclass
class DiskInfo:
    device: str
    mount_point: str
    total_bytes: int
    used_bytes: int
    free_bytes: int
    filesystem: str
    is_ssd: bool | None = None


@dataclass
class ProcessInfo:
    pid: int
    name: str
    cpu_percent: float
    memory_bytes: int
    command: str


@dataclass
class SystemProfile:
    platform: Platform
    os_name: str
    os_version: str
    architecture: str
    cpu_model: str
    cpu_cores: int
    ram_bytes: int
    disks: list[DiskInfo] = field(default_factory=list)
    processes: list[ProcessInfo] = field(default_factory=list)
    startup_items: list[str] = field(default_factory=list)
    installed_software: list[str] = field(default_factory=list)
    hostname: str = ""


@dataclass
class Finding:
    title: str
    description: str
    severity: Severity
    category: str
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class CheckResult:
    module_name: str
    findings: list[Finding] = field(default_factory=list)

    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0


@dataclass
class Action:
    title: str
    description: str
    risk_level: RiskLevel
    success: bool = False
    error: str | None = None
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class FixResult:
    module_name: str
    actions: list[Action] = field(default_factory=list)

    @property
    def all_succeeded(self) -> bool:
        return all(a.success for a in self.actions)
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_models.py -v`
Expected: All 7 tests PASS

- [ ] **Step 8: Install project in dev mode and commit**

Run:
```bash
pip install -e ".[dev]" 2>/dev/null || pip install -e .
git add pyproject.toml rescue/__init__.py rescue/models.py tests/__init__.py tests/test_models.py
git commit -m "feat: add project scaffolding and core data models"
```

---

### Task 2: System Profiler (macOS)

**Files:**
- Create: `rescue/profiler/__init__.py`
- Create: `rescue/profiler/base.py`
- Create: `rescue/profiler/darwin.py`
- Test: `tests/test_profiler.py`

**Interfaces:**
- Consumes: `Platform`, `SystemProfile`, `DiskInfo`, `ProcessInfo` from `rescue.models`
- Produces:
  - `detect_platform() -> Platform` in `rescue.profiler.base`
  - `gather_profile() -> SystemProfile` in `rescue.profiler.base` — dispatches to platform-specific implementation
  - `gather_darwin_profile() -> SystemProfile` in `rescue.profiler.darwin`

- [ ] **Step 1: Write failing tests for the profiler**

Create `tests/test_profiler.py`:

```python
import subprocess
from unittest.mock import patch, MagicMock

from rescue.models import Platform, SystemProfile
from rescue.profiler.base import detect_platform, gather_profile
from rescue.profiler.darwin import gather_darwin_profile, _parse_df_output, _parse_ps_output


def test_detect_platform_darwin():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "darwin"
        assert detect_platform() == Platform.DARWIN


def test_detect_platform_win32():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "win32"
        assert detect_platform() == Platform.WIN32


def test_detect_platform_linux():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "linux"
        assert detect_platform() == Platform.LINUX


def test_detect_platform_unsupported():
    with patch("rescue.profiler.base.sys") as mock_sys:
        mock_sys.platform = "freebsd"
        try:
            detect_platform()
            assert False, "Should have raised RuntimeError"
        except RuntimeError as e:
            assert "Unsupported platform" in str(e)


def test_parse_df_output():
    df_output = """Filesystem   1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1   460857696 316498192 121579504    73%    /
devfs                399       399         0   100%    /dev
/dev/disk3s5   460857696   262144 121579504     1%    /System/Volumes/VM
"""
    disks = _parse_df_output(df_output)
    assert len(disks) == 2  # /dev/ entries only, devfs excluded
    assert disks[0].mount_point == "/"
    assert disks[0].total_bytes == 460857696 * 1024
    assert disks[0].used_bytes == 316498192 * 1024


def test_parse_ps_output():
    ps_output = """USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 410327040  13040   ??  Ss   Sat08AM   3:22.85 /sbin/launchd
annhoward         5678  12.3  1.5 418955264  65536   ??  S    10:00AM   1:23.45 /Applications/Spotify.app/Contents/MacOS/Spotify
"""
    processes = _parse_ps_output(ps_output)
    assert len(processes) == 2
    assert processes[0].pid == 1
    assert processes[0].name == "launchd"
    assert processes[1].cpu_percent == 12.3
    assert processes[1].name == "Spotify"


def test_gather_darwin_profile():
    mock_results = {
        ("sysctl", "-n", "machdep.cpu.brand_string"): "Apple M2",
        ("sysctl", "-n", "hw.ncpu"): "8",
        ("sysctl", "-n", "hw.memsize"): "17179869184",
        ("hostname",): "test-mac.local",
    }

    df_output = """Filesystem   1024-blocks      Used Available Capacity  Mounted on
/dev/disk3s1   460857696 316498192 121579504    73%    /
"""

    ps_output = """USER               PID  %CPU %MEM      VSZ    RSS   TT  STAT STARTED      TIME COMMAND
root                 1   0.0  0.1 410327040  13040   ??  Ss   Sat08AM   3:22.85 /sbin/launchd
"""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        cmd_tuple = tuple(cmd)
        if cmd_tuple in mock_results:
            result.stdout = mock_results[cmd_tuple]
        elif cmd_tuple == ("df", "-k"):
            result.stdout = df_output
        elif cmd_tuple[0] == "ps":
            result.stdout = ps_output
        else:
            result.stdout = ""
        result.returncode = 0
        return result

    with patch("rescue.profiler.darwin.subprocess.run", side_effect=fake_run), \
         patch("rescue.profiler.darwin.platform.mac_ver", return_value=("15.2", ("", "", ""), "")), \
         patch("rescue.profiler.darwin.platform.machine", return_value="arm64"):
        profile = gather_darwin_profile()

    assert profile.platform == Platform.DARWIN
    assert profile.os_name == "macOS"
    assert profile.os_version == "15.2"
    assert profile.architecture == "arm64"
    assert profile.cpu_model == "Apple M2"
    assert profile.cpu_cores == 8
    assert profile.ram_bytes == 17179869184
    assert profile.hostname == "test-mac.local"
    assert len(profile.disks) == 1
    assert len(profile.processes) == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_profiler.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.profiler'`

- [ ] **Step 3: Implement the profiler**

Create `rescue/profiler/__init__.py`:

```python
```

Create `rescue/profiler/base.py`:

```python
import sys

from rescue.models import Platform, SystemProfile


def detect_platform() -> Platform:
    if sys.platform == "darwin":
        return Platform.DARWIN
    elif sys.platform == "win32":
        return Platform.WIN32
    elif sys.platform.startswith("linux"):
        return Platform.LINUX
    raise RuntimeError(f"Unsupported platform: {sys.platform}")


def gather_profile() -> SystemProfile:
    plat = detect_platform()
    if plat == Platform.DARWIN:
        from rescue.profiler.darwin import gather_darwin_profile
        return gather_darwin_profile()
    elif plat == Platform.WIN32:
        from rescue.profiler.win32 import gather_win32_profile
        return gather_win32_profile()
    elif plat == Platform.LINUX:
        from rescue.profiler.linux import gather_linux_profile
        return gather_linux_profile()
```

Create `rescue/profiler/darwin.py`:

```python
import platform
import subprocess

from rescue.models import DiskInfo, Platform, ProcessInfo, SystemProfile


def gather_darwin_profile() -> SystemProfile:
    os_version = platform.mac_ver()[0]
    architecture = platform.machine()
    cpu_model = _run("sysctl", "-n", "machdep.cpu.brand_string").strip()
    cpu_cores = int(_run("sysctl", "-n", "hw.ncpu").strip())
    ram_bytes = int(_run("sysctl", "-n", "hw.memsize").strip())
    hostname = _run("hostname").strip()

    df_output = _run("df", "-k")
    disks = _parse_df_output(df_output)

    ps_output = _run("ps", "aux")
    processes = _parse_ps_output(ps_output)

    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version=os_version,
        architecture=architecture,
        cpu_model=cpu_model,
        cpu_cores=cpu_cores,
        ram_bytes=ram_bytes,
        disks=disks,
        processes=processes,
        hostname=hostname,
    )


def _run(*cmd: str) -> str:
    result = subprocess.run(cmd, capture_output=True, text=True)
    return result.stdout


def _parse_df_output(output: str) -> list[DiskInfo]:
    disks = []
    for line in output.strip().split("\n")[1:]:
        parts = line.split()
        if len(parts) >= 6 and parts[0].startswith("/dev/"):
            total = int(parts[1]) * 1024
            used = int(parts[2]) * 1024
            free = int(parts[3]) * 1024
            mount = parts[-1]
            disks.append(
                DiskInfo(
                    device=parts[0],
                    mount_point=mount,
                    total_bytes=total,
                    used_bytes=used,
                    free_bytes=free,
                    filesystem="apfs",
                )
            )
    return disks


def _parse_ps_output(output: str) -> list[ProcessInfo]:
    processes = []
    for line in output.strip().split("\n")[1:]:
        parts = line.split(None, 10)
        if len(parts) >= 11:
            try:
                name = parts[10].split("/")[-1].split()[0]
                processes.append(
                    ProcessInfo(
                        pid=int(parts[1]),
                        name=name,
                        cpu_percent=float(parts[2]),
                        memory_bytes=int(parts[5]) * 1024,
                        command=parts[10],
                    )
                )
            except (ValueError, IndexError):
                continue
    return processes
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_profiler.py -v`
Expected: All 7 tests PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/profiler/ tests/test_profiler.py
git commit -m "feat: add system profiler with macOS implementation"
```

---

### Task 3: Module Base Class & Registry

**Files:**
- Create: `rescue/module_base.py`
- Create: `rescue/registry.py`
- Test: `tests/test_module_base.py`
- Test: `tests/test_registry.py`

**Interfaces:**
- Consumes: `SystemProfile`, `CheckResult`, `FixResult`, `Mode`, `Platform`, `RiskLevel`, `Finding`, `Action`, `Severity` from `rescue.models`
- Produces:
  - `ModuleBase` abstract class in `rescue.module_base` with abstract methods `check(profile: SystemProfile) -> CheckResult` and `fix(findings: CheckResult, mode: Mode) -> FixResult`, and concrete method `report(check: CheckResult, fix: FixResult | None) -> str`
  - `discover_modules(modules_dir: Path) -> list[ModuleBase]` in `rescue.registry`
  - `filter_by_platform(modules: list[ModuleBase], platform: Platform) -> list[ModuleBase]` in `rescue.registry`
  - `topological_sort(modules: list[ModuleBase]) -> list[ModuleBase]` in `rescue.registry`

- [ ] **Step 1: Write failing tests for ModuleBase**

Create `tests/test_module_base.py`:

```python
from rescue.models import (
    SystemProfile, Platform, CheckResult, FixResult, Finding,
    Action, Severity, RiskLevel, Mode,
)
from rescue.module_base import ModuleBase


class FakeModule(ModuleBase):
    name = "fake_module"
    category = "test"
    platforms = [Platform.DARWIN, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 50
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Test issue",
                    description="Something is wrong",
                    severity=Severity.WARNING,
                    category=self.category,
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Fixed it",
                    description="Did the fix",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            ],
        )


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


def test_module_check():
    mod = FakeModule()
    result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].title == "Test issue"


def test_module_fix():
    mod = FakeModule()
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded
    assert len(fix.actions) == 1


def test_module_report_with_issues():
    mod = FakeModule()
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    report = mod.report(check, fix)
    assert "fake_module" in report
    assert "Test issue" in report
    assert "Fixed it" in report
    assert "OK" in report


def test_module_report_no_issues():
    mod = FakeModule()
    check = CheckResult(module_name="fake_module")
    report = mod.report(check)
    assert "No issues found" in report
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_base.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.module_base'`

- [ ] **Step 3: Implement ModuleBase**

Create `rescue/module_base.py`:

```python
from abc import ABC, abstractmethod

from rescue.models import (
    CheckResult,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    SystemProfile,
)


class ModuleBase(ABC):
    name: str
    category: str
    platforms: list[Platform]
    risk_level: RiskLevel = RiskLevel.SAFE
    priority: int = 50
    depends_on: list[str] = []
    estimated_duration: str = "unknown"

    @abstractmethod
    def check(self, profile: SystemProfile) -> CheckResult:
        ...

    @abstractmethod
    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        ...

    def report(self, check: CheckResult, fix: FixResult | None = None) -> str:
        lines = [f"=== {self.name} ==="]
        if not check.has_issues:
            lines.append("No issues found.")
            return "\n".join(lines)
        lines.append(f"Found {len(check.findings)} issue(s):")
        for f in check.findings:
            lines.append(f"  [{f.severity.value}] {f.title}: {f.description}")
        if fix:
            lines.append(f"\nActions taken: {len(fix.actions)}")
            for a in fix.actions:
                status = "OK" if a.success else f"FAILED: {a.error}"
                lines.append(f"  {a.title}: {status}")
        return "\n".join(lines)
```

- [ ] **Step 4: Run ModuleBase tests to verify they pass**

Run: `python -m pytest tests/test_module_base.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Write failing tests for the Registry**

Create `tests/test_registry.py`:

```python
import sys
import types
from pathlib import Path
from unittest.mock import patch, MagicMock

from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.registry import filter_by_platform, topological_sort, discover_modules


class ModA(ModuleBase):
    name = "mod_a"
    category = "test"
    platforms = [Platform.DARWIN]
    depends_on = []

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModB(ModuleBase):
    name = "mod_b"
    category = "test"
    platforms = [Platform.DARWIN, Platform.LINUX]
    depends_on = ["mod_a"]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModC(ModuleBase):
    name = "mod_c"
    category = "test"
    platforms = [Platform.WIN32]
    depends_on = []

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_filter_by_platform_darwin():
    modules = [ModA(), ModB(), ModC()]
    result = filter_by_platform(modules, Platform.DARWIN)
    names = [m.name for m in result]
    assert "mod_a" in names
    assert "mod_b" in names
    assert "mod_c" not in names


def test_filter_by_platform_win32():
    modules = [ModA(), ModB(), ModC()]
    result = filter_by_platform(modules, Platform.WIN32)
    names = [m.name for m in result]
    assert names == ["mod_c"]


def test_topological_sort_respects_dependencies():
    modules = [ModB(), ModA()]  # B depends on A, given in wrong order
    sorted_mods = topological_sort(modules)
    names = [m.name for m in sorted_mods]
    assert names.index("mod_a") < names.index("mod_b")


def test_topological_sort_no_dependencies():
    modules = [ModA(), ModC()]
    sorted_mods = topological_sort(modules)
    assert len(sorted_mods) == 2


def test_topological_sort_missing_dependency():
    """Modules with dependencies not in the list still appear in output."""
    sorted_mods = topological_sort([ModB()])
    assert len(sorted_mods) == 1
    assert sorted_mods[0].name == "mod_b"


def test_discover_modules(tmp_path):
    # Create a fake module directory structure
    mod_dir = tmp_path / "modules" / "test_cat" / "fake_mod"
    mod_dir.mkdir(parents=True)
    init_file = mod_dir / "__init__.py"
    init_file.write_text('''
from rescue.module_base import ModuleBase
from rescue.models import Platform, CheckResult, FixResult

class Module(ModuleBase):
    name = "fake_mod"
    category = "test_cat"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)
''')

    modules = discover_modules(tmp_path / "modules")
    assert len(modules) == 1
    assert modules[0].name == "fake_mod"
```

- [ ] **Step 6: Run registry tests to verify they fail**

Run: `python -m pytest tests/test_registry.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.registry'`

- [ ] **Step 7: Implement the Registry**

Create `rescue/registry.py`:

```python
import importlib.util
import sys
from pathlib import Path

from rescue.models import Platform
from rescue.module_base import ModuleBase


def discover_modules(modules_dir: Path) -> list[ModuleBase]:
    modules = []
    if not modules_dir.is_dir():
        return modules

    for category_dir in sorted(modules_dir.iterdir()):
        if not category_dir.is_dir() or category_dir.name.startswith("_"):
            continue
        for module_dir in sorted(category_dir.iterdir()):
            if not module_dir.is_dir() or module_dir.name.startswith("_"):
                continue
            init_file = module_dir / "__init__.py"
            if not init_file.exists():
                continue
            mod = _load_module(init_file, module_dir.name)
            if mod is not None:
                modules.append(mod)
    return modules


def _load_module(init_file: Path, module_name: str) -> ModuleBase | None:
    spec = importlib.util.spec_from_file_location(
        f"rescue_modules.{module_name}", init_file
    )
    if spec is None or spec.loader is None:
        return None
    py_module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = py_module
    spec.loader.exec_module(py_module)
    module_class = getattr(py_module, "Module", None)
    if module_class is None or not (
        isinstance(module_class, type) and issubclass(module_class, ModuleBase)
    ):
        return None
    return module_class()


def filter_by_platform(
    modules: list[ModuleBase], platform: Platform
) -> list[ModuleBase]:
    return [m for m in modules if platform in m.platforms]


def topological_sort(modules: list[ModuleBase]) -> list[ModuleBase]:
    by_name = {m.name: m for m in modules}
    visited: set[str] = set()
    result: list[ModuleBase] = []

    def visit(name: str) -> None:
        if name in visited:
            return
        visited.add(name)
        mod = by_name.get(name)
        if mod is None:
            return
        for dep in mod.depends_on:
            visit(dep)
        result.append(mod)

    for m in modules:
        visit(m.name)
    return result
```

- [ ] **Step 8: Run all tests to verify they pass**

Run: `python -m pytest tests/test_module_base.py tests/test_registry.py -v`
Expected: All 10 tests PASS

- [ ] **Step 9: Commit**

```bash
git add rescue/module_base.py rescue/registry.py tests/test_module_base.py tests/test_registry.py
git commit -m "feat: add module base class and registry with discovery and dependency sorting"
```

---

### Task 4: Orchestrator

**Files:**
- Create: `rescue/orchestrator.py`
- Test: `tests/test_orchestrator.py`

**Interfaces:**
- Consumes:
  - `gather_profile() -> SystemProfile` from `rescue.profiler.base`
  - `discover_modules(modules_dir: Path) -> list[ModuleBase]` from `rescue.registry`
  - `filter_by_platform(modules, platform) -> list[ModuleBase]` from `rescue.registry`
  - `topological_sort(modules) -> list[ModuleBase]` from `rescue.registry`
  - `ModuleBase`, all model dataclasses
- Produces:
  - `Orchestrator` class in `rescue.orchestrator`:
    - `__init__(self, modules_dir: Path)`
    - `run_checks(self) -> list[tuple[ModuleBase, CheckResult]]` — profiles system, discovers modules, runs all checks
    - `run_fixes(self, check_results: list[tuple[ModuleBase, CheckResult]], mode: Mode) -> list[tuple[ModuleBase, CheckResult, FixResult]]` — executes fixes respecting mode and risk_level
    - `run_auto(self) -> list[tuple[ModuleBase, CheckResult, FixResult | None]]` — full auto pipeline

- [ ] **Step 1: Write failing tests for the Orchestrator**

Create `tests/test_orchestrator.py`:

```python
from pathlib import Path
from unittest.mock import patch, MagicMock

from rescue.models import (
    SystemProfile, Platform, CheckResult, FixResult, Finding,
    Action, Severity, RiskLevel, Mode,
)
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator


class SafeModule(ModuleBase):
    name = "safe_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Safe issue",
                    description="Can be auto-fixed",
                    severity=Severity.WARNING,
                    category=self.category,
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Safe fix",
                    description="Applied safe fix",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            ],
        )


class DestructiveModule(ModuleBase):
    name = "destructive_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.DESTRUCTIVE
    depends_on = []

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Destructive issue",
                    description="Needs confirmation",
                    severity=Severity.CRITICAL,
                    category=self.category,
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Destructive fix",
                    description="Deleted something",
                    risk_level=RiskLevel.DESTRUCTIVE,
                    success=True,
                )
            ],
        )


class CleanModule(ModuleBase):
    name = "clean_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return CheckResult(module_name=self.name)  # no findings

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)


FAKE_PROFILE = SystemProfile(
    platform=Platform.DARWIN,
    os_name="macOS",
    os_version="15.2",
    architecture="arm64",
    cpu_model="Apple M2",
    cpu_cores=8,
    ram_bytes=16 * 1024**3,
)


def test_run_checks():
    fake_modules = [SafeModule(), CleanModule()]
    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=fake_modules), \
         patch("rescue.orchestrator.filter_by_platform", return_value=fake_modules), \
         patch("rescue.orchestrator.topological_sort", return_value=fake_modules):
        orch = Orchestrator(modules_dir=Path("/fake"))
        results = orch.run_checks()

    assert len(results) == 2
    mod, check = results[0]
    assert mod.name == "safe_mod"
    assert check.has_issues

    mod, check = results[1]
    assert mod.name == "clean_mod"
    assert not check.has_issues


def test_run_fixes_auto_skips_destructive():
    safe = SafeModule()
    destructive = DestructiveModule()
    check_results = [
        (safe, safe.check(FAKE_PROFILE)),
        (destructive, destructive.check(FAKE_PROFILE)),
    ]

    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.AUTO)

    assert len(results) == 1  # only safe module gets fixed
    mod, check, fix = results[0]
    assert mod.name == "safe_mod"
    assert fix.all_succeeded


def test_run_fixes_cli_runs_all():
    safe = SafeModule()
    destructive = DestructiveModule()
    check_results = [
        (safe, safe.check(FAKE_PROFILE)),
        (destructive, destructive.check(FAKE_PROFILE)),
    ]

    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.CLI)

    assert len(results) == 2


def test_run_fixes_skips_clean_modules():
    clean = CleanModule()
    check_results = [
        (clean, clean.check(FAKE_PROFILE)),
    ]

    orch = Orchestrator.__new__(Orchestrator)
    results = orch.run_fixes(check_results, Mode.AUTO)
    assert len(results) == 0


def test_run_auto():
    fake_modules = [SafeModule(), DestructiveModule(), CleanModule()]
    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=fake_modules), \
         patch("rescue.orchestrator.filter_by_platform", return_value=fake_modules), \
         patch("rescue.orchestrator.topological_sort", return_value=fake_modules):
        orch = Orchestrator(modules_dir=Path("/fake"))
        results = orch.run_auto()

    # 3 modules checked, but only safe_mod gets a fix in auto mode
    assert len(results) == 3
    names_with_fixes = [
        (mod.name, fix is not None) for mod, check, fix in results
    ]
    assert ("safe_mod", True) in names_with_fixes
    assert ("destructive_mod", False) in names_with_fixes
    assert ("clean_mod", False) in names_with_fixes
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_orchestrator.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.orchestrator'`

- [ ] **Step 3: Implement the Orchestrator**

Create `rescue/orchestrator.py`:

```python
from pathlib import Path

from rescue.models import CheckResult, FixResult, Mode, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.registry import discover_modules, filter_by_platform, topological_sort


class Orchestrator:
    def __init__(self, modules_dir: Path):
        self._modules_dir = modules_dir

    def run_checks(self) -> list[tuple[ModuleBase, CheckResult]]:
        profile = gather_profile()
        modules = discover_modules(self._modules_dir)
        modules = filter_by_platform(modules, profile.platform)
        modules = topological_sort(modules)

        results = []
        for mod in modules:
            check = mod.check(profile)
            results.append((mod, check))
        return results

    def run_fixes(
        self,
        check_results: list[tuple[ModuleBase, CheckResult]],
        mode: Mode,
    ) -> list[tuple[ModuleBase, CheckResult, FixResult]]:
        results = []
        for mod, check in check_results:
            if not check.has_issues:
                continue
            if mode == Mode.AUTO and mod.risk_level != RiskLevel.SAFE:
                continue
            fix = mod.fix(check, mode)
            results.append((mod, check, fix))
        return results

    def run_auto(
        self,
    ) -> list[tuple[ModuleBase, CheckResult, FixResult | None]]:
        check_results = self.run_checks()
        fix_results = self.run_fixes(check_results, Mode.AUTO)

        combined = []
        for mod, check in check_results:
            fix = next(
                (f for m, _, f in fix_results if m.name == mod.name), None
            )
            combined.append((mod, check, fix))
        return combined
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_orchestrator.py -v`
Expected: All 5 tests PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/orchestrator.py tests/test_orchestrator.py
git commit -m "feat: add orchestrator for module check/fix pipeline"
```

---

### Task 5: CLI Entry Point

**Files:**
- Create: `rescue/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes:
  - `Orchestrator(modules_dir: Path)` from `rescue.orchestrator`
  - `Orchestrator.run_auto()`, `Orchestrator.run_checks()`, `Orchestrator.run_fixes()`
  - `Mode` from `rescue.models`
  - `__version__` from `rescue`
- Produces:
  - `main()` Click group in `rescue.cli` — the entry point registered as `rescue` in pyproject.toml
  - `rescue --auto` command
  - `rescue run <module_names>... --yes` command
  - `rescue version` command

- [ ] **Step 1: Write failing tests for the CLI**

Create `tests/test_cli.py`:

```python
from pathlib import Path
from unittest.mock import patch, MagicMock

from click.testing import CliRunner

from rescue.cli import main
from rescue.models import (
    CheckResult, FixResult, Finding, Action,
    Severity, RiskLevel, Platform, SystemProfile, Mode,
)
from rescue.module_base import ModuleBase


class FakeMod(ModuleBase):
    name = "fake_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        return CheckResult(
            module_name=self.name,
            findings=[
                Finding(
                    title="Test issue",
                    description="Something wrong",
                    severity=Severity.WARNING,
                    category="test",
                )
            ],
        )

    def fix(self, findings, mode):
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Fixed",
                    description="Fixed it",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            ],
        )


def test_version():
    runner = CliRunner()
    result = runner.invoke(main, ["version"])
    assert result.exit_code == 0
    assert "multiverse-device-rescue" in result.output


def test_auto_mode():
    fake = FakeMod()
    auto_results = [
        (fake, fake.check(None), fake.fix(None, Mode.AUTO)),
    ]

    with patch("rescue.cli.Orchestrator") as MockOrch:
        instance = MockOrch.return_value
        instance.run_auto.return_value = auto_results
        runner = CliRunner()
        result = runner.invoke(main, ["--auto"])

    assert result.exit_code == 0
    assert "Test issue" in result.output
    assert "Fixed" in result.output


def test_run_specific_modules():
    fake = FakeMod()
    profile = SystemProfile(
        platform=Platform.DARWIN, os_name="macOS", os_version="15.2",
        architecture="arm64", cpu_model="M2", cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )

    with patch("rescue.cli.Orchestrator") as MockOrch, \
         patch("rescue.cli.gather_profile", return_value=profile):
        instance = MockOrch.return_value
        instance.run_checks.return_value = [
            (fake, fake.check(None)),
        ]
        instance.run_fixes.return_value = [
            (fake, fake.check(None), fake.fix(None, Mode.CLI)),
        ]
        # Mock discover to return our fake module
        with patch("rescue.cli.discover_modules", return_value=[fake]):
            runner = CliRunner()
            result = runner.invoke(main, ["run", "fake_mod", "--yes"])

    assert result.exit_code == 0


def test_run_unknown_module():
    with patch("rescue.cli.discover_modules", return_value=[]):
        runner = CliRunner()
        result = runner.invoke(main, ["run", "nonexistent"])

    assert result.exit_code != 0 or "not found" in result.output.lower() or "unknown" in result.output.lower()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.cli'`

- [ ] **Step 3: Implement the CLI**

Create `rescue/cli.py`:

```python
from pathlib import Path

import click

import rescue
from rescue.models import Mode, RiskLevel
from rescue.orchestrator import Orchestrator
from rescue.profiler.base import gather_profile
from rescue.registry import discover_modules


def _get_modules_dir() -> Path:
    return Path(__file__).parent.parent / "modules"


@click.group(invoke_without_command=True)
@click.option("--auto", is_flag=True, help="Run all checks and apply safe fixes automatically.")
@click.pass_context
def main(ctx, auto):
    """Multiverse Device Rescue — system diagnostic and repair toolkit."""
    if auto:
        _run_auto()
    elif ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())


@main.command()
def version():
    """Show version information."""
    click.echo(f"multiverse-device-rescue {rescue.__version__}")


@main.command()
@click.argument("module_names", nargs=-1, required=True)
@click.option("--yes", is_flag=True, help="Skip confirmation prompts.")
def run(module_names, yes):
    """Run specific modules by name."""
    modules_dir = _get_modules_dir()
    all_modules = discover_modules(modules_dir)
    by_name = {m.name: m for m in all_modules}

    selected = []
    for name in module_names:
        if name not in by_name:
            click.echo(f"Unknown module: {name}", err=True)
            click.echo(f"Available: {', '.join(sorted(by_name.keys()))}", err=True)
            raise SystemExit(1)
        selected.append(by_name[name])

    profile = gather_profile()

    click.echo(f"System: {profile.os_name} {profile.os_version} | {profile.cpu_model} | {profile.architecture}")
    click.echo(f"Running {len(selected)} module(s)...\n")

    mode = Mode.CLI if yes else Mode.MANUAL

    for mod in selected:
        check = mod.check(profile)
        click.echo(mod.report(check))
        if check.has_issues and (yes or mod.risk_level == RiskLevel.SAFE):
            fix = mod.fix(check, mode)
            click.echo(mod.report(check, fix))
        elif check.has_issues and not yes:
            if click.confirm(f"Apply fixes for {mod.name}?"):
                fix = mod.fix(check, mode)
                click.echo(mod.report(check, fix))
        click.echo()


def _run_auto():
    modules_dir = _get_modules_dir()
    orch = Orchestrator(modules_dir=modules_dir)
    results = orch.run_auto()

    total_issues = sum(len(check.findings) for _, check, _ in results)
    fixed = sum(1 for _, _, fix in results if fix is not None)

    click.echo("=" * 50)
    click.echo("Multiverse Device Rescue — Auto Mode")
    click.echo("=" * 50)
    click.echo(f"\nScanned {len(results)} module(s), found {total_issues} issue(s), applied {fixed} fix(es).\n")

    for mod, check, fix in results:
        if check.has_issues:
            click.echo(mod.report(check, fix))
            click.echo()

    skipped = [
        (mod, check)
        for mod, check, fix in results
        if check.has_issues and fix is None
    ]
    if skipped:
        click.echo("--- Skipped (requires confirmation) ---")
        for mod, check in skipped:
            click.echo(f"  [{mod.risk_level.value}] {mod.name}: {len(check.findings)} issue(s)")
        click.echo("\nRun 'rescue run <module>' to address these individually.")
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/cli.py tests/test_cli.py
git commit -m "feat: add CLI entry point with auto mode and module runner"
```

---

### Task 6: First Real Module — Disk Space Checker

**Files:**
- Create: `modules/__init__.py`
- Create: `modules/performance/__init__.py`
- Create: `modules/performance/disk_space/__init__.py`
- Test: `tests/test_module_disk_space.py`

**Interfaces:**
- Consumes:
  - `ModuleBase` from `rescue.module_base`
  - `SystemProfile`, `CheckResult`, `FixResult`, `Finding`, `Action`, `Severity`, `RiskLevel`, `Mode`, `Platform` from `rescue.models`
- Produces:
  - `Module` class in `modules/performance/disk_space/__init__.py` — a concrete module that checks disk usage and reports findings. Warns at >80% full, critical at >95%. In fix mode, reports common cache directories and their sizes (actual deletion is a separate disk_reclaimer module — this one is diagnostic only, `risk_level=safe`).

- [ ] **Step 1: Create module directory structure**

Create empty `__init__.py` files at `modules/__init__.py` and `modules/performance/__init__.py` (these can be empty — they exist so the directory is a valid Python package tree, but module discovery uses `importlib.util` directly).

- [ ] **Step 2: Write failing tests for the disk_space module**

Create `tests/test_module_disk_space.py`:

```python
import sys
from pathlib import Path

# Add project root so modules/ is importable via discover_modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile, Platform, DiskInfo, CheckResult,
    Severity, RiskLevel, Mode,
)
from rescue.registry import discover_modules


def _make_profile(disk_used_pct: float) -> SystemProfile:
    total = 500 * 1024**3  # 500 GB
    used = int(total * disk_used_pct)
    free = total - used
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        disks=[
            DiskInfo(
                device="/dev/disk1s1",
                mount_point="/",
                total_bytes=total,
                used_bytes=used,
                free_bytes=free,
                filesystem="apfs",
            )
        ],
    )


def test_disk_space_module_discovered():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    names = [m.name for m in modules]
    assert "disk_space" in names


def test_disk_space_healthy():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.50)  # 50% full
    result = mod.check(profile)
    assert not result.has_issues


def test_disk_space_warning():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.85)  # 85% full
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING


def test_disk_space_critical():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.97)  # 97% full
    result = mod.check(profile)
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL


def test_disk_space_fix_is_informational():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    assert mod.risk_level == RiskLevel.SAFE

    profile = _make_profile(0.85)
    check = mod.check(profile)
    fix = mod.fix(check, Mode.AUTO)
    assert fix.all_succeeded  # informational fix always succeeds


def test_disk_space_report():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    mod = next(m for m in modules if m.name == "disk_space")

    profile = _make_profile(0.85)
    check = mod.check(profile)
    report = mod.report(check)
    assert "disk_space" in report
    assert "85" in report or "warning" in report.lower()
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_disk_space.py -v`
Expected: FAIL — module "disk_space" not found in discovered modules

- [ ] **Step 4: Implement the disk_space module**

Create `modules/performance/disk_space/__init__.py`:

```python
from rescue.models import (
    Action,
    CheckResult,
    DiskInfo,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase

WARNING_THRESHOLD = 0.80
CRITICAL_THRESHOLD = 0.95


class Module(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN, Platform.WIN32, Platform.LINUX]
    risk_level = RiskLevel.SAFE
    priority = 80
    depends_on = []
    estimated_duration = "5s"

    def check(self, profile: SystemProfile) -> CheckResult:
        findings = []
        for disk in profile.disks:
            if disk.total_bytes == 0:
                continue
            used_pct = disk.used_bytes / disk.total_bytes
            if used_pct >= CRITICAL_THRESHOLD:
                findings.append(self._make_finding(disk, used_pct, Severity.CRITICAL))
            elif used_pct >= WARNING_THRESHOLD:
                findings.append(self._make_finding(disk, used_pct, Severity.WARNING))
        return CheckResult(module_name=self.name, findings=findings)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        actions = []
        for finding in findings.findings:
            actions.append(
                Action(
                    title=f"Disk space report for {finding.data.get('mount_point', 'unknown')}",
                    description=(
                        f"Disk is {finding.data.get('used_pct_str', '?')} full. "
                        f"Free: {_fmt_bytes(finding.data.get('free_bytes', 0))}. "
                        f"Consider running the disk_reclaimer module to free space."
                    ),
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            )
        return FixResult(module_name=self.name, actions=actions)

    def _make_finding(
        self, disk: DiskInfo, used_pct: float, severity: Severity
    ) -> Finding:
        return Finding(
            title=f"Disk {disk.mount_point} is {used_pct:.0%} full",
            description=(
                f"{disk.device} mounted at {disk.mount_point}: "
                f"{_fmt_bytes(disk.used_bytes)} used of {_fmt_bytes(disk.total_bytes)} "
                f"({_fmt_bytes(disk.free_bytes)} free)"
            ),
            severity=severity,
            category=self.category,
            data={
                "mount_point": disk.mount_point,
                "device": disk.device,
                "used_pct": used_pct,
                "used_pct_str": f"{used_pct:.0%}",
                "free_bytes": disk.free_bytes,
                "total_bytes": disk.total_bytes,
            },
        )


def _fmt_bytes(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if abs(n) < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} PB"
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_disk_space.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Run the full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS (models + profiler + module_base + registry + orchestrator + cli + disk_space)

- [ ] **Step 7: Smoke test the CLI end-to-end**

Run:
```bash
python -m rescue.cli --auto
```

Expected: The tool profiles the system, discovers the disk_space module, checks disk usage, and reports findings. If your disk is under 80% full, it reports "Scanned 1 module(s), found 0 issue(s)". If over 80%, it reports the warning and the informational fix.

- [ ] **Step 8: Commit**

```bash
git add modules/ tests/test_module_disk_space.py
git commit -m "feat: add disk_space module — first working module for the framework"
```

---

## Future Plans

These are separate implementation plans to be written after this core framework is working:

- **Plan 2: Interactive TUI** — Textual-based app with category menus, progress bars, findings display, guide rendering
- **Plan 3: Profile System & Guide Engine** — YAML threat-model profiles, markdown guide parser with frontmatter, walkthrough rendering, session progress persistence
- **Plan 4: Secure Update System** — Signed bundle format, threshold signing verification, checksum validation, TLS cert pinning, air-gapped sideloading, `rescue update` command
- **Plan 5: AI Layer** — Optional diagnostic explainer, profile recommender, walkthrough copilot with Anthropic/OpenAI/Ollama backends
- **Plan 6+: Module Packs** — Bloatware cleanup modules, performance modules (disk_reclaimer, resource_hog, startup_optimizer), system integrity modules, security hardening modules, privacy modules
