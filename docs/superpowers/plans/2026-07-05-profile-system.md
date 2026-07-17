# Profile System & Guide Engine Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Add threat-model profile configuration (YAML) and a markdown-with-frontmatter guide engine, wire both into the Orchestrator and CLI, and persist walkthrough progress across sessions — shipping with two fully-populated starter profiles (`digital_security_reset` and `home_for_the_holidays`).

**Architecture:** Profiles (`rescue/profiles.py`) load YAML configs that select/filter modules and attach per-module config dicts. The Guide Engine (`rescue/guides.py`) parses markdown-with-frontmatter into structured `Guide`/`GuideStep` objects, distinguishing automatable steps from human-only ones. The `Orchestrator` (from Plan 1) gains an optional `profile` parameter that filters discovered modules and calls a new `ModuleBase.configure()` hook. A `SessionStore` persists per-profile, per-phase completion state as JSON so the CLI's `guide` command can resume a walkthrough exactly where the user left off.

**Tech Stack:** Python 3.11+, PyYAML, python-frontmatter, Click, pytest — building directly on the Plan 1 core framework (`rescue.models`, `rescue.module_base`, `rescue.orchestrator`, `rescue.registry`, `rescue.cli`).

## Global Constraints

- Python 3.11+ required, matching the core framework.
- PyYAML parses profile YAML; python-frontmatter parses guide markdown frontmatter — both are added as core (non-dev) dependencies in `pyproject.toml`.
- Profile integration is additive: `Orchestrator(modules_dir, profile=None)` (the default) behaves identically to the Plan 1 orchestrator — existing Plan 1 tests (`tests/test_orchestrator.py`, `tests/test_cli.py`, etc.) must keep passing unmodified.
- Guide markdown step headers must use the exact `## Step N: Title` format — the parser locates steps with a regex tied to that convention.
- `ModuleBase.configure(config: dict) -> None` defaults to a no-op; a module only overrides it when it needs profile-driven settings (e.g. sensitivity level).
- Session state is one JSON file per profile, under a session directory, tracking which step numbers are complete per phase and which phase is "current."
- Profile YAML schema: top-level `name`, `display_name`, `description`, `modules.include`, `modules.exclude`, `module_config`, `guides`.
- Every task is independently testable via `python -m pytest tests/<file> -v`.

---

### Task 1: Profile Loader

**Files:**
- Modify: `pyproject.toml`
- Create: `rescue/profiles.py`
- Test: `tests/test_profiles.py`

**Interfaces:**
- Consumes: `ModuleBase` from `rescue.module_base`
- Produces:
  - `Profile` dataclass: `name: str, display_name: str, description: str, include_modules: list[str], exclude_modules: list[str], module_config: dict[str, dict[str, Any]], guides: list[str]`
  - `load_profile(path: Path) -> Profile` in `rescue.profiles`
  - `discover_profiles(profiles_dir: Path) -> dict[str, Profile]` in `rescue.profiles` — keyed by `Profile.name`
  - `filter_modules_by_profile(modules: list[ModuleBase], profile: Profile) -> list[ModuleBase]` in `rescue.profiles`

- [ ] **Step 1: Add PyYAML dependency**

Update `pyproject.toml`:

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
    "pyyaml>=6.0",
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

- [ ] **Step 2: Write failing tests for the profile loader**

Create `tests/test_profiles.py`:

```python
from pathlib import Path

from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiles import Profile, discover_profiles, filter_modules_by_profile, load_profile


PROFILE_YAML = """
name: test_profile
display_name: "Test Profile"
description: "A profile for testing."
modules:
  include:
    - mod_a
    - mod_b
  exclude:
    - mod_c
module_config:
  mod_a:
    sensitivity: elevated
guides:
  - test_profile
"""


def test_load_profile(tmp_path):
    profile_path = tmp_path / "test_profile.yaml"
    profile_path.write_text(PROFILE_YAML)

    profile = load_profile(profile_path)

    assert profile.name == "test_profile"
    assert profile.display_name == "Test Profile"
    assert profile.description == "A profile for testing."
    assert profile.include_modules == ["mod_a", "mod_b"]
    assert profile.exclude_modules == ["mod_c"]
    assert profile.module_config == {"mod_a": {"sensitivity": "elevated"}}
    assert profile.guides == ["test_profile"]


def test_load_profile_minimal(tmp_path):
    minimal_yaml = "name: minimal\n"
    profile_path = tmp_path / "minimal.yaml"
    profile_path.write_text(minimal_yaml)

    profile = load_profile(profile_path)

    assert profile.name == "minimal"
    assert profile.display_name == "minimal"
    assert profile.description == ""
    assert profile.include_modules == []
    assert profile.exclude_modules == []
    assert profile.module_config == {}
    assert profile.guides == []


def test_discover_profiles(tmp_path):
    (tmp_path / "a.yaml").write_text("name: profile_a\n")
    (tmp_path / "b.yaml").write_text("name: profile_b\n")
    (tmp_path / "not_a_profile.txt").write_text("ignore me")

    profiles = discover_profiles(tmp_path)

    assert set(profiles.keys()) == {"profile_a", "profile_b"}
    assert profiles["profile_a"].name == "profile_a"


def test_discover_profiles_missing_dir(tmp_path):
    missing = tmp_path / "does_not_exist"
    assert discover_profiles(missing) == {}


class ModA(ModuleBase):
    name = "mod_a"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModB(ModuleBase):
    name = "mod_b"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModC(ModuleBase):
    name = "mod_c"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_filter_modules_by_profile_include_and_exclude():
    profile = Profile(
        name="test_profile",
        display_name="Test Profile",
        description="",
        include_modules=["mod_a", "mod_b", "mod_c"],
        exclude_modules=["mod_c"],
    )
    modules = [ModA(), ModB(), ModC()]

    result = filter_modules_by_profile(modules, profile)

    names = [m.name for m in result]
    assert names == ["mod_a", "mod_b"]


def test_filter_modules_by_profile_no_include_list_keeps_all():
    profile = Profile(name="test_profile", display_name="Test Profile", description="")
    modules = [ModA(), ModB(), ModC()]

    result = filter_modules_by_profile(modules, profile)

    assert len(result) == 3
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_profiles.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.profiles'`

- [ ] **Step 4: Implement the profile loader**

Create `rescue/profiles.py`:

```python
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rescue.module_base import ModuleBase


@dataclass
class Profile:
    name: str
    display_name: str
    description: str
    include_modules: list[str] = field(default_factory=list)
    exclude_modules: list[str] = field(default_factory=list)
    module_config: dict[str, dict[str, Any]] = field(default_factory=dict)
    guides: list[str] = field(default_factory=list)


def load_profile(path: Path) -> Profile:
    with open(path, "r") as f:
        data = yaml.safe_load(f) or {}

    modules_section = data.get("modules", {}) or {}

    return Profile(
        name=data["name"],
        display_name=data.get("display_name", data["name"]),
        description=(data.get("description") or "").strip(),
        include_modules=modules_section.get("include", []) or [],
        exclude_modules=modules_section.get("exclude", []) or [],
        module_config=data.get("module_config", {}) or {},
        guides=data.get("guides", []) or [],
    )


def discover_profiles(profiles_dir: Path) -> dict[str, Profile]:
    profiles: dict[str, Profile] = {}
    if not profiles_dir.is_dir():
        return profiles

    for path in sorted(profiles_dir.glob("*.yaml")):
        profile = load_profile(path)
        profiles[profile.name] = profile
    return profiles


def filter_modules_by_profile(
    modules: list[ModuleBase], profile: Profile
) -> list[ModuleBase]:
    result = modules
    if profile.include_modules:
        result = [m for m in result if m.name in profile.include_modules]
    if profile.exclude_modules:
        result = [m for m in result if m.name not in profile.exclude_modules]
    return result
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_profiles.py -v`
Expected: All 6 tests PASS

- [ ] **Step 6: Reinstall project to pick up the new dependency and commit**

Run:
```bash
pip install -e ".[dev]" 2>/dev/null || pip install -e .
git add pyproject.toml rescue/profiles.py tests/test_profiles.py
git commit -m "feat: add YAML threat-model profile loader"
```

---

### Task 2: Guide Engine

**Files:**
- Modify: `pyproject.toml`
- Create: `rescue/guides.py`
- Test: `tests/test_guides.py`

**Interfaces:**
- Consumes: nothing from prior tasks (uses `python-frontmatter` and stdlib only)
- Produces:
  - `GuideStep` dataclass: `number: int, title: str, body: str, automatable: bool`
  - `Guide` dataclass: `profile: str, phase: int, title: str, estimated_time: str, steps: list[GuideStep], automatable_steps: list[int], human_only_steps: list[int]`
  - `parse_guide_markdown(text: str) -> Guide` in `rescue.guides`
  - `load_guide(path: Path) -> Guide` in `rescue.guides`
  - `discover_guides(guides_dir: Path, profile_name: str) -> list[Guide]` in `rescue.guides` — sorted by `phase` ascending

- [ ] **Step 1: Add python-frontmatter dependency**

Update `pyproject.toml`:

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
    "pyyaml>=6.0",
    "python-frontmatter>=1.0",
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

- [ ] **Step 2: Write failing tests for the guide engine**

Create `tests/test_guides.py`:

```python
from pathlib import Path

from rescue.guides import Guide, GuideStep, discover_guides, load_guide, parse_guide_markdown


SAMPLE_GUIDE = """---
profile: digital_security_reset
phase: 3
title: "Systematic Cleanup"
automatable_steps: [1, 2, 5]
human_only_steps: [3, 4, 6]
estimated_time: "45 minutes"
---

## Step 1: Reset your primary email password

Use a long, unique passphrase and store it in your password manager.

## Step 2: Reset passwords for your top 5 accounts

Banking, primary social, cloud storage, and work accounts first.

## Step 3: Clean up saved browser passwords

Remove anything tied to accounts you no longer use.

## Step 4: Contact your bank

Flag potential compromise with your financial institutions.

## Step 5: Run the 2FA audit

Enable two-factor authentication wherever it's missing.

## Step 6: Write down your progress

Keep a paper list of every account you've secured so far.
"""


def test_parse_guide_markdown_frontmatter():
    guide = parse_guide_markdown(SAMPLE_GUIDE)

    assert guide.profile == "digital_security_reset"
    assert guide.phase == 3
    assert guide.title == "Systematic Cleanup"
    assert guide.estimated_time == "45 minutes"
    assert guide.automatable_steps == [1, 2, 5]
    assert guide.human_only_steps == [3, 4, 6]


def test_parse_guide_markdown_steps():
    guide = parse_guide_markdown(SAMPLE_GUIDE)

    assert len(guide.steps) == 6
    assert guide.steps[0].number == 1
    assert guide.steps[0].title == "Reset your primary email password"
    assert "passphrase" in guide.steps[0].body
    assert guide.steps[0].automatable is True

    assert guide.steps[2].number == 3
    assert guide.steps[2].automatable is False


def test_load_guide(tmp_path):
    guide_path = tmp_path / "phase_3.md"
    guide_path.write_text(SAMPLE_GUIDE)

    guide = load_guide(guide_path)

    assert guide.phase == 3
    assert len(guide.steps) == 6


def test_discover_guides_sorted_by_phase(tmp_path):
    profile_dir = tmp_path / "digital_security_reset"
    profile_dir.mkdir()

    phase_1 = SAMPLE_GUIDE.replace("phase: 3", "phase: 1").replace(
        '"Systematic Cleanup"', '"Reality Check"'
    )
    phase_0 = SAMPLE_GUIDE.replace("phase: 3", "phase: 0").replace(
        '"Systematic Cleanup"', '"Emergency Grounding"'
    )

    # Written in reverse order on disk to prove sorting is by phase, not filename
    (profile_dir / "z_phase_3.md").write_text(SAMPLE_GUIDE)
    (profile_dir / "a_phase_1.md").write_text(phase_1)
    (profile_dir / "m_phase_0.md").write_text(phase_0)

    guides = discover_guides(tmp_path, "digital_security_reset")

    assert [g.phase for g in guides] == [0, 1, 3]
    assert guides[0].title == "Emergency Grounding"


def test_discover_guides_missing_profile_dir(tmp_path):
    guides = discover_guides(tmp_path, "nonexistent_profile")
    assert guides == []
```

- [ ] **Step 3: Run tests to verify they fail**

Run: `python -m pytest tests/test_guides.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.guides'`

- [ ] **Step 4: Implement the guide engine**

Create `rescue/guides.py`:

```python
import re
from dataclasses import dataclass, field
from pathlib import Path

import frontmatter

_STEP_PATTERN = re.compile(r"^## Step (\d+): (.+)$", re.MULTILINE)


@dataclass
class GuideStep:
    number: int
    title: str
    body: str
    automatable: bool


@dataclass
class Guide:
    profile: str
    phase: int
    title: str
    estimated_time: str
    steps: list[GuideStep] = field(default_factory=list)
    automatable_steps: list[int] = field(default_factory=list)
    human_only_steps: list[int] = field(default_factory=list)


def parse_guide_markdown(text: str) -> Guide:
    post = frontmatter.loads(text)
    meta = post.metadata

    automatable_steps = list(meta.get("automatable_steps", []))
    human_only_steps = list(meta.get("human_only_steps", []))

    steps = [
        GuideStep(
            number=number,
            title=title,
            body=body,
            automatable=number in automatable_steps,
        )
        for number, title, body in _split_steps(post.content)
    ]

    return Guide(
        profile=meta["profile"],
        phase=meta["phase"],
        title=meta.get("title", ""),
        estimated_time=meta.get("estimated_time", ""),
        steps=steps,
        automatable_steps=automatable_steps,
        human_only_steps=human_only_steps,
    )


def load_guide(path: Path) -> Guide:
    return parse_guide_markdown(path.read_text())


def discover_guides(guides_dir: Path, profile_name: str) -> list[Guide]:
    profile_dir = guides_dir / profile_name
    if not profile_dir.is_dir():
        return []

    guides = [load_guide(path) for path in sorted(profile_dir.glob("*.md"))]
    guides.sort(key=lambda g: g.phase)
    return guides


def _split_steps(body: str) -> list[tuple[int, str, str]]:
    matches = list(_STEP_PATTERN.finditer(body))
    steps = []
    for i, match in enumerate(matches):
        number = int(match.group(1))
        title = match.group(2).strip()
        start = match.end()
        end = matches[i + 1].start() if i + 1 < len(matches) else len(body)
        steps.append((number, title, body[start:end].strip()))
    return steps
```

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_guides.py -v`
Expected: All 5 tests PASS

- [ ] **Step 6: Reinstall project to pick up the new dependency and commit**

Run:
```bash
pip install -e ".[dev]" 2>/dev/null || pip install -e .
git add pyproject.toml rescue/guides.py tests/test_guides.py
git commit -m "feat: add markdown-with-frontmatter guide engine"
```

---

### Task 3: Session Persistence

**Files:**
- Create: `rescue/session.py`
- Test: `tests/test_session.py`

**Interfaces:**
- Consumes: `Guide` from `rescue.guides` (type hint only, imported under `TYPE_CHECKING` to avoid a hard runtime dependency)
- Produces:
  - `SessionState` dataclass: `profile: str, completed_steps: dict[int, list[int]], current_phase: int = 0`
  - `SessionStore` class in `rescue.session`:
    - `__init__(self, session_dir: Path)` — creates `session_dir` if missing
    - `load(self, profile_name: str) -> SessionState`
    - `save(self, state: SessionState) -> None`
    - `mark_step_complete(self, profile_name: str, phase: int, step: int) -> SessionState`
    - `is_phase_complete(self, state: SessionState, phase: int, guide: Guide) -> bool`
    - `advance_phase(self, profile_name: str, next_phase: int) -> SessionState`

- [ ] **Step 1: Write failing tests for session persistence**

Create `tests/test_session.py`:

```python
from rescue.guides import Guide, GuideStep
from rescue.session import SessionState, SessionStore


def _make_guide(phase: int, step_numbers: list[int]) -> Guide:
    return Guide(
        profile="test_profile",
        phase=phase,
        title="Test Phase",
        estimated_time="10 minutes",
        steps=[
            GuideStep(number=n, title=f"Step {n}", body="", automatable=False)
            for n in step_numbers
        ],
        automatable_steps=[],
        human_only_steps=step_numbers,
    )


def test_load_returns_fresh_state_when_no_file(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    state = store.load("new_profile")

    assert state.profile == "new_profile"
    assert state.completed_steps == {}
    assert state.current_phase == 0


def test_save_and_load_round_trip(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    state = SessionState(profile="test_profile", completed_steps={1: [1, 2]}, current_phase=1)

    store.save(state)
    loaded = store.load("test_profile")

    assert loaded.profile == "test_profile"
    assert loaded.completed_steps == {1: [1, 2]}
    assert loaded.current_phase == 1


def test_mark_step_complete_creates_and_updates(tmp_path):
    store = SessionStore(session_dir=tmp_path)

    store.mark_step_complete("test_profile", phase=2, step=1)
    state = store.mark_step_complete("test_profile", phase=2, step=3)

    assert state.completed_steps[2] == [1, 3]


def test_mark_step_complete_is_idempotent(tmp_path):
    store = SessionStore(session_dir=tmp_path)

    store.mark_step_complete("test_profile", phase=1, step=5)
    state = store.mark_step_complete("test_profile", phase=1, step=5)

    assert state.completed_steps[1] == [5]


def test_is_phase_complete_true_when_all_steps_done(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    guide = _make_guide(phase=1, step_numbers=[1, 2, 3])

    store.mark_step_complete("test_profile", phase=1, step=1)
    store.mark_step_complete("test_profile", phase=1, step=2)
    state = store.mark_step_complete("test_profile", phase=1, step=3)

    assert store.is_phase_complete(state, phase=1, guide=guide) is True


def test_is_phase_complete_false_when_steps_missing(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    guide = _make_guide(phase=1, step_numbers=[1, 2, 3])

    state = store.mark_step_complete("test_profile", phase=1, step=1)

    assert store.is_phase_complete(state, phase=1, guide=guide) is False


def test_advance_phase_updates_current_phase(tmp_path):
    store = SessionStore(session_dir=tmp_path)
    store.mark_step_complete("test_profile", phase=0, step=1)

    state = store.advance_phase("test_profile", next_phase=1)

    assert state.current_phase == 1
    # advancing preserves prior completed step history
    assert state.completed_steps[0] == [1]


def test_session_dir_created_if_missing(tmp_path):
    session_dir = tmp_path / "nested" / "sessions"
    assert not session_dir.exists()

    SessionStore(session_dir=session_dir)

    assert session_dir.exists()
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_session.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.session'`

- [ ] **Step 3: Implement session persistence**

Create `rescue/session.py`:

```python
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from rescue.guides import Guide


@dataclass
class SessionState:
    profile: str
    completed_steps: dict[int, list[int]] = field(default_factory=dict)
    current_phase: int = 0

    def to_dict(self) -> dict:
        return {
            "profile": self.profile,
            "completed_steps": {
                str(phase): steps for phase, steps in self.completed_steps.items()
            },
            "current_phase": self.current_phase,
        }

    @classmethod
    def from_dict(cls, data: dict) -> "SessionState":
        return cls(
            profile=data["profile"],
            completed_steps={
                int(phase): steps
                for phase, steps in data.get("completed_steps", {}).items()
            },
            current_phase=data.get("current_phase", 0),
        )


class SessionStore:
    def __init__(self, session_dir: Path):
        self._session_dir = session_dir
        self._session_dir.mkdir(parents=True, exist_ok=True)

    def load(self, profile_name: str) -> SessionState:
        path = self._path(profile_name)
        if not path.exists():
            return SessionState(profile=profile_name)
        with open(path, "r") as f:
            data = json.load(f)
        return SessionState.from_dict(data)

    def save(self, state: SessionState) -> None:
        path = self._path(state.profile)
        with open(path, "w") as f:
            json.dump(state.to_dict(), f, indent=2)

    def mark_step_complete(self, profile_name: str, phase: int, step: int) -> SessionState:
        state = self.load(profile_name)
        done = state.completed_steps.setdefault(phase, [])
        if step not in done:
            done.append(step)
            done.sort()
        self.save(state)
        return state

    def is_phase_complete(self, state: SessionState, phase: int, guide: "Guide") -> bool:
        step_numbers = {s.number for s in guide.steps}
        done = set(state.completed_steps.get(phase, []))
        return step_numbers.issubset(done)

    def advance_phase(self, profile_name: str, next_phase: int) -> SessionState:
        state = self.load(profile_name)
        state.current_phase = next_phase
        self.save(state)
        return state

    def _path(self, profile_name: str) -> Path:
        return self._session_dir / f"{profile_name}.json"
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_session.py -v`
Expected: All 8 tests PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/session.py tests/test_session.py
git commit -m "feat: add session persistence for guide walkthrough progress"
```

---

### Task 4: Profile Integration into the Orchestrator

**Files:**
- Modify: `rescue/module_base.py`
- Modify: `rescue/orchestrator.py`
- Test: `tests/test_module_configure.py`
- Test: `tests/test_orchestrator_profile.py`

**Interfaces:**
- Consumes: `Profile`, `filter_modules_by_profile` from `rescue.profiles`
- Produces:
  - `ModuleBase.configure(self, config: dict[str, Any]) -> None` — default no-op, in `rescue.module_base`
  - `Orchestrator.__init__(self, modules_dir: Path, profile: Profile | None = None)` — new optional `profile` parameter
  - `Orchestrator.run_checks()` now filters modules through `filter_modules_by_profile` and calls `mod.configure(profile.module_config.get(mod.name, {}))` for each surviving module, but only when `profile is not None`

- [ ] **Step 1: Write failing tests for `ModuleBase.configure`**

Create `tests/test_module_configure.py`:

```python
from rescue.models import Platform, RiskLevel
from rescue.module_base import ModuleBase


class ConfigurableModule(ModuleBase):
    name = "configurable_mod"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def __init__(self):
        self.sensitivity = "normal"

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass

    def configure(self, config):
        self.sensitivity = config.get("sensitivity", self.sensitivity)


class PlainModule(ModuleBase):
    name = "plain_mod"
    category = "test"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_configure_default_is_noop():
    mod = PlainModule()
    mod.configure({"anything": "goes"})  # must not raise


def test_configure_overridden_updates_state():
    mod = ConfigurableModule()
    assert mod.sensitivity == "normal"

    mod.configure({"sensitivity": "elevated"})

    assert mod.sensitivity == "elevated"
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_module_configure.py -v`
Expected: FAIL — `AttributeError: 'PlainModule' object has no attribute 'configure'`

- [ ] **Step 3: Add `configure` to `ModuleBase`**

Update `rescue/module_base.py`:

```python
from abc import ABC, abstractmethod
from typing import Any

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

    def configure(self, config: dict[str, Any]) -> None:
        """Apply profile-driven configuration to this module. Default: no-op.

        Modules that care about profile settings (e.g. sensitivity level)
        override this to react to the `module_config` entry a profile YAML
        defines for them.
        """
        pass

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

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_module_configure.py -v`
Expected: All 2 tests PASS

- [ ] **Step 5: Run the full Plan 1 suite to confirm no regressions**

Run: `python -m pytest tests/test_module_base.py tests/test_registry.py tests/test_orchestrator.py tests/test_cli.py tests/test_module_disk_space.py -v`
Expected: All PASS — `configure` is additive and doesn't change existing behavior.

- [ ] **Step 6: Write failing tests for profile-aware orchestration**

Create `tests/test_orchestrator_profile.py`:

```python
from pathlib import Path
from unittest.mock import patch

from rescue.models import Platform, CheckResult, FixResult, RiskLevel, SystemProfile
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator
from rescue.profiles import Profile


class ModA(ModuleBase):
    name = "mod_a"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def __init__(self):
        self.configured_with = None

    def check(self, profile):
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        return FixResult(module_name=self.name)

    def configure(self, config):
        self.configured_with = config


class ModB(ModuleBase):
    name = "mod_b"
    category = "test"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE
    depends_on = []

    def check(self, profile):
        return CheckResult(module_name=self.name)

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


def test_run_checks_without_profile_runs_all_modules_and_skips_configure():
    mod_a, mod_b = ModA(), ModB()
    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.filter_by_platform", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.topological_sort", side_effect=lambda mods: mods):
        orch = Orchestrator(modules_dir=Path("/fake"))
        results = orch.run_checks()

    assert len(results) == 2
    assert mod_a.configured_with is None  # no profile means configure never called


def test_run_checks_with_profile_filters_and_configures():
    mod_a, mod_b = ModA(), ModB()
    profile = Profile(
        name="test_profile",
        display_name="Test Profile",
        description="",
        include_modules=["mod_a"],
        module_config={"mod_a": {"sensitivity": "elevated"}},
    )

    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.filter_by_platform", return_value=[mod_a, mod_b]), \
         patch("rescue.orchestrator.topological_sort", side_effect=lambda mods: mods):
        orch = Orchestrator(modules_dir=Path("/fake"), profile=profile)
        results = orch.run_checks()

    names = [mod.name for mod, _ in results]
    assert names == ["mod_a"]
    assert mod_a.configured_with == {"sensitivity": "elevated"}


def test_run_checks_with_profile_no_config_for_module_gets_empty_dict():
    mod_a = ModA()
    profile = Profile(
        name="test_profile",
        display_name="Test Profile",
        description="",
        include_modules=["mod_a"],
    )

    with patch("rescue.orchestrator.gather_profile", return_value=FAKE_PROFILE), \
         patch("rescue.orchestrator.discover_modules", return_value=[mod_a]), \
         patch("rescue.orchestrator.filter_by_platform", return_value=[mod_a]), \
         patch("rescue.orchestrator.topological_sort", side_effect=lambda mods: mods):
        orch = Orchestrator(modules_dir=Path("/fake"), profile=profile)
        orch.run_checks()

    assert mod_a.configured_with == {}
```

- [ ] **Step 7: Run tests to verify they fail**

Run: `python -m pytest tests/test_orchestrator_profile.py -v`
Expected: FAIL — `TypeError: Orchestrator.__init__() got an unexpected keyword argument 'profile'`

- [ ] **Step 8: Wire `Profile` into the Orchestrator**

Update `rescue/orchestrator.py`:

```python
from pathlib import Path

from rescue.models import CheckResult, FixResult, Mode, RiskLevel
from rescue.module_base import ModuleBase
from rescue.profiler.base import gather_profile
from rescue.profiles import Profile, filter_modules_by_profile
from rescue.registry import discover_modules, filter_by_platform, topological_sort


class Orchestrator:
    def __init__(self, modules_dir: Path, profile: Profile | None = None):
        self._modules_dir = modules_dir
        self._profile = profile

    def run_checks(self) -> list[tuple[ModuleBase, CheckResult]]:
        profile = gather_profile()
        modules = discover_modules(self._modules_dir)
        modules = filter_by_platform(modules, profile.platform)

        if self._profile is not None:
            modules = filter_modules_by_profile(modules, self._profile)
            for mod in modules:
                mod.configure(self._profile.module_config.get(mod.name, {}))

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

- [ ] **Step 9: Run tests to verify they pass**

Run: `python -m pytest tests/test_orchestrator_profile.py -v`
Expected: All 3 tests PASS

- [ ] **Step 10: Run the full Plan 1 orchestrator suite again to confirm no regressions**

Run: `python -m pytest tests/test_orchestrator.py -v`
Expected: All 5 tests PASS unmodified (the new `profile` parameter defaults to `None`)

- [ ] **Step 11: Commit**

```bash
git add rescue/module_base.py rescue/orchestrator.py tests/test_module_configure.py tests/test_orchestrator_profile.py
git commit -m "feat: wire threat-model profiles into the orchestrator via configure() and module filtering"
```

---

### Task 5: CLI Integration — `--profile`, `profiles`, and `guide` Commands

**Files:**
- Modify: `rescue/cli.py`
- Test: `tests/test_cli_guide.py`

**Interfaces:**
- Consumes:
  - `discover_profiles(profiles_dir: Path) -> dict[str, Profile]` from `rescue.profiles`
  - `discover_guides(guides_dir: Path, profile_name: str) -> list[Guide]` from `rescue.guides`
  - `SessionStore(session_dir: Path)` from `rescue.session`
  - `Orchestrator(modules_dir: Path, profile: Profile | None)` from `rescue.orchestrator`
- Produces:
  - `rescue --auto --profile <name>` — filters/configures modules per profile before running
  - `rescue profiles` command — lists discovered profiles
  - `rescue guide <profile_name> [--complete <step>]` command — renders the current phase's steps (tagged automatable/human, done/pending) and resumes from saved session state

- [ ] **Step 1: Write failing tests for the new CLI surface**

Create `tests/test_cli_guide.py`:

```python
from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.guides import Guide, GuideStep
from rescue.profiles import Profile


FAKE_PROFILE = Profile(
    name="test_profile",
    display_name="Test Profile",
    description="A profile for testing guides.",
    guides=["test_profile"],
)

FAKE_GUIDE = Guide(
    profile="test_profile",
    phase=0,
    title="Getting Started",
    estimated_time="10 minutes",
    steps=[
        GuideStep(number=1, title="Automated check", body="...", automatable=True),
        GuideStep(number=2, title="Manual review", body="...", automatable=False),
    ],
    automatable_steps=[1],
    human_only_steps=[2],
)

# Regression fixture: a guide set whose only phase is numbered 1, not 0.
# A fresh SessionState always starts at current_phase=0, so the CLI must
# detect that 0 doesn't match any authored phase and jump to phase 1
# *before* recording any --complete step against the (wrong) phase 0.
FAKE_GUIDE_PHASE_1 = Guide(
    profile="test_profile",
    phase=1,
    title="Only Phase",
    estimated_time="5 minutes",
    steps=[
        GuideStep(number=1, title="First step", body="...", automatable=False),
        GuideStep(number=2, title="Second step", body="...", automatable=False),
    ],
    automatable_steps=[],
    human_only_steps=[1, 2],
)


def test_profiles_command_lists_profiles():
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}):
        runner = CliRunner()
        result = runner.invoke(main, ["profiles"])

    assert result.exit_code == 0
    assert "test_profile" in result.output
    assert "Test Profile" in result.output


def test_guide_command_unknown_profile():
    with patch("rescue.cli.discover_profiles", return_value={}):
        runner = CliRunner()
        result = runner.invoke(main, ["guide", "nonexistent"])

    assert result.exit_code != 0


def test_guide_command_renders_steps(tmp_path):
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.discover_guides", return_value=[FAKE_GUIDE]), \
         patch("rescue.cli._get_session_dir", return_value=tmp_path):
        runner = CliRunner()
        result = runner.invoke(main, ["guide", "test_profile"])

    assert result.exit_code == 0
    assert "Getting Started" in result.output
    assert "[automatable] [pending] Step 1" in result.output
    assert "[human] [pending] Step 2" in result.output


def test_guide_command_mark_step_complete_persists(tmp_path):
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.discover_guides", return_value=[FAKE_GUIDE]), \
         patch("rescue.cli._get_session_dir", return_value=tmp_path):
        runner = CliRunner()
        runner.invoke(main, ["guide", "test_profile", "--complete", "2"])
        result = runner.invoke(main, ["guide", "test_profile"])

    assert result.exit_code == 0
    assert "[human] [done] Step 2" in result.output


def test_guide_command_fresh_session_jumps_to_first_authored_phase(tmp_path):
    """Regression test: a guide set starting at phase 1 (not 0) must not be
    reported as already complete on a fresh session, and completing a step
    must be recorded against phase 1, not the stale default phase 0."""
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.discover_guides", return_value=[FAKE_GUIDE_PHASE_1]), \
         patch("rescue.cli._get_session_dir", return_value=tmp_path):
        runner = CliRunner()

        first = runner.invoke(main, ["guide", "test_profile"])
        assert "All phases complete!" not in first.output
        assert "Only Phase" in first.output
        assert "[human] [pending] Step 1" in first.output

        runner.invoke(main, ["guide", "test_profile", "--complete", "1"])
        second = runner.invoke(main, ["guide", "test_profile"])

    assert "[human] [done] Step 1" in second.output


def test_auto_mode_with_unknown_profile_exits_nonzero():
    with patch("rescue.cli.discover_profiles", return_value={}):
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--profile", "nonexistent"])

    assert result.exit_code != 0


def test_auto_mode_with_known_profile_passes_to_orchestrator():
    with patch("rescue.cli.discover_profiles", return_value={"test_profile": FAKE_PROFILE}), \
         patch("rescue.cli.Orchestrator") as MockOrch:
        instance = MockOrch.return_value
        instance.run_auto.return_value = []
        runner = CliRunner()
        result = runner.invoke(main, ["--auto", "--profile", "test_profile"])

    assert result.exit_code == 0
    _, kwargs = MockOrch.call_args
    assert kwargs["profile"] is FAKE_PROFILE
    assert "Test Profile" in result.output
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_cli_guide.py -v`
Expected: FAIL — `Error: No such command 'profiles'.` (and similar for `guide`, and `no such option: --profile`)

- [ ] **Step 3: Run the existing CLI suite to record the baseline (must still pass after this task)**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All 4 tests PASS (baseline before modification)

- [ ] **Step 4: Update the CLI**

Update `rescue/cli.py`:

```python
from pathlib import Path

import click

import rescue
from rescue.guides import discover_guides
from rescue.models import Mode, RiskLevel
from rescue.orchestrator import Orchestrator
from rescue.profiler.base import gather_profile
from rescue.profiles import discover_profiles
from rescue.registry import discover_modules
from rescue.session import SessionStore


def _project_root() -> Path:
    return Path(__file__).parent.parent


def _get_modules_dir() -> Path:
    return _project_root() / "modules"


def _get_profiles_dir() -> Path:
    return _project_root() / "profiles"


def _get_guides_dir() -> Path:
    return _project_root() / "guides"


def _get_session_dir() -> Path:
    return Path.home() / ".rescue" / "sessions"


def _load_profile_or_exit(profile_name: str):
    profiles = discover_profiles(_get_profiles_dir())
    if profile_name not in profiles:
        click.echo(f"Unknown profile: {profile_name}", err=True)
        click.echo(f"Available: {', '.join(sorted(profiles.keys()))}", err=True)
        raise SystemExit(1)
    return profiles[profile_name]


@click.group(invoke_without_command=True)
@click.option("--auto", is_flag=True, help="Run all checks and apply safe fixes automatically.")
@click.option("--profile", "profile_name", default=None, help="Threat-model profile to apply (filters/configures modules).")
@click.pass_context
def main(ctx, auto, profile_name):
    """Multiverse Device Rescue — system diagnostic and repair toolkit."""
    if auto:
        _run_auto(profile_name)
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


@main.command(name="profiles")
def list_profiles_cmd():
    """List available threat-model profiles."""
    profiles = discover_profiles(_get_profiles_dir())
    if not profiles:
        click.echo("No profiles found.")
        return
    for name in sorted(profiles):
        p = profiles[name]
        click.echo(f"{p.name} — {p.display_name}")
        if p.description:
            click.echo(f"    {p.description.strip()}")


@main.command()
@click.argument("profile_name")
@click.option("--complete", "complete_step", type=int, default=None, help="Mark a step number complete in the current phase.")
def guide(profile_name, complete_step):
    """Render the guide walkthrough for a profile, resuming saved progress."""
    profile = _load_profile_or_exit(profile_name)

    guides = discover_guides(_get_guides_dir(), profile_name)
    if not guides:
        click.echo(f"No guide content found for profile: {profile_name}")
        return

    store = SessionStore(session_dir=_get_session_dir())
    state = store.load(profile_name)

    phases_available = sorted(g.phase for g in guides)

    # If the session's current phase doesn't correspond to any authored
    # guide (e.g. a fresh session and this guide set's phases don't start
    # at 0), jump forward to the first authored phase *before* recording
    # any completion, so progress lands on the right phase.
    if state.current_phase not in phases_available and state.current_phase < phases_available[0]:
        state = store.advance_phase(profile_name, phases_available[0])

    if complete_step is not None:
        state = store.mark_step_complete(profile_name, state.current_phase, complete_step)
        click.echo(f"Marked step {complete_step} complete for phase {state.current_phase}.\n")

    current_guide = next((g for g in guides if g.phase == state.current_phase), None)
    if current_guide is None:
        click.echo("All phases complete!")
        return

    if store.is_phase_complete(state, current_guide.phase, current_guide):
        next_phase = current_guide.phase + 1
        next_guide = next((g for g in guides if g.phase == next_phase), None)
        if next_guide is not None:
            state = store.advance_phase(profile_name, next_phase)
            click.echo(f"Phase {current_guide.phase} complete! Moving to Phase {next_phase}.\n")
            current_guide = next_guide
        else:
            click.echo("All phases complete!")
            return

    done_steps = set(state.completed_steps.get(current_guide.phase, []))
    click.echo(f"=== {profile.display_name}: Phase {current_guide.phase} — {current_guide.title} ===")
    click.echo(f"Estimated time: {current_guide.estimated_time}\n")
    for step in current_guide.steps:
        tag = "automatable" if step.automatable else "human"
        status = "done" if step.number in done_steps else "pending"
        click.echo(f"[{tag}] [{status}] Step {step.number}: {step.title}")
    click.echo("\nRun again with --complete <step number> to mark a step done.")


def _run_auto(profile_name: str | None = None):
    modules_dir = _get_modules_dir()
    profile = _load_profile_or_exit(profile_name) if profile_name else None

    orch = Orchestrator(modules_dir=modules_dir, profile=profile)
    results = orch.run_auto()

    total_issues = sum(len(check.findings) for _, check, _ in results)
    fixed = sum(1 for _, _, fix in results if fix is not None)

    click.echo("=" * 50)
    click.echo("Multiverse Device Rescue — Auto Mode")
    if profile:
        click.echo(f"Profile: {profile.display_name}")
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

    if profile and profile.guides:
        click.echo("\n--- Guided walkthroughs available for this profile ---")
        for guide_name in profile.guides:
            click.echo(f"  Run 'rescue guide {guide_name}' to continue.")
```

- [ ] **Step 5: Run the new CLI tests to verify they pass**

Run: `python -m pytest tests/test_cli_guide.py -v`
Expected: All 7 tests PASS

- [ ] **Step 6: Run the original CLI suite to confirm no regressions**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All 4 tests PASS unmodified — `--auto` and `run` behave exactly as in Plan 1 when `--profile` is omitted.

- [ ] **Step 7: Commit**

```bash
git add rescue/cli.py tests/test_cli_guide.py
git commit -m "feat: add --profile flag, profiles command, and guide walkthrough command to the CLI"
```

---

### Task 6: Starter Profiles — `digital_security_reset` and `home_for_the_holidays`

**Files:**
- Create: `profiles/digital_security_reset.yaml`
- Create: `profiles/home_for_the_holidays.yaml`
- Create: `guides/digital_security_reset/phase_0.md`
- Create: `guides/digital_security_reset/phase_1.md`
- Create: `guides/digital_security_reset/phase_2.md`
- Create: `guides/digital_security_reset/phase_3.md`
- Create: `guides/digital_security_reset/phase_4.md`
- Create: `guides/digital_security_reset/phase_5.md`
- Create: `guides/home_for_the_holidays/phase_1.md`
- Test: `tests/test_starter_content.py`

**Interfaces:**
- Consumes: `discover_profiles`, `filter_modules_by_profile` from `rescue.profiles`; `discover_guides` from `rescue.guides`; `discover_modules` from `rescue.registry`
- Produces: working, loadable content at `profiles/*.yaml` and `guides/<profile>/*.md`, usable via `rescue profiles`, `rescue guide <name>`, and `rescue --auto --profile <name>`

**Note on file count:** this task creates more than the usual 2–5 files. That's an intentional exception to the "keep tasks small" constraint — every file here is static content (YAML or markdown), not code. There's no logic to review file-by-file; the six `digital_security_reset` phase files and one `home_for_the_holidays` phase file are validated as a single unit by `tests/test_starter_content.py` in Step 1, and splitting one profile's guide set across multiple tasks would only fragment a single coherent narrative (the six-phase recovery walkthrough) without reducing real complexity.

- [ ] **Step 1: Write failing tests for the starter content**

Create `tests/test_starter_content.py`:

```python
from pathlib import Path

from rescue.guides import discover_guides
from rescue.profiles import discover_profiles, filter_modules_by_profile
from rescue.registry import discover_modules

PROJECT_ROOT = Path(__file__).parent.parent
PROFILES_DIR = PROJECT_ROOT / "profiles"
GUIDES_DIR = PROJECT_ROOT / "guides"
MODULES_DIR = PROJECT_ROOT / "modules"


def test_starter_profiles_discovered():
    profiles = discover_profiles(PROFILES_DIR)
    assert "digital_security_reset" in profiles
    assert "home_for_the_holidays" in profiles


def test_digital_security_reset_profile_fields():
    profiles = discover_profiles(PROFILES_DIR)
    profile = profiles["digital_security_reset"]
    assert profile.display_name == "Digital Security Reset"
    assert profile.guides == ["digital_security_reset"]
    assert "password_manager_check" in profile.include_modules


def test_home_for_the_holidays_profile_fields():
    profiles = discover_profiles(PROFILES_DIR)
    profile = profiles["home_for_the_holidays"]
    assert profile.display_name == "Home for the Holidays"
    assert profile.guides == ["home_for_the_holidays"]
    assert "disk_space" in profile.include_modules


def test_home_for_the_holidays_profile_matches_real_disk_space_module():
    profiles = discover_profiles(PROFILES_DIR)
    profile = profiles["home_for_the_holidays"]
    modules = discover_modules(MODULES_DIR)

    matched = filter_modules_by_profile(modules, profile)

    names = [m.name for m in matched]
    assert names == ["disk_space"]


def test_digital_security_reset_guides_all_six_phases():
    guides = discover_guides(GUIDES_DIR, "digital_security_reset")
    assert [g.phase for g in guides] == [0, 1, 2, 3, 4, 5]


def test_digital_security_reset_phase_3_matches_design_spec_example():
    guides = discover_guides(GUIDES_DIR, "digital_security_reset")
    phase_3 = next(g for g in guides if g.phase == 3)

    assert phase_3.title == "Systematic Cleanup"
    assert phase_3.automatable_steps == [1, 2, 5]
    assert phase_3.human_only_steps == [3, 4, 6]
    assert phase_3.steps[0].title == "Reset your primary email password"


def test_home_for_the_holidays_guide_thirteen_steps():
    guides = discover_guides(GUIDES_DIR, "home_for_the_holidays")
    assert len(guides) == 1
    checklist = guides[0]
    assert len(checklist.steps) == 13
    assert len(checklist.automatable_steps) + len(checklist.human_only_steps) == 13
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `python -m pytest tests/test_starter_content.py -v`
Expected: FAIL — `AssertionError` (no profiles/guides exist on disk yet)

- [ ] **Step 3: Create the `digital_security_reset` profile**

Create `profiles/digital_security_reset.yaml`:

```yaml
name: digital_security_reset
display_name: "Digital Security Reset"
description: >
  Post-compromise recovery for someone who has been hacked or suspects
  their accounts or device have been compromised. Automates password
  manager, 2FA, and session checks, then guides through the six-phase
  recovery process: grounding, reality check, immediate protective
  actions, systematic cleanup, rebuilding security, and mental health
  maintenance.
modules:
  include:
    - password_manager_check
    - twofa_audit
    - session_revocation_scan
  exclude: []
module_config:
  password_manager_check:
    sensitivity: elevated
  twofa_audit:
    sensitivity: elevated
  session_revocation_scan:
    sensitivity: elevated
guides:
  - digital_security_reset
```

- [ ] **Step 4: Create the `home_for_the_holidays` profile**

Create `profiles/home_for_the_holidays.yaml`:

```yaml
name: home_for_the_holidays
display_name: "Home for the Holidays"
description: >
  Help a family member get their device cleaned up, secured, and
  documented in one visit. Runs the built-in device maintenance checks
  and walks through the 13-point checklist: data removal, password
  manager setup, device maintenance, and account hardening.
modules:
  include:
    - disk_space
  exclude: []
module_config:
  disk_space:
    sensitivity: normal
guides:
  - home_for_the_holidays
```

- [ ] **Step 5: Create the six digital_security_reset guide phases**

Create `guides/digital_security_reset/phase_0.md`:

```markdown
---
profile: digital_security_reset
phase: 0
title: "Emergency Grounding"
automatable_steps: []
human_only_steps: [1, 2, 3]
estimated_time: "10 minutes"
---

## Step 1: Ground yourself

Take a breath. You caught this, and you're taking the right steps by
working through this now. Compromise recovery is a process, not a single
action — it's normal for this to take a few sessions.

## Step 2: Check whether you can still get in

Confirm you can still sign into your primary email and at least one other
critical account. If you're already locked out of something, note it —
you'll come back to account recovery for that service in Phase 2.

## Step 3: Write down what you've already noticed

Before you start fixing anything, jot down (on paper, or in a notes app
on a device you trust) exactly what made you suspicious: strange emails,
unfamiliar logins, messages you didn't send, unexpected password reset
notifications. This becomes your starting checklist for Phase 1.
```

Create `guides/digital_security_reset/phase_1.md`:

```markdown
---
profile: digital_security_reset
phase: 1
title: "Reality Check"
automatable_steps: [1]
human_only_steps: [2, 3]
estimated_time: "20 minutes"
---

## Step 1: Run a full device scan

Run the tool's malware, remote-access-tool, and unexpected-software
scans on the device you're using right now. You want to know if the
device itself is compromised before you start changing passwords from it.

## Step 2: List every account tied to this identity

Write down every account you can think of that uses this email address
or phone number for recovery: email, banking, social media, cloud
storage, shopping, work accounts. You'll work through this list in later
phases — it doesn't need to be perfect, just as complete as you can make
it right now.

## Step 3: Check recent sign-in activity

For your primary email and any account that shows "recent activity" or
"login history," look for sign-ins from places or devices you don't
recognize. Note the ones that look wrong — you'll use this list in
Phase 2.
```

Create `guides/digital_security_reset/phase_2.md`:

```markdown
---
profile: digital_security_reset
phase: 2
title: "Immediate Protective Actions"
automatable_steps: [3, 4]
human_only_steps: [1, 2]
estimated_time: "30 minutes"
---

## Step 1: Change your primary email password

Do this first — your email is the recovery path for almost every other
account. Use a long, unique passphrase you haven't used anywhere else.

## Step 2: Turn on two-factor authentication for your email

If it isn't already on, enable it now, preferably with an authenticator
app rather than SMS.

## Step 3: Revoke sessions and connected apps you don't recognize

Run the session revocation scan to list active sessions and third-party
app connections across your accounts, and revoke anything you don't
recognize or no longer use.

## Step 4: Run the stalkerware and remote-access scan

Run the tool's scan for remote access tools, screen-sharing software, and
stalkerware-style apps that could be letting someone else see what you're
doing.
```

Create `guides/digital_security_reset/phase_3.md`:

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

Run the password manager check to confirm your new email password is
strong and not reused anywhere else, and that it's saved somewhere you'll
actually find it again.

## Step 2: Reset passwords for your top 5 accounts

Banking, primary social media, cloud storage, and your main work account
first. Run the password manager check again after each one to confirm
it's unique.

## Step 3: Clean up saved browser passwords

Go through your browser's saved password list and delete anything tied to
accounts you no longer use. Old saved logins are a liability you don't
need to keep around.

## Step 4: Contact your bank and financial institutions

Call the institutions tied to any account where you saw suspicious
activity in Phase 1. Ask them to flag the account and review recent
transactions with you.

## Step 5: Run the 2FA audit

Run the 2FA audit module to see which of your accounts don't have
two-factor authentication enabled yet, and turn it on for each one.

## Step 6: Write down your progress

Keep a paper list (not digital, in case the device is still a concern) of
every account you've secured so far. You'll want this in Phase 4.
```

Create `guides/digital_security_reset/phase_4.md`:

```markdown
---
profile: digital_security_reset
phase: 4
title: "Rebuilding Security"
automatable_steps: [2]
human_only_steps: [1, 3, 4]
estimated_time: "40 minutes"
---

## Step 1: Set up a password manager

If you don't already use one, set one up now and start migrating your
accounts into it — starting with the ones you haven't touched yet.

## Step 2: Verify unique passwords everywhere

Run the password manager check across your full account list from Phase 1
to confirm nothing is reused and everything meets a minimum strength bar.

## Step 3: Review app permissions on your phone

Go through installed apps and revoke location, contacts, and microphone
access for anything that doesn't need it.

## Step 4: Set up strong 2FA on your most critical accounts

For email, banking, and any account tied to your identity or finances,
move from SMS-based 2FA to an authenticator app or hardware security key
where the service supports it.
```

Create `guides/digital_security_reset/phase_5.md`:

```markdown
---
profile: digital_security_reset
phase: 5
title: "Mental Health Maintenance"
automatable_steps: []
human_only_steps: [1, 2, 3]
estimated_time: "ongoing"
---

## Step 1: Acknowledge the effort this took

Recovering from a compromise is genuinely stressful and time-consuming.
Getting through the previous five phases is a real accomplishment — be
kind to yourself about how long it took or how it felt.

## Step 2: Tell someone you trust

Even a short version of what happened, told to one person you trust,
makes this easier to carry. You don't have to handle this alone.

## Step 3: Schedule a one-week check-in

Put a reminder on your calendar for one week from now to re-check your
accounts: sign-in activity, connected apps, and 2FA status. A quick
follow-up catches anything that slipped through.
```

- [ ] **Step 6: Create the `home_for_the_holidays` guide**

Create `guides/home_for_the_holidays/phase_1.md`:

```markdown
---
profile: home_for_the_holidays
phase: 1
title: "The Family Device Checkup"
automatable_steps: [1, 2, 3]
human_only_steps: [4, 5, 6, 7, 8, 9, 10, 11, 12, 13]
estimated_time: "2 hours"
---

## Step 1: Run a full device health check

Run the disk space check and any available malware and update scans to
get a picture of what state the device is actually in before you touch
anything.

## Step 2: Clear out old temp files and caches

Free up space from caches, temp files, and old logs the disk space check
flagged as safe to remove.

## Step 3: Install pending OS and app updates

Bring the operating system and installed apps up to date. This closes off
known vulnerabilities and is one of the highest-value things you can do
in a single visit.

## Step 4: Set up a password manager

If they don't already have one, install a password manager and get it
signed in on their primary devices.

## Step 5: Migrate saved browser passwords

Move passwords saved in the browser into the password manager, and flag
any that are reused across multiple sites.

## Step 6: Enable two-factor authentication

Turn on 2FA for email, banking, and any social media accounts that
support it. Prefer an authenticator app over SMS where possible.

## Step 7: Review logged-in devices and sessions

Check the "devices" or "active sessions" list on their major accounts and
sign out of anything that isn't recognized or hasn't been used in months.

## Step 8: Set up automatic backups

Turn on a backup solution — local, cloud, or both — so the next device
problem doesn't mean losing photos and documents.

## Step 9: Review social media privacy settings

Walk through privacy settings on the platforms they actually use, and
tighten who can see posts, contact them, and view their friend/follower
list.

## Step 10: Remove unused accounts and apps

Uninstall apps that are no longer used, and close out or deactivate
accounts they don't need anymore — fewer accounts means a smaller attack
surface.

## Step 11: Set a strong lock screen

Make sure the device has a passcode, PIN, or biometric lock set, not
"none" or something trivially guessable.

## Step 12: Confirm disk encryption is enabled

Check that FileVault (macOS), BitLocker (Windows), or device encryption
(mobile) is turned on, so the data is protected if the device is lost or
stolen.

## Step 13: Write the "Help Me" reference document

Write down, in plain language, what was changed today: which password
manager they're using and how to open it, which accounts now have 2FA,
and who to call (you) if something goes wrong. Leave it somewhere they'll
actually find it.
```

- [ ] **Step 7: Run tests to verify they pass**

Run: `python -m pytest tests/test_starter_content.py -v`
Expected: All 7 tests PASS

- [ ] **Step 8: Run the full test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS (models, profiler, module_base, registry, orchestrator, cli, disk_space, profiles, guides, session, module_configure, orchestrator_profile, cli_guide, starter_content)

- [ ] **Step 9: Smoke test the CLI end-to-end**

Use the installed `rescue` command (from the `pip install -e .` steps in earlier tasks — since the install is editable, it already reflects the `rescue/cli.py` changes from Task 5). `rescue.cli` has no `if __name__ == "__main__"` guard, so `python -m rescue.cli` will *not* invoke the command — always use the `rescue` entry point, exactly as Plan 1's smoke tests did.

Run:
```bash
rescue profiles
rescue guide home_for_the_holidays
rescue guide home_for_the_holidays --complete 1
rescue guide home_for_the_holidays
rescue --auto --profile home_for_the_holidays
```

Expected:
- `profiles` lists `digital_security_reset` and `home_for_the_holidays` with their descriptions.
- The first `guide` invocation shows "Phase 1 — The Family Device Checkup" with all 13 steps as `[pending]`, steps 1–3 tagged `[automatable]`, steps 4–13 tagged `[human]`. (The session starts fresh at phase 0, but this guide set's only phase is numbered 1, so the phase-fallback logic in `guide()` jumps to phase 1 automatically — verify this happens and no "All phases complete!" message appears.)
- `--complete 1` marks step 1 done; the next `guide` invocation shows Step 1 as `[done]` and the rest still `[pending]`.
- `--auto --profile home_for_the_holidays` filters the run down to the `disk_space` module (the only module in `include_modules` that's actually implemented), and prints "Run 'rescue guide home_for_the_holidays' to continue." at the end.

- [ ] **Step 10: Verify full multi-phase progression through `digital_security_reset`**

This exercises the phase-advancement logic (not just the fallback-jump logic exercised by `home_for_the_holidays` in Step 9), using a throwaway `HOME` so it doesn't collide with real session state:

```bash
export HOME=$(mktemp -d)
rescue guide digital_security_reset --complete 1
rescue guide digital_security_reset --complete 2
rescue guide digital_security_reset --complete 3   # phase 0 has 3 steps; this should complete it
rescue guide digital_security_reset                # should now show "Phase 1 — Reality Check"
```

Expected: after completing steps 1–3, the next plain `rescue guide digital_security_reset` call prints `Phase 0 complete! Moving to Phase 1.` followed by the Phase 1 (Reality Check) step list. Continuing to complete every step of every phase (0 through 5) eventually prints `Phase 5 complete! Moving to Phase 6.`-style output is *not* expected — instead, since phase 5 is the last authored phase, completing it prints `All phases complete!` on the next invocation.

- [ ] **Step 11: Commit**

```bash
git add profiles/ guides/ tests/test_starter_content.py
git commit -m "feat: add digital_security_reset and home_for_the_holidays starter profiles and guide content"
```

---

## Future Plans

These remain separate implementation plans, unaffected by this one:

- **Plan 2: Interactive TUI** — Textual-based app with category menus, progress bars, findings display, and richer guide/walkthrough rendering (the `rescue guide` CLI command in this plan is a plain-text stand-in; the TUI should render `Guide`/`GuideStep`/`SessionState` as interactive checklists).
- **Plan 4: Secure Update System** — Signed bundle format, threshold signing verification, checksum validation, TLS cert pinning, air-gapped sideloading, `rescue update` command. Profile and guide content are part of the "guide content" update layer described in the design spec and should update independently of the core.
- **Plan 5: AI Layer** — Optional diagnostic explainer, profile recommender (intake conversation → suggests a `Profile` by name), and walkthrough copilot grounded in `Guide` content and `SystemProfile` state.
- **Plan 6+: Module Packs** — Implements the actual modules referenced by `include_modules` in the starter profiles (`password_manager_check`, `twofa_audit`, `session_revocation_scan`), plus the remaining threat-model profiles from the design spec (`six_roses`, `activist_security`, `journalist_security`, `personal_lockdown`, `creator`, `family_device`, `work_machine`) and their guide content.
