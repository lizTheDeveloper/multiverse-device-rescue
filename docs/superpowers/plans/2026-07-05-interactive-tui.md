# Interactive TUI Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Build the `textual`-based interactive TUI so that running `rescue` with no flags launches a full category → module → findings → fix-selection flow driven by the existing `Orchestrator`, with a placeholder screen where Plan 3's guide/walkthrough engine will render.

**Architecture:** A `RescueApp` (Textual `App`) owns one `Orchestrator` instance for the whole session. On startup a `LoadingScreen` calls `Orchestrator.run_checks()` in a background thread (profiling + module discovery + running every applicable module's `check()` happen once, up front) and hands the full `list[tuple[ModuleBase, CheckResult]]` back to the app. Every screen after that — category menu, module list, findings, fix confirmation/progress/result, guide placeholder — is a pure view over that already-computed data, pushed/popped on Textual's screen stack. Fixes are applied per-module (`ModuleBase.fix()`), in a background thread, with a confirmation modal gating anything above `RiskLevel.SAFE`. `rescue.cli.main` launches `RescueApp` when invoked with no subcommand and no `--auto` flag.

**Tech Stack:** Python 3.11+, Textual (TUI framework, pinned `>=8,<9`), pytest + pytest-asyncio (`asyncio_mode = "auto"`) for testing Textual screens via `App.run_test()` / `Pilot`, Click (existing CLI, unchanged for `--auto`/`run`/`version`)

## Global Constraints

- Textual version is pinned `textual>=8,<9` in `pyproject.toml` — the plan's code (private-attribute-free, but still API-shaped to 8.x) is validated against 8.2.8; an untested major bump could change `ProgressBar(total=None)`, `push_screen_wait`, or message class behavior.
- `asyncio_mode = "auto"` lives in `[tool.pytest.ini_options]` in `pyproject.toml` from Task 1 onward — every `pytest` command in every later task relies on this and passes no `--asyncio-mode` flag.
- Never subclass `RescueApp` in a test to mount a single screen for isolation — subclassing `RescueApp` and overriding `on_mount` was empirically found to double-fire mount handlers (both the parent's `LoadingScreen` push and the subclass's push happen, corrupting the screen stack). Per-screen tests define their own minimal `textual.app.App` subclass that pushes only the screen under test. Only the final end-to-end integration test (Task 8) instantiates `RescueApp` directly.
- Screens reach forward to screens defined in later tasks via a lazy `import` **inside the event handler method**, never at module top level. This avoids circular imports between screen modules and lets each task's tests pass before later screens exist.
- All screen-to-screen handoffs pass already-computed data through constructor arguments (`__init__`), never through ad-hoc attributes bolted onto `self.app` after construction. The one exception is `RescueApp.on_checks_complete()`, which is the single, explicit handoff point from `LoadingScreen` back to the app.
- Any work that blocks for more than a fraction of a second (profiling, running checks, running fixes) runs in a Textual `@work(thread=True)` worker and calls back into the UI thread via `self.app.call_from_thread(...)`. Never call these directly from `compose()` or `on_mount()`.
- **Interpretation note for reviewers:** the design spec says "category menu → module selection → findings → fix selection." This plan runs `Orchestrator.run_checks()` for *all* applicable modules once, up front (via `LoadingScreen`), and treats "module selection" as a drill-down/filter over already-computed results rather than a pre-check selector — this is the cleanest way to have the TUI "consume the Orchestrator" as a single unit of work, and checks are inspection-only (never mutate state) so running all of them eagerly costs nothing extra. "Fix selection" operates at the module level (one "Apply Fixes" button per module, gated by a confirm modal for `moderate`/`destructive` modules) rather than per-finding — per-finding selection is possible later by constructing a filtered `CheckResult` and is out of scope now (YAGNI).

---

### Task 1: Textual Dependency, Package Skeleton & Formatting Helpers

**Files:**
- Edit: `pyproject.toml`
- Create: `rescue/tui/__init__.py`
- Create: `rescue/tui/formatting.py`
- Create: `rescue/tui/screens/__init__.py`
- Test: `tests/tui/__init__.py`
- Test: `tests/tui/test_formatting.py`

**Interfaces:**
- Consumes: `CheckResult`, `Finding`, `RiskLevel`, `Severity` from `rescue.models`; `ModuleBase` from `rescue.module_base`
- Produces (in `rescue.tui.formatting`, no Textual imports — pure functions, unit-testable without spinning up a TUI):
  - `group_by_category(modules: list[ModuleBase]) -> dict[str, list[ModuleBase]]`
  - `severity_color(severity: Severity) -> str`
  - `risk_color(risk_level: RiskLevel) -> str`
  - `format_finding_line(finding: Finding) -> str` — Rich-markup string, color coded by severity
  - `format_module_summary(mod: ModuleBase, check: CheckResult) -> str` — one-line summary for list rows
  - `format_category_summary(category: str, modules: list[ModuleBase], results: dict[str, CheckResult]) -> str`

- [ ] **Step 1: Add Textual and pytest-asyncio to pyproject.toml, pin versions, enable asyncio auto mode**

Edit `pyproject.toml`. Change the `dependencies` list and `[project.optional-dependencies]` and add the asyncio pytest setting:

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
    "textual>=8,<9",
]

[project.optional-dependencies]
dev = ["pytest>=8.0", "pytest-asyncio>=0.24"]

[project.scripts]
rescue = "rescue.cli:main"

[tool.pytest.ini_options]
testpaths = ["tests"]
asyncio_mode = "auto"

[tool.setuptools.packages.find]
include = ["rescue*"]
```

Run:
```bash
pip install -e ".[dev]"
```

- [ ] **Step 2: Create package skeleton**

Create `rescue/tui/__init__.py` (empty file).

Create `rescue/tui/screens/__init__.py` (empty file).

Create `tests/tui/__init__.py` (empty file).

- [ ] **Step 3: Write failing tests for formatting helpers**

Create `tests/tui/test_formatting.py`:

```python
from rescue.models import CheckResult, Finding, Platform, RiskLevel, Severity
from rescue.module_base import ModuleBase
from rescue.tui.formatting import (
    format_category_summary,
    format_finding_line,
    format_module_summary,
    group_by_category,
    risk_color,
    severity_color,
)


class PerfModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class SecurityModule(ModuleBase):
    name = "firewall_audit"
    category = "security"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.MODERATE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def test_group_by_category():
    modules = [SecurityModule(), PerfModule()]
    groups = group_by_category(modules)
    assert list(groups.keys()) == ["performance", "security"]
    assert groups["performance"] == [modules[1]]
    assert groups["security"] == [modules[0]]


def test_severity_color():
    assert severity_color(Severity.CRITICAL) == "red"
    assert severity_color(Severity.WARNING) == "yellow"
    assert severity_color(Severity.INFO) == "cyan"


def test_risk_color():
    assert risk_color(RiskLevel.SAFE) == "green"
    assert risk_color(RiskLevel.MODERATE) == "yellow"
    assert risk_color(RiskLevel.DESTRUCTIVE) == "red"


def test_format_finding_line_includes_severity_and_text():
    finding = Finding(
        title="Disk full",
        description="90% used",
        severity=Severity.CRITICAL,
        category="performance",
    )
    line = format_finding_line(finding)
    assert "CRITICAL" in line
    assert "Disk full" in line
    assert "90% used" in line
    assert "[red]" in line


def test_format_module_summary_no_issues():
    mod = PerfModule()
    check = CheckResult(module_name="disk_space")
    summary = format_module_summary(mod, check)
    assert "no issues found" in summary


def test_format_module_summary_with_issues():
    mod = PerfModule()
    check = CheckResult(
        module_name="disk_space",
        findings=[
            Finding(
                title="Disk full",
                description="d",
                severity=Severity.CRITICAL,
                category="performance",
            )
        ],
    )
    summary = format_module_summary(mod, check)
    assert "1 issue(s)" in summary
    assert "[red]" in summary


def test_format_category_summary_aggregates_across_modules():
    mods = [PerfModule()]
    results = {
        "disk_space": CheckResult(
            module_name="disk_space",
            findings=[
                Finding(
                    title="t", description="d", severity=Severity.WARNING, category="performance"
                )
            ],
        )
    }
    summary = format_category_summary("performance", mods, results)
    assert "1 issue(s)" in summary


def test_format_category_summary_no_issues():
    mods = [PerfModule()]
    results = {"disk_space": CheckResult(module_name="disk_space")}
    summary = format_category_summary("performance", mods, results)
    assert "no issues found" in summary
```

- [ ] **Step 4: Run tests to verify they fail**

Run: `python -m pytest tests/tui/test_formatting.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.formatting'`

- [ ] **Step 5: Implement formatting helpers**

Create `rescue/tui/formatting.py`:

```python
"""Pure formatting/grouping helpers for the TUI. No Textual imports here —
kept dependency-free so it can be unit tested in isolation."""

from collections import defaultdict

from rescue.models import CheckResult, Finding, RiskLevel, Severity
from rescue.module_base import ModuleBase

SEVERITY_COLORS: dict[Severity, str] = {
    Severity.INFO: "cyan",
    Severity.WARNING: "yellow",
    Severity.CRITICAL: "red",
}

RISK_COLORS: dict[RiskLevel, str] = {
    RiskLevel.SAFE: "green",
    RiskLevel.MODERATE: "yellow",
    RiskLevel.DESTRUCTIVE: "red",
}


def group_by_category(modules: list[ModuleBase]) -> dict[str, list[ModuleBase]]:
    """Group modules by their `category` attribute, sorted by category name."""
    groups: dict[str, list[ModuleBase]] = defaultdict(list)
    for mod in modules:
        groups[mod.category].append(mod)
    return dict(sorted(groups.items()))


def severity_color(severity: Severity) -> str:
    return SEVERITY_COLORS.get(severity, "white")


def risk_color(risk_level: RiskLevel) -> str:
    return RISK_COLORS.get(risk_level, "white")


def format_finding_line(finding: Finding) -> str:
    """Rich-markup line for a single finding, color coded by severity."""
    color = severity_color(finding.severity)
    return f"[{color}]{finding.severity.value.upper()}[/{color}] {finding.title} — {finding.description}"


def format_module_summary(mod: ModuleBase, check: CheckResult) -> str:
    """One-line summary of a module's check result, for list rows."""
    if not check.has_issues:
        return f"{mod.name} — no issues found"
    color = "yellow"
    for f in check.findings:
        if f.severity == Severity.CRITICAL:
            color = "red"
            break
    return f"{mod.name} — [{color}]{len(check.findings)} issue(s)[/{color}]"


def format_category_summary(
    category: str, modules: list[ModuleBase], results: dict[str, CheckResult]
) -> str:
    """One-line summary of a category, showing total issue count across its modules."""
    total = sum(len(results[m.name].findings) for m in modules if m.name in results)
    if total == 0:
        return f"{category} — no issues found"
    return f"{category} — [yellow]{total} issue(s)[/yellow]"
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `python -m pytest tests/tui/test_formatting.py -v`
Expected: All 7 tests PASS

- [ ] **Step 7: Commit**

```bash
git add pyproject.toml rescue/tui/__init__.py rescue/tui/formatting.py rescue/tui/screens/__init__.py tests/tui/__init__.py tests/tui/test_formatting.py
git commit -m "feat: add textual dependency and TUI formatting helpers"
```

---

### Task 2: Confirmation Modal & Guide Placeholder Screen

**Files:**
- Create: `rescue/tui/screens/confirm.py`
- Create: `rescue/tui/screens/guide_placeholder.py`
- Test: `tests/tui/test_confirm_screen.py`
- Test: `tests/tui/test_guide_placeholder_screen.py`

**Interfaces:**
- Consumes: `ModuleBase` from `rescue.module_base`
- Produces:
  - `ConfirmScreen(message: str)` — `textual.screen.ModalScreen[bool]` in `rescue.tui.screens.confirm`; resolves to `True`/`False` via `self.dismiss(...)` when its Confirm/Cancel buttons (`id="confirm-yes"` / `id="confirm-no"`) are pressed
  - `GuidePlaceholderScreen(mod: ModuleBase)` — `textual.screen.Screen` in `rescue.tui.screens.guide_placeholder`; renders a static message plus a disabled 3-item `Checkbox` checklist previewing the shape of Plan 3's walkthrough UI

These two screens have no dependency on check/fix results, so they can be built and tested standalone before the data-flow screens in later tasks.

- [ ] **Step 1: Write failing test for ConfirmScreen**

Create `tests/tui/test_confirm_screen.py`:

```python
from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Static

from rescue.tui.screens.confirm import ConfirmScreen


class ConfirmHostScreen(Screen):
    """Hosts a button that triggers the modal and records the result."""

    def compose(self) -> ComposeResult:
        yield Static("waiting", id="result")

    def on_mount(self) -> None:
        self.run_worker(self.ask())

    async def ask(self) -> None:
        result = await self.app.push_screen_wait(ConfirmScreen("Proceed?"))
        self.query_one("#result", Static).update(f"result:{result}")


class ConfirmHostApp(App):
    def on_mount(self) -> None:
        self.push_screen(ConfirmHostScreen())


async def test_confirm_screen_yes():
    app = ConfirmHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#confirm-yes")
        await pilot.pause()
        assert app.screen.query_one("#result", Static).content == "result:True"


async def test_confirm_screen_no():
    app = ConfirmHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#confirm-no")
        await pilot.pause()
        assert app.screen.query_one("#result", Static).content == "result:False"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_confirm_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.confirm'`

- [ ] **Step 3: Implement ConfirmScreen**

Create `rescue/tui/screens/confirm.py`:

```python
"""Reusable yes/no confirmation modal, used before applying moderate or
destructive fixes."""

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmScreen(ModalScreen[bool]):
    """A modal that resolves to True (confirmed) or False (cancelled)."""

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(self.message, id="confirm-message"),
            Button("Confirm", id="confirm-yes", variant="success"),
            Button("Cancel", id="confirm-no", variant="error"),
            id="confirm-container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_confirm_screen.py -v`
Expected: Both tests PASS

- [ ] **Step 5: Write failing test for GuidePlaceholderScreen**

Create `tests/tui/test_guide_placeholder_screen.py`:

```python
from textual.app import App
from textual.widgets import Checkbox, Static

from rescue.models import Platform
from rescue.module_base import ModuleBase
from rescue.tui.screens.guide_placeholder import GuidePlaceholderScreen


class FakeMod(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class GuideHostApp(App):
    def on_mount(self) -> None:
        self.push_screen(GuidePlaceholderScreen(FakeMod()))


async def test_guide_placeholder_shows_disabled_checklist():
    app = GuideHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        checkboxes = list(app.screen.query(Checkbox))
        assert len(checkboxes) == 3
        for cb in checkboxes:
            assert cb.disabled

        message = app.screen.query_one("#guide-placeholder-message", Static)
        assert "disk_space" in str(message.content)
        assert "Plan 3" in str(message.content)
```

- [ ] **Step 6: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_guide_placeholder_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.guide_placeholder'`

- [ ] **Step 7: Implement GuidePlaceholderScreen**

Create `rescue/tui/screens/guide_placeholder.py`:

```python
"""Placeholder for the guide/walkthrough system (Plan 3). Shows what a
step-by-step guided walkthrough checklist will look like, without any real
guide content or progress persistence wired up yet."""

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Checkbox, Footer, Header, Static

from rescue.module_base import ModuleBase

PLACEHOLDER_STEPS = [
    "Review the finding details",
    "Apply the recommended change",
    "Confirm the change took effect",
]


class GuidePlaceholderScreen(Screen):
    """Stub screen for guide/walkthrough rendering.

    This is a hook point for Plan 3 (Profile System & Guide Engine). Once
    markdown guide content with frontmatter is parsed, this screen will be
    replaced with real step content driven by the guide's `automatable_steps`
    and `human_only_steps` metadata. For now it renders a static, disabled
    checklist so the eventual UI shape is visible.
    """

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, mod: ModuleBase):
        super().__init__()
        self.mod = mod

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static(
                f"Guides & interactive walkthroughs for '{self.mod.name}' are "
                f"coming in Plan 3 (Profile System & Guide Engine).",
                id="guide-placeholder-message",
            ),
            Static("Preview of the walkthrough checklist UI:", id="guide-placeholder-preview-label"),
            *[Checkbox(step, disabled=True) for step in PLACEHOLDER_STEPS],
        )
        yield Footer()
```

- [ ] **Step 8: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_guide_placeholder_screen.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add rescue/tui/screens/confirm.py rescue/tui/screens/guide_placeholder.py tests/tui/test_confirm_screen.py tests/tui/test_guide_placeholder_screen.py
git commit -m "feat: add confirmation modal and guide/walkthrough placeholder screen"
```

---

### Task 3: Loading Screen (Orchestrator Integration)

**Files:**
- Create: `rescue/tui/screens/loading.py`
- Test: `tests/tui/test_loading_screen.py`

**Interfaces:**
- Consumes:
  - `Orchestrator(modules_dir: Path)` and `Orchestrator.run_checks() -> list[tuple[ModuleBase, CheckResult]]` from `rescue.orchestrator`
  - `CheckResult` from `rescue.models`, `ModuleBase` from `rescue.module_base`
- Produces:
  - `LoadingScreen(orchestrator: Orchestrator)` — `textual.screen.Screen` in `rescue.tui.screens.loading`. On mount, runs `orchestrator.run_checks()` in a background thread, then calls `self.app.on_checks_complete(results)` on the UI thread. Requires the hosting `App` to implement `on_checks_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None` (provided by `RescueApp` in Task 8; test hosts provide their own stub).

- [ ] **Step 1: Write failing test for LoadingScreen**

Create `tests/tui/test_loading_screen.py`:

```python
from unittest.mock import MagicMock

from textual.app import App
from textual.widgets import ProgressBar

from rescue.tui.screens.loading import LoadingScreen


class LoadingHostApp(App):
    """Minimal host that records the results handed back by LoadingScreen."""

    def __init__(self, orchestrator):
        super().__init__()
        self.orchestrator = orchestrator
        self.received_results = None

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen(self.orchestrator))

    def on_checks_complete(self, results) -> None:
        self.received_results = results


async def test_loading_screen_runs_checks_and_hands_off():
    fake_results = [("mod1", "check1")]
    orchestrator = MagicMock()
    orchestrator.run_checks.return_value = fake_results

    app = LoadingHostApp(orchestrator)
    async with app.run_test() as pilot:
        for _ in range(20):
            await pilot.pause(0.05)
            if app.received_results is not None:
                break

    assert app.received_results == fake_results
    orchestrator.run_checks.assert_called_once()


async def test_loading_screen_shows_indeterminate_progress():
    orchestrator = MagicMock()
    orchestrator.run_checks.return_value = []

    app = LoadingHostApp(orchestrator)
    async with app.run_test() as pilot:
        await pilot.pause()
        progress = app.screen.query_one("#loading-progress", ProgressBar)
        assert progress.total is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_loading_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.loading'`

- [ ] **Step 3: Implement LoadingScreen**

Create `rescue/tui/screens/loading.py`:

```python
"""Loading screen: profiles the system and runs all module checks via the
Orchestrator, then hands off to the category menu."""

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator


class LoadingScreen(Screen):
    """Shown on startup while the orchestrator profiles the system and runs checks."""

    def __init__(self, orchestrator: Orchestrator):
        super().__init__()
        self.orchestrator = orchestrator

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static("Profiling system and running checks…", id="loading-status"),
            ProgressBar(show_eta=False, id="loading-progress"),
            id="loading-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#loading-progress", ProgressBar).update(total=None)
        self.run_scan()

    @work(thread=True)
    def run_scan(self) -> None:
        results = self.orchestrator.run_checks()
        self.app.call_from_thread(self.on_scan_complete, results)

    def on_scan_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None:
        self.app.on_checks_complete(results)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_loading_screen.py -v`
Expected: Both tests PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/tui/screens/loading.py tests/tui/test_loading_screen.py
git commit -m "feat: add TUI loading screen that runs orchestrator checks in a worker thread"
```

---

### Task 4: Category Menu & Module List Screens

**Files:**
- Create: `rescue/tui/screens/categories.py`
- Create: `rescue/tui/screens/modules.py`
- Test: `tests/tui/test_categories_screen.py`
- Test: `tests/tui/test_modules_screen.py`

**Interfaces:**
- Consumes:
  - `CheckResult` from `rescue.models`, `ModuleBase` from `rescue.module_base`
  - `group_by_category`, `format_category_summary`, `format_module_summary` from `rescue.tui.formatting` (Task 1)
- Produces:
  - `CategoryMenuScreen(results: list[tuple[ModuleBase, CheckResult]])` — `textual.screen.Screen` in `rescue.tui.screens.categories`. Lists categories via `OptionList` (`id="category-list"`), each `Option.id` equal to the category slug. Selecting one pushes `ModuleListScreen(category, category_results)`.
  - `ModuleListScreen(category: str, results: list[tuple[ModuleBase, CheckResult]])` — `textual.screen.Screen` in `rescue.tui.screens.modules`. Lists modules via `OptionList` (`id="module-list"`), each `Option.id` equal to the module name. Selecting one pushes `FindingsScreen(mod, check)` (from Task 5 — imported lazily inside the handler).

- [ ] **Step 1: Write failing test for CategoryMenuScreen and ModuleListScreen navigation**

Create `tests/tui/test_categories_screen.py`:

```python
from textual.app import App
from textual.widgets import OptionList

from rescue.models import CheckResult, Finding, Platform, Severity
from rescue.module_base import ModuleBase
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.modules import ModuleListScreen


class PerfModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class SecurityModule(ModuleBase):
    name = "firewall_audit"
    category = "security"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def _make_results():
    perf_check = CheckResult(
        module_name="disk_space",
        findings=[
            Finding(title="Disk full", description="90%", severity=Severity.WARNING, category="performance")
        ],
    )
    sec_check = CheckResult(module_name="firewall_audit")
    return [(PerfModule(), perf_check), (SecurityModule(), sec_check)]


class CategoryHostApp(App):
    def __init__(self, results):
        super().__init__()
        self.results = results

    def on_mount(self) -> None:
        self.push_screen(CategoryMenuScreen(self.results))


async def test_category_menu_lists_categories_sorted():
    app = CategoryHostApp(_make_results())
    async with app.run_test() as pilot:
        await pilot.pause()
        option_list = app.screen.query_one("#category-list", OptionList)
        ids = [option_list.get_option_at_index(i).id for i in range(option_list.option_count)]
        assert ids == ["performance", "security"]


async def test_selecting_category_pushes_module_list_screen():
    app = CategoryHostApp(_make_results())
    async with app.run_test() as pilot:
        await pilot.pause()
        option_list = app.screen.query_one("#category-list", OptionList)
        option_list.action_select()
        await pilot.pause()
        assert isinstance(app.screen, ModuleListScreen)
        assert app.screen.category == "performance"
        module_list = app.screen.query_one("#module-list", OptionList)
        assert module_list.get_option_at_index(0).id == "disk_space"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_categories_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.categories'`

- [ ] **Step 3: Implement CategoryMenuScreen and ModuleListScreen**

Create `rescue/tui/screens/categories.py`:

```python
"""Category menu screen — the entry point after checks have run. Lists each
module category with an aggregate issue count."""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList
from textual.widgets.option_list import Option

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.tui.formatting import format_category_summary, group_by_category


class CategoryMenuScreen(Screen):
    """Displays module categories discovered on this system."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, results: list[tuple[ModuleBase, CheckResult]]):
        super().__init__()
        self.results = results
        self.results_by_name = {mod.name: check for mod, check in results}
        self.groups = group_by_category([mod for mod, _ in results])

    def compose(self) -> ComposeResult:
        yield Header()
        options = [
            Option(
                format_category_summary(category, mods, self.results_by_name),
                id=category,
            )
            for category, mods in self.groups.items()
        ]
        yield OptionList(*options, id="category-list")
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        category = event.option.id
        assert category is not None
        category_results = [
            (mod, check) for mod, check in self.results if mod.category == category
        ]
        from rescue.tui.screens.modules import ModuleListScreen

        self.app.push_screen(ModuleListScreen(category, category_results))
```

Create `rescue/tui/screens/modules.py`:

```python
"""Module list screen — shows the modules within a category and their check
results; selecting one drills into its findings."""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList
from textual.widgets.option_list import Option

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.tui.formatting import format_module_summary


class ModuleListScreen(Screen):
    """Displays modules within a single category."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, category: str, results: list[tuple[ModuleBase, CheckResult]]):
        super().__init__()
        self.category = category
        self.results = results
        self.results_by_name = {mod.name: (mod, check) for mod, check in results}

    def compose(self) -> ComposeResult:
        yield Header()
        options = [
            Option(format_module_summary(mod, check), id=mod.name)
            for mod, check in self.results
        ]
        yield OptionList(*options, id="module-list")
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        module_name = event.option.id
        assert module_name is not None
        mod, check = self.results_by_name[module_name]
        from rescue.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(mod, check))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_categories_screen.py -v`
Expected: Both tests PASS. Note that `FindingsScreen` (Task 5) does not exist yet — `ModuleListScreen.on_option_list_option_selected` imports it lazily inside the handler, and this test never selects a module (it only exercises `CategoryMenuScreen`'s handler), so that import is never reached.

- [ ] **Step 5: Write a standalone test for ModuleListScreen alone (does not touch FindingsScreen)**

Create `tests/tui/test_modules_screen.py`:

```python
from textual.app import App
from textual.widgets import OptionList

from rescue.models import CheckResult, Platform
from rescue.module_base import ModuleBase
from rescue.tui.screens.modules import ModuleListScreen


class PerfModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModuleListHostApp(App):
    def __init__(self, category, results):
        super().__init__()
        self.category = category
        self.results = results

    def on_mount(self) -> None:
        self.push_screen(ModuleListScreen(self.category, self.results))


async def test_module_list_shows_modules_in_category():
    results = [(PerfModule(), CheckResult(module_name="disk_space"))]
    app = ModuleListHostApp("performance", results)
    async with app.run_test() as pilot:
        await pilot.pause()
        option_list = app.screen.query_one("#module-list", OptionList)
        assert option_list.get_option_at_index(0).id == "disk_space"
```

- [ ] **Step 6: Run both test files to verify they pass**

Run: `python -m pytest tests/tui/test_categories_screen.py tests/tui/test_modules_screen.py -v`
Expected: All 3 tests PASS (`FindingsScreen` does not need to exist yet — the import in `ModuleListScreen.on_option_list_option_selected` is lazy and is never executed by these tests since no test selects a module).

- [ ] **Step 7: Commit**

```bash
git add rescue/tui/screens/categories.py rescue/tui/screens/modules.py tests/tui/test_categories_screen.py tests/tui/test_modules_screen.py
git commit -m "feat: add TUI category menu and module list screens"
```

---

### Task 5: Findings Screen

**Files:**
- Create: `rescue/tui/screens/findings.py`
- Test: `tests/tui/test_findings_screen.py`

**Interfaces:**
- Consumes:
  - `CheckResult`, `RiskLevel` from `rescue.models`, `ModuleBase` from `rescue.module_base`
  - `format_finding_line` from `rescue.tui.formatting` (Task 1)
  - `ConfirmScreen` from `rescue.tui.screens.confirm` (Task 2, lazy import)
- Produces:
  - `FindingsScreen(mod: ModuleBase, check: CheckResult)` — `textual.screen.Screen` in `rescue.tui.screens.findings`. Renders each finding via `format_finding_line`. If `check.has_issues`, shows an `Apply Fixes` button (`id="apply-fixes"`). Pressing it: if `mod.risk_level != RiskLevel.SAFE`, awaits a `ConfirmScreen` via `push_screen_wait`; on confirmation (or immediately if already safe), pushes `FixProgressScreen(mod, check)` (from Task 6, lazy import).

- [ ] **Step 1: Write failing tests for FindingsScreen**

Create `tests/tui/test_findings_screen.py`:

```python
from textual.app import App
from textual.widgets import Button, Static

from rescue.models import CheckResult, Finding, Platform, RiskLevel, Severity
from rescue.module_base import ModuleBase
from rescue.tui.screens.findings import FindingsScreen


class SafeModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class FindingsHostApp(App):
    def __init__(self, mod, check):
        super().__init__()
        self.mod = mod
        self.check = check

    def on_mount(self) -> None:
        self.push_screen(FindingsScreen(self.mod, self.check))


async def test_findings_screen_shows_no_issues_message():
    app = FindingsHostApp(SafeModule(), CheckResult(module_name="disk_space"))
    async with app.run_test() as pilot:
        await pilot.pause()
        empty = app.screen.query_one("#findings-empty", Static)
        assert "no issues found" in str(empty.content)
        assert app.screen.query(Button).is_empty


async def test_findings_screen_lists_findings_and_apply_button():
    check = CheckResult(
        module_name="disk_space",
        findings=[
            Finding(title="Disk full", description="90% used", severity=Severity.WARNING, category="performance")
        ],
    )
    app = FindingsHostApp(SafeModule(), check)
    async with app.run_test() as pilot:
        await pilot.pause()
        rows = list(app.screen.query(".finding-row"))
        assert len(rows) == 1
        assert "Disk full" in str(rows[0].content)
        apply_button = app.screen.query_one("#apply-fixes", Button)
        assert "safe" in str(apply_button.label)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_findings_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.findings'`

- [ ] **Step 3: Implement FindingsScreen**

Create `rescue/tui/screens/findings.py`:

```python
"""Findings screen — shows every finding for a single module, color coded by
severity, with a button to move to fix selection."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from rescue.models import CheckResult, RiskLevel
from rescue.module_base import ModuleBase
from rescue.tui.formatting import format_finding_line


class FindingsScreen(Screen):
    """Displays findings for one module."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, mod: ModuleBase, check: CheckResult):
        super().__init__()
        self.mod = mod
        self.check = check

    def compose(self) -> ComposeResult:
        yield Header()
        if not self.check.has_issues:
            yield Static(f"{self.mod.name}: no issues found.", id="findings-empty")
        else:
            with VerticalScroll(id="findings-list"):
                for finding in self.check.findings:
                    yield Static(format_finding_line(finding), classes="finding-row")
            yield Button(
                f"Apply Fixes ({self.mod.risk_level.value})",
                id="apply-fixes",
                variant="primary",
            )
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply-fixes":
            self.run_worker(self.start_fix_flow())

    async def start_fix_flow(self) -> None:
        from rescue.tui.screens.confirm import ConfirmScreen

        if self.mod.risk_level != RiskLevel.SAFE:
            message = (
                f"'{self.mod.name}' applies {self.mod.risk_level.value} changes. "
                f"Are you sure you want to proceed?"
            )
            confirmed = await self.app.push_screen_wait(ConfirmScreen(message))
            if not confirmed:
                return

        from rescue.tui.screens.fix_progress import FixProgressScreen

        self.app.push_screen(FixProgressScreen(self.mod, self.check))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_findings_screen.py -v`
Expected: Both tests PASS (the `FixProgressScreen`/`ConfirmScreen` imports inside `start_fix_flow` are never reached because neither test presses the `apply-fixes` button)

- [ ] **Step 5: Commit**

```bash
git add rescue/tui/screens/findings.py tests/tui/test_findings_screen.py
git commit -m "feat: add TUI findings screen with severity-coded finding list"
```

---

### Task 6: Fix Progress & Fix Result Screens

**Files:**
- Create: `rescue/tui/screens/fix_progress.py`
- Create: `rescue/tui/screens/fix_result.py`
- Test: `tests/tui/test_fix_progress_screen.py`
- Test: `tests/tui/test_fix_result_screen.py`

**Interfaces:**
- Consumes:
  - `CheckResult`, `FixResult`, `Mode` from `rescue.models`, `ModuleBase` from `rescue.module_base`
  - `GuidePlaceholderScreen` from `rescue.tui.screens.guide_placeholder` (Task 2, lazy import)
- Produces:
  - `FixProgressScreen(mod: ModuleBase, check: CheckResult)` — `textual.screen.Screen` in `rescue.tui.screens.fix_progress`. On mount, runs `mod.fix(check, Mode.MANUAL)` in a background thread, then calls `self.app.switch_screen(FixResultScreen(mod, check, fix_result))`.
  - `FixResultScreen(mod: ModuleBase, check: CheckResult, fix: FixResult)` — `textual.screen.Screen` in `rescue.tui.screens.fix_result`. Lists each `Action` (green `OK` / red `FAILED`). Has a `View Guide (coming soon)` button (`id="view-guide"`, pushes `GuidePlaceholderScreen(mod)`) and a `Back to Categories` button (`id="back-to-categories"`, calls `self.app.pop_screen_to_categories()` — provided by `RescueApp` in Task 8; test hosts provide their own stub).
  - `format_action_line(action: Action) -> str` module-level helper in `rescue.tui.screens.fix_result`

FixResultScreen has no dependency on FixProgressScreen (it just displays an already-computed `FixResult`), so it is built and tested first. FixProgressScreen is built second, since its test needs `FixResultScreen` to already exist to assert the screen it switches to.

- [ ] **Step 1: Write failing test for FixResultScreen**

Create `tests/tui/test_fix_result_screen.py`:

```python
from textual.app import App
from textual.widgets import Static

from rescue.models import Action, CheckResult, FixResult, Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.tui.screens.fix_result import FixResultScreen, format_action_line
from rescue.tui.screens.guide_placeholder import GuidePlaceholderScreen


class SomeModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def _make_fix(success: bool):
    return FixResult(
        module_name="disk_space",
        actions=[
            Action(
                title="Reported disk usage",
                description="Informational",
                risk_level=RiskLevel.SAFE,
                success=success,
                error=None if success else "boom",
            )
        ],
    )


def test_format_action_line_success():
    fix = _make_fix(True)
    line = format_action_line(fix.actions[0])
    assert "OK" in line
    assert "[green]" in line


def test_format_action_line_failure():
    fix = _make_fix(False)
    line = format_action_line(fix.actions[0])
    assert "FAILED" in line
    assert "boom" in line
    assert "[red]" in line


class FixResultHostApp(App):
    def __init__(self, mod, check, fix):
        super().__init__()
        self.mod = mod
        self.check = check
        self.fix = fix
        self.popped_to_categories = False

    def on_mount(self) -> None:
        self.push_screen(FixResultScreen(self.mod, self.check, self.fix))

    def pop_screen_to_categories(self) -> None:
        self.popped_to_categories = True


async def test_view_guide_button_pushes_placeholder_screen():
    app = FixResultHostApp(SomeModule(), CheckResult(module_name="disk_space"), _make_fix(True))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#view-guide")
        await pilot.pause()
        assert isinstance(app.screen, GuidePlaceholderScreen)


async def test_back_to_categories_button_calls_app_hook():
    app = FixResultHostApp(SomeModule(), CheckResult(module_name="disk_space"), _make_fix(True))
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#back-to-categories")
        await pilot.pause()
        assert app.popped_to_categories is True
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_fix_result_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.fix_result'`

- [ ] **Step 3: Implement FixResultScreen**

Create `rescue/tui/screens/fix_result.py`:

```python
"""Fix result screen — shows what actions were taken and whether they
succeeded, plus a hook into the (future) guide/walkthrough system."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from rescue.models import Action, CheckResult, FixResult
from rescue.module_base import ModuleBase


def format_action_line(action: Action) -> str:
    if action.success:
        return f"[green]OK[/green] {action.title} — {action.description}"
    return f"[red]FAILED[/red] {action.title} — {action.error or 'unknown error'}"


class FixResultScreen(Screen):
    """Displays the outcome of running a module's fix()."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, mod: ModuleBase, check: CheckResult, fix: FixResult):
        super().__init__()
        self.mod = mod
        self.check = check
        self.fix = fix

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="fix-result-list"):
            if self.fix.all_succeeded:
                yield Static(f"All {len(self.fix.actions)} action(s) succeeded.", id="fix-result-summary")
            else:
                yield Static("Some actions failed.", id="fix-result-summary")
            for action in self.fix.actions:
                yield Static(format_action_line(action), classes="action-row")
        yield Button("View Guide (coming soon)", id="view-guide")
        yield Button("Back to Categories", id="back-to-categories", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "view-guide":
            from rescue.tui.screens.guide_placeholder import GuidePlaceholderScreen

            self.app.push_screen(GuidePlaceholderScreen(self.mod))
        elif event.button.id == "back-to-categories":
            self.app.pop_screen_to_categories()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_fix_result_screen.py -v`
Expected: All 4 tests PASS

- [ ] **Step 5: Write failing test for FixProgressScreen**

Create `tests/tui/test_fix_progress_screen.py`:

```python
from textual.app import App

from rescue.models import Action, CheckResult, FixResult, Mode, Platform, RiskLevel
from rescue.module_base import ModuleBase
from rescue.tui.screens.fix_progress import FixProgressScreen
from rescue.tui.screens.fix_result import FixResultScreen


class FixableModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]
    risk_level = RiskLevel.SAFE

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        assert mode == Mode.MANUAL
        return FixResult(
            module_name=self.name,
            actions=[
                Action(
                    title="Reported disk usage",
                    description="Informational",
                    risk_level=RiskLevel.SAFE,
                    success=True,
                )
            ],
        )


class FixProgressHostApp(App):
    def __init__(self, mod, check):
        super().__init__()
        self.mod = mod
        self.check = check

    def on_mount(self) -> None:
        self.push_screen(FixProgressScreen(self.mod, self.check))


async def test_fix_progress_runs_fix_and_switches_to_result_screen():
    check = CheckResult(module_name="disk_space")
    app = FixProgressHostApp(FixableModule(), check)
    async with app.run_test() as pilot:
        for _ in range(20):
            await pilot.pause(0.05)
            if isinstance(app.screen, FixResultScreen):
                break
        assert isinstance(app.screen, FixResultScreen)
        assert app.screen.fix.all_succeeded
        assert app.screen.fix.actions[0].title == "Reported disk usage"
```

- [ ] **Step 6: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_fix_progress_screen.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.screens.fix_progress'`

- [ ] **Step 7: Implement FixProgressScreen**

Create `rescue/tui/screens/fix_progress.py`:

```python
"""Fix progress screen — runs a module's fix() in a background thread so the
UI stays responsive, then shows the result."""

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static

from rescue.models import CheckResult, FixResult, Mode
from rescue.module_base import ModuleBase


class FixProgressScreen(Screen):
    """Shown while a module's fix() is running."""

    def __init__(self, mod: ModuleBase, check: CheckResult):
        super().__init__()
        self.mod = mod
        self.check = check

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static(f"Applying fixes for {self.mod.name}…", id="fix-status"),
            ProgressBar(show_eta=False, id="fix-progress"),
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#fix-progress", ProgressBar).update(total=None)
        self.run_fix()

    @work(thread=True)
    def run_fix(self) -> None:
        fix_result = self.mod.fix(self.check, Mode.MANUAL)
        self.app.call_from_thread(self.on_fix_complete, fix_result)

    def on_fix_complete(self, fix_result: FixResult) -> None:
        from rescue.tui.screens.fix_result import FixResultScreen

        self.app.switch_screen(FixResultScreen(self.mod, self.check, fix_result))
```

- [ ] **Step 8: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_fix_progress_screen.py -v`
Expected: PASS

- [ ] **Step 9: Run all Task 6 tests together**

Run: `python -m pytest tests/tui/test_fix_progress_screen.py tests/tui/test_fix_result_screen.py -v`
Expected: All 5 tests PASS

- [ ] **Step 10: Commit**

```bash
git add rescue/tui/screens/fix_progress.py rescue/tui/screens/fix_result.py tests/tui/test_fix_progress_screen.py tests/tui/test_fix_result_screen.py
git commit -m "feat: add TUI fix progress and fix result screens"
```

---

### Task 7: RescueApp — Wiring All Screens Together

**Files:**
- Create: `rescue/tui/app.py`
- Create: `rescue/tui/app.tcss`
- Test: `tests/tui/test_app.py`

**Interfaces:**
- Consumes:
  - `Orchestrator(modules_dir: Path)` from `rescue.orchestrator`
  - `CheckResult` from `rescue.models`, `ModuleBase` from `rescue.module_base`
  - `LoadingScreen(orchestrator)` from `rescue.tui.screens.loading` (Task 3)
  - `CategoryMenuScreen(results)` from `rescue.tui.screens.categories` (Task 4)
- Produces:
  - `RescueApp(modules_dir: Path)` — `textual.app.App` in `rescue.tui.app`. `CSS_PATH` points at `rescue/tui/app.tcss`. On mount, pushes `LoadingScreen(self.orchestrator)`. Implements:
    - `on_checks_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None` — replaces the loading screen with `CategoryMenuScreen(results)` via `self.switch_screen(...)`
    - `pop_screen_to_categories(self) -> None` — pops screens until the category menu (index 1) is on top
  - `run_tui(modules_dir: Path) -> None` — module-level function in `rescue.tui.app` that constructs and runs a `RescueApp`

- [ ] **Step 1: Create the CSS file (required before the app can compose without erroring)**

Create `rescue/tui/app.tcss`:

```css
#loading-container {
    align: center middle;
    height: 100%;
}

#loading-progress {
    width: 60%;
}

#findings-list {
    height: 1fr;
    border: solid $primary;
    padding: 1;
}

.finding-row {
    padding: 0 1;
}

#fix-result-list {
    height: 1fr;
    border: solid $primary;
    padding: 1;
}

.action-row {
    padding: 0 1;
}
```

- [ ] **Step 2: Write failing end-to-end test for RescueApp**

Create `tests/tui/test_app.py`:

```python
from pathlib import Path
from unittest.mock import patch

from textual.widgets import OptionList

from rescue.models import DiskInfo, Platform, SystemProfile
from rescue.tui.app import RescueApp
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.findings import FindingsScreen
from rescue.tui.screens.fix_result import FixResultScreen
from rescue.tui.screens.modules import ModuleListScreen


def _profile(used_pct: float) -> SystemProfile:
    total = 500 * 1024**3
    used = int(total * used_pct)
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
                device="/dev/disk1",
                mount_point="/",
                total_bytes=total,
                used_bytes=used,
                free_bytes=total - used,
                filesystem="apfs",
            )
        ],
    )


async def test_full_flow_category_to_fix_result():
    """End-to-end: loading -> categories -> modules -> findings -> fix ->
    result -> back to categories, using the real disk_space module shipped
    in modules/performance/disk_space, with a mocked-full-disk profile so it
    reliably produces a finding."""
    modules_dir = Path(__file__).parent.parent.parent / "modules"

    with patch("rescue.orchestrator.gather_profile", return_value=_profile(0.85)):
        app = RescueApp(modules_dir=modules_dir)
        async with app.run_test() as pilot:
            for _ in range(20):
                await pilot.pause(0.05)
                if isinstance(app.screen, CategoryMenuScreen):
                    break
            assert isinstance(app.screen, CategoryMenuScreen)

            category_list = app.screen.query_one("#category-list", OptionList)
            assert category_list.get_option_at_index(0).id == "performance"
            category_list.action_select()
            await pilot.pause()
            assert isinstance(app.screen, ModuleListScreen)

            module_list = app.screen.query_one("#module-list", OptionList)
            assert module_list.get_option_at_index(0).id == "disk_space"
            module_list.action_select()
            await pilot.pause()
            assert isinstance(app.screen, FindingsScreen)

            await pilot.click("#apply-fixes")
            for _ in range(20):
                await pilot.pause(0.05)
                if isinstance(app.screen, FixResultScreen):
                    break
            assert isinstance(app.screen, FixResultScreen)
            assert app.screen.fix.all_succeeded

            await pilot.click("#back-to-categories")
            await pilot.pause()
            assert isinstance(app.screen, CategoryMenuScreen)
```

- [ ] **Step 3: Run test to verify it fails**

Run: `python -m pytest tests/tui/test_app.py -v`
Expected: FAIL — `ModuleNotFoundError: No module named 'rescue.tui.app'`

- [ ] **Step 4: Implement RescueApp**

Create `rescue/tui/app.py`:

```python
"""The interactive TUI entry point. Launched by `rescue` with no subcommand."""

from pathlib import Path

from textual.app import App

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.loading import LoadingScreen

_CSS_PATH = Path(__file__).parent / "app.tcss"


class RescueApp(App):
    """Multiverse Device Rescue interactive TUI."""

    CSS_PATH = _CSS_PATH
    TITLE = "Multiverse Device Rescue"
    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self, modules_dir: Path):
        super().__init__()
        self.modules_dir = modules_dir
        self.orchestrator = Orchestrator(modules_dir=modules_dir)

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen(self.orchestrator))

    def on_checks_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None:
        """Called by LoadingScreen once the orchestrator has finished running
        checks. Replaces the loading screen with the category menu."""
        self.switch_screen(CategoryMenuScreen(results))

    def pop_screen_to_categories(self) -> None:
        """Pop screens until the category menu (index 1, just above the
        default screen) is on top."""
        while len(self.screen_stack) > 2:
            self.pop_screen()


def run_tui(modules_dir: Path) -> None:
    app = RescueApp(modules_dir=modules_dir)
    app.run()
```

- [ ] **Step 5: Run test to verify it passes**

Run: `python -m pytest tests/tui/test_app.py -v`
Expected: PASS

- [ ] **Step 6: Run the entire TUI test suite**

Run: `python -m pytest tests/tui/ -v`
Expected: All tests from Tasks 1–7 PASS

- [ ] **Step 7: Commit**

```bash
git add rescue/tui/app.py rescue/tui/app.tcss tests/tui/test_app.py
git commit -m "feat: wire TUI screens together into RescueApp"
```

---

### Task 8: CLI Wiring — `rescue` With No Flags Launches the TUI

**Files:**
- Edit: `rescue/cli.py`
- Test: `tests/test_cli.py`

**Interfaces:**
- Consumes: `run_tui(modules_dir: Path) -> None` from `rescue.tui.app` (Task 7)
- Produces: modifies the existing `main()` Click group in `rescue.cli` so that invoking `rescue` with no subcommand and without `--auto` calls `run_tui(_get_modules_dir())` instead of printing help text

- [ ] **Step 1: Write failing test for the new bare-invocation behavior**

Edit `tests/test_cli.py` — add this test (append to the file; it uses the same imports already present in that file):

```python
def test_bare_invocation_launches_tui():
    with patch("rescue.cli.run_tui") as mock_run_tui:
        runner = CliRunner()
        result = runner.invoke(main, [])

    assert result.exit_code == 0
    mock_run_tui.assert_called_once()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli.py::test_bare_invocation_launches_tui -v`
Expected: FAIL — `AttributeError: <module 'rescue.cli'> does not have the attribute 'run_tui'` (patch target doesn't exist yet)

- [ ] **Step 3: Wire `run_tui` into the CLI**

Edit `rescue/cli.py`. Add a top-level import of `run_tui` and change the `main` group so the no-subcommand branch launches the TUI instead of printing help. A top-level import (not a lazy one inside the function) is required here: `unittest.mock.patch("rescue.cli.run_tui")` needs `run_tui` to already exist as an attribute of the `rescue.cli` module at patch time, which only happens if the `import` runs at module load, not inside `main()`.

Add this import alongside the existing ones at the top of `rescue/cli.py`:

```python
from rescue.tui.app import run_tui
```

So the full import block at the top of the file reads:

```python
from pathlib import Path

import click

import rescue
from rescue.models import Mode, RiskLevel
from rescue.orchestrator import Orchestrator
from rescue.profiler.base import gather_profile
from rescue.registry import discover_modules
from rescue.tui.app import run_tui
```

Then change the body of `main()` from:

```python
@click.group(invoke_without_command=True)
@click.option("--auto", is_flag=True, help="Run all checks and apply safe fixes automatically.")
@click.pass_context
def main(ctx, auto):
    """Multiverse Device Rescue — system diagnostic and repair toolkit."""
    if auto:
        _run_auto()
    elif ctx.invoked_subcommand is None:
        click.echo(ctx.get_help())
```

to:

```python
@click.group(invoke_without_command=True)
@click.option("--auto", is_flag=True, help="Run all checks and apply safe fixes automatically.")
@click.pass_context
def main(ctx, auto):
    """Multiverse Device Rescue — system diagnostic and repair toolkit."""
    if auto:
        _run_auto()
    elif ctx.invoked_subcommand is None:
        run_tui(_get_modules_dir())
```

Everything else in `rescue/cli.py` (the `version` and `run` commands, `_run_auto`, `_get_modules_dir`) is unchanged.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/test_cli.py -v`
Expected: All tests PASS, including the new `test_bare_invocation_launches_tui`

- [ ] **Step 5: Run the full project test suite**

Run: `python -m pytest tests/ -v`
Expected: All tests PASS (models, profiler, module_base, registry, orchestrator, cli, disk_space module, and every `tests/tui/` test)

- [ ] **Step 6: Smoke test the TUI manually**

Run:
```bash
python -m rescue.cli
```
Expected: The terminal switches to the Textual TUI, briefly shows "Profiling system and running checks…" with an indeterminate progress bar, then shows a category menu (at least "performance", since `disk_space` is the only module currently shipped). Press `q` to quit.

- [ ] **Step 7: Commit**

```bash
git add rescue/cli.py tests/test_cli.py
git commit -m "feat: launch interactive TUI when rescue is invoked with no subcommand"
```

---

## Future Plans

- **Plan 3: Profile System & Guide Engine** — replaces `GuidePlaceholderScreen` with real markdown-guide-driven walkthrough rendering, YAML threat-model profiles, and session progress persistence
- **Plan 4: Secure Update System** — signed bundle format, threshold signing, `rescue update` command
- **Plan 5: AI Layer** — diagnostic explainer, profile recommender, walkthrough copilot; likely surfaces as a `--copilot` toggle and an additional TUI panel/screen
- **Plan 6+: Module Packs** — more modules across bloatware, performance, integrity, security, and privacy categories, which the category/module screens built here will display without any TUI code changes
