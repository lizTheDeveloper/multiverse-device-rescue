# Finding-Linked Remediation Walkthroughs Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Give each scan finding a stable code that opens a matching in-tool remediation walkthrough, with a generated coverage catalog.

**Architecture:** Findings carry a `code`; walkthrough markdown files in `guides/remediation/` declare `remediates: [codes]`; a reverse index resolves code→walkthrough at startup; the TUI shows a per-finding "Walkthrough" button; a catalog generator + validation gate keep codes consistent.

**Tech Stack:** Python 3.14, dataclasses, `python-frontmatter`, Click (CLI), Textual (TUI), pytest.

## Global Constraints

- New `Finding.code` and `ModuleBase.emits_codes` MUST default to `None`/`[]` (backward compatible; unmigrated modules unaffected).
- Code scheme: `<category>.<module>.<slug>`, lowercase `snake_case` slug.
- Walkthroughs reuse the existing `## Step N: <title>` format and the existing guide parser — do NOT create a second step parser/model.
- One walkthrough may remediate many codes; a code resolves to exactly one walkthrough (first-wins, warn on conflict).
- Stateless v1: no `session`/`SessionState` persistence of walkthrough progress.
- Severity order (high→low): `CRITICAL` > `WARNING` > `INFO`.
- Content roots resolve via existing `rescue/cli.py` helpers (`_get_guides_dir()`), so everything works under PyInstaller bundles too.
- The `ai_worm_persistence` dead-man-switch ordering (disable `com.user.gh-token-monitor` BEFORE any other persistence removal) MUST be preserved verbatim in its walkthrough.

---

### Task 1: `Finding.code` field

**Files:**
- Modify: `rescue/models.py` (the `Finding` dataclass, ~line 86)
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `Finding(..., code: str | None = None)` — new optional field.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_models.py`:

```python
def test_finding_code_defaults_to_none():
    from rescue.models import Finding, Severity
    f = Finding(title="t", description="d", severity=Severity.WARNING, category="security")
    assert f.code is None


def test_finding_code_roundtrips():
    from rescue.models import Finding, Severity
    f = Finding(title="t", description="d", severity=Severity.CRITICAL,
                category="security", code="security.ssh_key_audit.world_readable_key")
    assert f.code == "security.ssh_key_audit.world_readable_key"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -k finding_code -v`
Expected: FAIL (`TypeError: ... unexpected keyword argument 'code'`)

- [ ] **Step 3: Add the field**

In `rescue/models.py`, in the `Finding` dataclass, after the `collected_at` field, add:

```python
    # Stable finding-type code linking this finding to a remediation
    # walkthrough. Scheme: "<category>.<module>.<slug>". None = no walkthrough.
    code: str | None = None
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -k finding_code -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/models.py tests/test_models.py
git commit -m "feat: add optional Finding.code for remediation linkage"
```

---

### Task 2: `ModuleBase.emits_codes`

**Files:**
- Modify: `rescue/module_base.py` (class attributes, ~line 15-27)
- Test: `tests/test_models.py`

**Interfaces:**
- Produces: `ModuleBase.emits_codes: list[str] = []` — class attribute listing every code the module's `check()` can emit.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_models.py`:

```python
def test_modulebase_emits_codes_defaults_empty():
    from rescue.module_base import ModuleBase
    assert ModuleBase.emits_codes == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_models.py -k emits_codes -v`
Expected: FAIL (`AttributeError: type object 'ModuleBase' has no attribute 'emits_codes'`)

- [ ] **Step 3: Add the attribute**

In `rescue/module_base.py`, inside `class ModuleBase(ABC):`, after `depends_on: list[str] = []`, add:

```python
    # Every remediation code this module's check() can attach to a Finding.
    # Powers the coverage catalog and the validation gate. Default: none.
    emits_codes: list[str] = []
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_models.py -k emits_codes -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/module_base.py tests/test_models.py
git commit -m "feat: add ModuleBase.emits_codes declaration"
```

---

### Task 3: Generalize the guide parser for walkthroughs

**Files:**
- Modify: `rescue/guides.py` (`Guide` dataclass ~line 18-26; `parse_guide_markdown` ~line 29-55)
- Test: `tests/test_guides.py`

**Interfaces:**
- Consumes: existing `GuideStep`, `_split_steps`, `_STEP_PATTERN`.
- Produces: `Guide.profile: str | None`, `Guide.phase: int | None`, `Guide.remediates: list[str]`; `parse_guide_markdown` tolerates missing `profile`/`phase` and reads `remediates`.

- [ ] **Step 1: Write the failing test**

Add to `tests/test_guides.py`:

```python
def test_parse_walkthrough_without_profile_or_phase():
    from rescue.guides import parse_guide_markdown
    text = (
        "---\n"
        "title: \"Reset SSH keys\"\n"
        "estimated_time: \"15 minutes\"\n"
        "remediates:\n"
        "  - security.ssh_key_audit.world_readable_key\n"
        "automatable_steps: []\n"
        "human_only_steps: [1]\n"
        "---\n"
        "## Step 1: Do the thing\n\nBody text.\n"
    )
    g = parse_guide_markdown(text)
    assert g.profile is None
    assert g.phase is None
    assert g.remediates == ["security.ssh_key_audit.world_readable_key"]
    assert g.steps[0].title == "Do the thing"


def test_parse_profile_guide_still_works():
    from rescue.guides import parse_guide_markdown
    text = (
        "---\nprofile: p\nphase: 2\ntitle: t\nestimated_time: \"5 minutes\"\n"
        "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: x\n\nb\n"
    )
    g = parse_guide_markdown(text)
    assert g.profile == "p"
    assert g.phase == 2
    assert g.remediates == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_guides.py -k "walkthrough_without or profile_guide_still" -v`
Expected: FAIL (`KeyError: 'profile'` in `parse_guide_markdown`)

- [ ] **Step 3: Update `Guide` and the parser**

In `rescue/guides.py`, change the `Guide` dataclass fields for `profile` and `phase` and add `remediates`:

```python
@dataclass
class Guide:
    profile: str | None
    phase: int | None
    title: str
    estimated_time: str
    steps: list[GuideStep] = field(default_factory=list)
    automatable_steps: list[int] = field(default_factory=list)
    human_only_steps: list[int] = field(default_factory=list)
    remediates: list[str] = field(default_factory=list)
```

In `parse_guide_markdown`, replace the `return Guide(...)` construction so `profile`/`phase` use `.get` and `remediates` is read:

```python
    return Guide(
        profile=meta.get("profile"),
        phase=meta.get("phase"),
        title=meta.get("title", ""),
        estimated_time=meta.get("estimated_time", ""),
        steps=steps,
        automatable_steps=automatable_steps,
        human_only_steps=human_only_steps,
        remediates=list(meta.get("remediates", []) or []),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_guides.py -v`
Expected: PASS (both new tests and all existing guide tests)

- [ ] **Step 5: Commit**

```bash
git add rescue/guides.py tests/test_guides.py
git commit -m "feat: guide parser supports remediates + optional profile/phase"
```

---

### Task 4: Remediation reverse index

**Files:**
- Create: `rescue/remediation.py`
- Test: `tests/test_remediation.py`

**Interfaces:**
- Consumes: `rescue.guides.load_guide`, `Guide`.
- Produces:
  - `load_remediation_walkthroughs(guides_dir: Path) -> dict[str, Guide]`
  - `walkthrough_for(index: dict[str, Guide], code: str | None) -> Guide | None`

- [ ] **Step 1: Write the failing test**

Create `tests/test_remediation.py`:

```python
from pathlib import Path

from rescue.remediation import load_remediation_walkthroughs, walkthrough_for


def _write(dir: Path, name: str, codes: list[str]) -> None:
    body = (
        "---\ntitle: \"" + name + "\"\nestimated_time: \"5 minutes\"\n"
        "remediates:\n" + "".join(f"  - {c}\n" for c in codes) +
        "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: x\n\nb\n"
    )
    (dir / (name + ".md")).write_text(body)


def test_missing_dir_returns_empty(tmp_path):
    assert load_remediation_walkthroughs(tmp_path / "nope") == {}


def test_index_maps_codes_to_walkthrough(tmp_path):
    rem = tmp_path / "remediation"; rem.mkdir()
    _write(rem, "reset_ssh", ["security.ssh_key_audit.world_readable_key"])
    index = load_remediation_walkthroughs(rem)
    g = walkthrough_for(index, "security.ssh_key_audit.world_readable_key")
    assert g is not None and g.title == "reset_ssh"
    assert walkthrough_for(index, None) is None
    assert walkthrough_for(index, "security.unknown.code") is None


def test_conflict_first_wins(tmp_path):
    rem = tmp_path / "remediation"; rem.mkdir()
    _write(rem, "a_first", ["security.x.dup"])
    _write(rem, "b_second", ["security.x.dup"])
    index = load_remediation_walkthroughs(rem)
    # sorted filenames: a_first wins
    assert walkthrough_for(index, "security.x.dup").title == "a_first"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_remediation.py -v`
Expected: FAIL (`ModuleNotFoundError: No module named 'rescue.remediation'`)

- [ ] **Step 3: Implement `rescue/remediation.py`**

```python
"""Remediation walkthrough loading and the code->walkthrough reverse index.

Walkthroughs live in guides/remediation/*.md and declare which finding codes
they remediate via a front-matter `remediates: [codes]` list. This module
builds a reverse index {code: Guide} at startup, first-wins on conflict.
"""

import logging
from pathlib import Path

from rescue.guides import Guide, load_guide

logger = logging.getLogger(__name__)


def load_remediation_walkthroughs(remediation_dir: Path) -> dict[str, Guide]:
    """Scan a directory of walkthrough markdown files, return {code: Guide}.

    First-wins on a code claimed by two files (sorted by filename); a warning
    is logged. Files with no `remediates` entries are skipped with a warning.
    A missing directory yields an empty index (no error).
    """
    index: dict[str, Guide] = {}
    if not remediation_dir.is_dir():
        return index
    for path in sorted(remediation_dir.glob("*.md")):
        try:
            guide = load_guide(path)
        except Exception as e:  # malformed front-matter etc.
            logger.warning("Skipping unparseable walkthrough %s: %s", path.name, e)
            continue
        if not guide.remediates:
            logger.warning("Walkthrough %s declares no `remediates` codes", path.name)
            continue
        for code in guide.remediates:
            if code in index:
                logger.warning(
                    "Code %s already remediated by an earlier walkthrough; "
                    "ignoring duplicate in %s", code, path.name)
                continue
            index[code] = guide
    return index


def walkthrough_for(index: dict[str, Guide], code: str | None) -> Guide | None:
    """Resolve a finding code to its walkthrough, or None."""
    if not code:
        return None
    return index.get(code)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_remediation.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/remediation.py tests/test_remediation.py
git commit -m "feat: remediation walkthrough reverse index"
```

---

### Task 5: Load the index into the TUI app

**Files:**
- Modify: `rescue/tui/app.py` (`RescueApp.__init__`, `run_tui`)
- Modify: `rescue/cli.py` (the `run_tui(...)` call ~line 95)
- Test: `tests/tui/test_app_remediation_index.py`

**Interfaces:**
- Consumes: `load_remediation_walkthroughs`, `_get_guides_dir`.
- Produces: `RescueApp(modules_dir, guides_dir=None)` with attribute `self.remediation_index: dict[str, Guide]`; `run_tui(modules_dir, guides_dir=None)`.

- [ ] **Step 1: Write the failing test**

Create `tests/tui/test_app_remediation_index.py`:

```python
from pathlib import Path

from rescue.tui.app import RescueApp


def test_app_loads_remediation_index(tmp_path):
    rem = tmp_path / "remediation"; rem.mkdir()
    (rem / "w.md").write_text(
        "---\ntitle: t\nestimated_time: \"5 minutes\"\n"
        "remediates:\n  - security.x.y\n"
        "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: a\n\nb\n"
    )
    app = RescueApp(modules_dir=tmp_path / "modules", guides_dir=tmp_path)
    assert "security.x.y" in app.remediation_index


def test_app_missing_guides_dir_is_empty_index(tmp_path):
    app = RescueApp(modules_dir=tmp_path / "modules", guides_dir=None)
    assert app.remediation_index == {}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tui/test_app_remediation_index.py -v`
Expected: FAIL (`TypeError: __init__() got an unexpected keyword argument 'guides_dir'`)

- [ ] **Step 3: Wire the index into `RescueApp`**

In `rescue/tui/app.py`, update imports and `__init__`, and `run_tui`:

```python
from rescue.remediation import load_remediation_walkthroughs
```

```python
    def __init__(self, modules_dir: Path, guides_dir: Path | None = None):
        super().__init__()
        self.modules_dir = modules_dir
        self.orchestrator = Orchestrator(modules_dir=modules_dir)
        self.remediation_index = (
            load_remediation_walkthroughs(guides_dir / "remediation")
            if guides_dir is not None
            else {}
        )
```

```python
def run_tui(modules_dir: Path, guides_dir: Path | None = None) -> None:
    app = RescueApp(modules_dir=modules_dir, guides_dir=guides_dir)
    app.run()
```

In `rescue/cli.py`, update the no-subcommand launch (~line 95) to pass the guides dir:

```python
        run_tui(_get_modules_dir(), _get_guides_dir())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/tui/test_app_remediation_index.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/tui/app.py rescue/cli.py tests/tui/test_app_remediation_index.py
git commit -m "feat: load remediation index into the TUI app"
```

---

### Task 6: `WalkthroughScreen`

**Files:**
- Create: `rescue/tui/screens/walkthrough.py`
- Test: `tests/tui/test_walkthrough_screen.py`

**Interfaces:**
- Consumes: `rescue.guides.Guide`.
- Produces: `WalkthroughScreen(guide: Guide)` — a Textual `Screen` rendering title, estimated time, and steps; `escape` pops.

- [ ] **Step 1: Write the failing test**

Create `tests/tui/test_walkthrough_screen.py`:

```python
import pytest

from rescue.guides import parse_guide_markdown
from rescue.tui.screens.walkthrough import WalkthroughScreen

WT = parse_guide_markdown(
    "---\ntitle: \"Reset SSH keys\"\nestimated_time: \"15 minutes\"\n"
    "remediates:\n  - security.ssh_key_audit.world_readable_key\n"
    "automatable_steps: []\nhuman_only_steps: [1]\n---\n"
    "## Step 1: Revoke the key\n\nRemove the world-readable private key.\n"
)


@pytest.mark.asyncio
async def test_walkthrough_screen_renders_title_and_step():
    from textual.app import App

    class Host(App):
        def on_mount(self):
            self.push_screen(WalkthroughScreen(WT))

    app = Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        text = app.screen.query_one("#walkthrough-body").render()
        rendered = str(text)
        assert "Reset SSH keys" in rendered
        assert "Revoke the key" in rendered
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tui/test_walkthrough_screen.py -v`
Expected: FAIL (`ModuleNotFoundError: rescue.tui.screens.walkthrough`)

- [ ] **Step 3: Implement the screen**

```python
"""Walkthrough screen — renders a remediation walkthrough's steps. Stateless:
local `mark done` toggles only, nothing persisted."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from rescue.guides import Guide


def _render_walkthrough(guide: Guide) -> str:
    lines = [f"[b]{guide.title}[/b]"]
    if guide.estimated_time:
        lines.append(f"[dim]Estimated time: {guide.estimated_time}[/dim]")
    lines.append("")
    for step in guide.steps:
        marker = " [cyan](automatable)[/cyan]" if step.automatable else ""
        lines.append(f"[b]Step {step.number}: {step.title}[/b]{marker}")
        lines.append(step.body)
        lines.append("")
    return "\n".join(lines)


class WalkthroughScreen(Screen):
    """Displays one remediation walkthrough."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, guide: Guide):
        super().__init__()
        self.guide = guide

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="walkthrough-list"):
            yield Static(_render_walkthrough(self.guide), id="walkthrough-body")
        yield Footer()
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/tui/test_walkthrough_screen.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/tui/screens/walkthrough.py tests/tui/test_walkthrough_screen.py
git commit -m "feat: WalkthroughScreen renders remediation steps"
```

---

### Task 7: Per-finding "Walkthrough" button on FindingsScreen

**Files:**
- Modify: `rescue/tui/screens/findings.py`
- Test: `tests/tui/test_findings_walkthrough_button.py`

**Interfaces:**
- Consumes: `self.app.remediation_index`, `walkthrough_for`, `WalkthroughScreen`.
- Produces: FindingsScreen renders a `Button(id="wt-<i>")` under each finding whose `code` resolves; pressing it pushes `WalkthroughScreen`.

- [ ] **Step 1: Write the failing test**

Create `tests/tui/test_findings_walkthrough_button.py`:

```python
import pytest

from rescue.guides import parse_guide_markdown
from rescue.models import CheckResult, Finding, RiskLevel, Severity
from rescue.module_base import ModuleBase


class _Mod(ModuleBase):
    name = "ssh_key_audit"
    category = "security"
    platforms = []
    risk_level = RiskLevel.SAFE
    def check(self, profile): ...
    def fix(self, findings, mode): ...


WT = parse_guide_markdown(
    "---\ntitle: t\nestimated_time: \"5 minutes\"\n"
    "remediates:\n  - security.ssh_key_audit.world_readable_key\n"
    "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: a\n\nb\n"
)


@pytest.mark.asyncio
async def test_finding_with_code_shows_walkthrough_button():
    from textual.app import App
    from rescue.tui.screens.findings import FindingsScreen
    from rescue.tui.screens.walkthrough import WalkthroughScreen

    check = CheckResult(module_name="ssh_key_audit", findings=[
        Finding(title="Key", description="d", severity=Severity.CRITICAL,
                category="security",
                code="security.ssh_key_audit.world_readable_key"),
        Finding(title="NoCode", description="d", severity=Severity.INFO,
                category="security"),
    ])

    class Host(App):
        remediation_index = {"security.ssh_key_audit.world_readable_key": WT}
        def on_mount(self):
            self.push_screen(FindingsScreen(_Mod(), check))

    app = Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        buttons = app.screen.query("Button")
        ids = [b.id for b in buttons]
        assert "wt-0" in ids      # first finding has a code
        assert "wt-1" not in ids  # second finding has no code
        await pilot.click("#wt-0")
        await pilot.pause()
        assert isinstance(app.screen, WalkthroughScreen)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/tui/test_findings_walkthrough_button.py -v`
Expected: FAIL (no `wt-0` button exists)

- [ ] **Step 3: Add per-finding buttons + handler**

In `rescue/tui/screens/findings.py`, update `compose` so each finding renders its row plus a walkthrough button when resolvable, and handle the press. Replace the findings-list block and `on_button_pressed`:

```python
from rescue.remediation import walkthrough_for
```

```python
            with VerticalScroll(id="findings-list"):
                self._wt_by_button: dict[str, "object"] = {}
                for i, finding in enumerate(self.check.findings):
                    yield Static(format_finding_line(finding), classes="finding-row")
                    guide = walkthrough_for(
                        getattr(self.app, "remediation_index", {}), finding.code)
                    if guide is not None:
                        bid = f"wt-{i}"
                        self._wt_by_button[bid] = guide
                        yield Button("Walkthrough", id=bid)
            yield Button(
                f"Apply Fixes ({self.mod.risk_level.value})",
                id="apply-fixes",
                variant="primary",
            )
```

Extend `on_button_pressed` (keep the existing `apply-fixes` branch):

```python
    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply-fixes":
            self.run_worker(self.start_fix_flow())
        elif event.button.id in getattr(self, "_wt_by_button", {}):
            from rescue.tui.screens.walkthrough import WalkthroughScreen
            self.app.push_screen(WalkthroughScreen(self._wt_by_button[event.button.id]))
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/tui/test_findings_walkthrough_button.py -v`
Expected: PASS

- [ ] **Step 5: Commit**

```bash
git add rescue/tui/screens/findings.py tests/tui/test_findings_walkthrough_button.py
git commit -m "feat: per-finding Walkthrough button on FindingsScreen"
```

---

### Task 8: Replace the GuidePlaceholderScreen post-fix hook

**Files:**
- Modify: `rescue/tui/screens/fix_result.py` (`on_button_pressed`, ~line 63)
- Create: `rescue/tui/screens/_pick.py` (helper `highest_severity_walkthrough`)
- Test: `tests/tui/test_fix_result_walkthrough.py`, `tests/test_pick_walkthrough.py`

**Interfaces:**
- Consumes: `self.app.remediation_index`, `walkthrough_for`, `Severity`.
- Produces: `highest_severity_walkthrough(index, check) -> Guide | None`; the "View Guide" button opens that walkthrough, and is not shown when there is none.

- [ ] **Step 1: Write the failing test (pure helper first)**

Create `tests/test_pick_walkthrough.py`:

```python
from rescue.guides import parse_guide_markdown
from rescue.models import CheckResult, Finding, Severity
from rescue.tui.screens._pick import highest_severity_walkthrough

WT = parse_guide_markdown(
    "---\ntitle: t\nestimated_time: \"5m\"\nremediates:\n  - c.crit\n"
    "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: a\n\nb\n"
)


def test_picks_highest_severity_with_walkthrough():
    check = CheckResult(module_name="m", findings=[
        Finding(title="i", description="d", severity=Severity.INFO, category="s", code="c.info"),
        Finding(title="c", description="d", severity=Severity.CRITICAL, category="s", code="c.crit"),
    ])
    assert highest_severity_walkthrough({"c.crit": WT}, check) is WT


def test_none_when_no_coded_finding_has_walkthrough():
    check = CheckResult(module_name="m", findings=[
        Finding(title="i", description="d", severity=Severity.INFO, category="s"),
    ])
    assert highest_severity_walkthrough({"c.crit": WT}, check) is None
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_pick_walkthrough.py -v`
Expected: FAIL (`ModuleNotFoundError: rescue.tui.screens._pick`)

- [ ] **Step 3: Implement the helper**

Create `rescue/tui/screens/_pick.py`:

```python
"""Pick the walkthrough for the highest-severity coded finding in a check."""

from rescue.guides import Guide
from rescue.models import CheckResult, Severity
from rescue.remediation import walkthrough_for

_SEVERITY_ORDER = {Severity.CRITICAL: 3, Severity.WARNING: 2, Severity.INFO: 1}


def highest_severity_walkthrough(index: dict, check: CheckResult) -> Guide | None:
    best = None
    best_rank = 0
    for finding in check.findings:
        guide = walkthrough_for(index, finding.code)
        if guide is None:
            continue
        rank = _SEVERITY_ORDER.get(finding.severity, 0)
        if rank > best_rank:
            best, best_rank = guide, rank
    return best
```

- [ ] **Step 4: Run helper test**

Run: `pytest tests/test_pick_walkthrough.py -v`
Expected: PASS

- [ ] **Step 5: Write the fix_result screen test**

Create `tests/tui/test_fix_result_walkthrough.py`:

```python
import pytest

from rescue.guides import parse_guide_markdown
from rescue.models import Action, CheckResult, Finding, FixResult, RiskLevel, Severity
from rescue.module_base import ModuleBase

WT = parse_guide_markdown(
    "---\ntitle: t\nestimated_time: \"5m\"\nremediates:\n  - security.m.crit\n"
    "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: a\n\nb\n"
)


class _Mod(ModuleBase):
    name = "m"; category = "security"; platforms = []; risk_level = RiskLevel.SAFE
    def check(self, profile): ...
    def fix(self, findings, mode): ...


@pytest.mark.asyncio
async def test_view_guide_opens_walkthrough_when_available():
    from textual.app import App
    from rescue.tui.screens.fix_result import FixResultScreen
    from rescue.tui.screens.walkthrough import WalkthroughScreen

    check = CheckResult(module_name="m", findings=[
        Finding(title="c", description="d", severity=Severity.CRITICAL,
                category="security", code="security.m.crit")])
    fix = FixResult(module_name="m", actions=[])

    class Host(App):
        remediation_index = {"security.m.crit": WT}
        def on_mount(self):
            self.push_screen(FixResultScreen(_Mod(), check, fix))

    app = Host()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert "view-guide" in [b.id for b in app.screen.query("Button")]
        await pilot.click("#view-guide")
        await pilot.pause()
        assert isinstance(app.screen, WalkthroughScreen)
```

- [ ] **Step 6: Run it to verify it fails**

Run: `pytest tests/tui/test_fix_result_walkthrough.py -v`
Expected: FAIL (button still opens `GuidePlaceholderScreen`)

- [ ] **Step 7: Repoint the button**

In `rescue/tui/screens/fix_result.py`, in `compose`, replace the unconditional `View Guide (coming soon)` button with a conditional one:

```python
        from rescue.tui.screens._pick import highest_severity_walkthrough
        self._wt = highest_severity_walkthrough(
            getattr(self.app, "remediation_index", {}), self.check)
        if self._wt is not None:
            yield Button("View Walkthrough", id="view-guide")
        yield Button("Back to Categories", id="back-to-categories", variant="primary")
```

Replace the `view-guide` branch in `on_button_pressed`:

```python
        if event.button.id == "view-guide":
            from rescue.tui.screens.walkthrough import WalkthroughScreen
            self.app.push_screen(WalkthroughScreen(self._wt))
```

- [ ] **Step 8: Run both tests**

Run: `pytest tests/tui/test_fix_result_walkthrough.py tests/test_pick_walkthrough.py -v`
Expected: PASS

- [ ] **Step 9: Commit**

```bash
git add rescue/tui/screens/fix_result.py rescue/tui/screens/_pick.py tests/tui/test_fix_result_walkthrough.py tests/test_pick_walkthrough.py
git commit -m "feat: post-fix View Walkthrough replaces guide placeholder stub"
```

---

### Task 9: Coverage catalog generator + `remediation-catalog` subcommand

**Files:**
- Modify: `rescue/remediation.py` (add `build_catalog`, `render_catalog_markdown`)
- Modify: `rescue/cli.py` (add Click subcommand)
- Test: `tests/test_remediation_catalog.py`

**Interfaces:**
- Consumes: `discover_modules`, `load_remediation_walkthroughs`.
- Produces:
  - `build_catalog(modules, index) -> list[dict]` (rows: `code`, `module`, `walkthrough_title` or None)
  - `render_catalog_markdown(rows) -> str`

- [ ] **Step 1: Write the failing test**

Create `tests/test_remediation_catalog.py`:

```python
from rescue.module_base import ModuleBase
from rescue.remediation import build_catalog, render_catalog_markdown


class _Mod(ModuleBase):
    name = "ssh_key_audit"; category = "security"; platforms = []
    emits_codes = ["security.ssh_key_audit.world_readable_key",
                   "security.ssh_key_audit.no_passphrase"]
    def check(self, profile): ...
    def fix(self, findings, mode): ...


def test_build_catalog_marks_covered_and_gaps():
    index = {"security.ssh_key_audit.world_readable_key":
             type("G", (), {"title": "Reset SSH keys"})()}
    rows = build_catalog([_Mod()], index)
    by_code = {r["code"]: r for r in rows}
    assert by_code["security.ssh_key_audit.world_readable_key"]["walkthrough_title"] == "Reset SSH keys"
    assert by_code["security.ssh_key_audit.no_passphrase"]["walkthrough_title"] is None


def test_render_markdown_has_table_and_summary():
    rows = [{"code": "security.m.a", "module": "m", "walkthrough_title": "W"},
            {"code": "security.m.b", "module": "m", "walkthrough_title": None}]
    md = render_catalog_markdown(rows)
    assert "| Code | Module | Walkthrough |" in md
    assert "**gap**" in md
    assert "1 with walkthroughs" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `pytest tests/test_remediation_catalog.py -v`
Expected: FAIL (`ImportError: cannot import name 'build_catalog'`)

- [ ] **Step 3: Implement generator in `rescue/remediation.py`**

Append:

```python
def build_catalog(modules, index: dict[str, "Guide"]) -> list[dict]:
    """One row per declared code across all modules, sorted by code."""
    rows: list[dict] = []
    for mod in modules:
        for code in getattr(mod, "emits_codes", []):
            guide = index.get(code)
            rows.append({
                "code": code,
                "module": mod.name,
                "walkthrough_title": guide.title if guide is not None else None,
            })
    rows.sort(key=lambda r: r["code"])
    return rows


def render_catalog_markdown(rows: list[dict]) -> str:
    covered = sum(1 for r in rows if r["walkthrough_title"])
    lines = [
        "# Remediation Catalog",
        "",
        "> Generated by `rescue remediation-catalog`. Do not edit by hand.",
        "",
        f"{len(rows)} codes, {covered} with walkthroughs "
        f"({(100 * covered // len(rows)) if rows else 0}% covered).",
        "",
        "| Code | Module | Walkthrough |",
        "|---|---|---|",
    ]
    for r in rows:
        wt = r["walkthrough_title"] or "— **gap**"
        lines.append(f"| `{r['code']}` | {r['module']} | {wt} |")
    return "\n".join(lines) + "\n"
```

- [ ] **Step 4: Run test to verify it passes**

Run: `pytest tests/test_remediation_catalog.py -v`
Expected: PASS

- [ ] **Step 5: Add the Click subcommand**

In `rescue/cli.py`, after the `main` group is defined, add:

```python
@main.command("remediation-catalog")
def remediation_catalog():
    """Regenerate docs/REMEDIATION_CATALOG.md from modules + walkthroughs."""
    from rescue.registry import discover_modules
    from rescue.remediation import (
        build_catalog, load_remediation_walkthroughs, render_catalog_markdown)

    modules = discover_modules(_get_modules_dir())
    index = load_remediation_walkthroughs(_get_guides_dir() / "remediation")
    rows = build_catalog(modules, index)
    out = _project_root() / "docs" / "REMEDIATION_CATALOG.md"
    out.write_text(render_catalog_markdown(rows))
    click.echo(f"Wrote {out} ({len(rows)} codes)")
```

Ensure `import click` is present at the top of `cli.py` (it already is — the CLI uses Click).

- [ ] **Step 6: Generate the catalog and verify the command runs**

Run: `python -m rescue.cli remediation-catalog` (or `rescue remediation-catalog`)
Expected: prints `Wrote .../docs/REMEDIATION_CATALOG.md (N codes)`; file exists.

- [ ] **Step 7: Commit**

```bash
git add rescue/remediation.py rescue/cli.py tests/test_remediation_catalog.py docs/REMEDIATION_CATALOG.md
git commit -m "feat: remediation coverage catalog generator + CLI subcommand"
```

---

### Task 10: Whole-catalog validation gate

**Files:**
- Create: `tests/test_remediation_validation.py`

**Interfaces:**
- Consumes: `discover_modules(_get_modules_dir())`, `load_remediation_walkthroughs`, real shipped content.

- [ ] **Step 1: Write the validation tests**

Create `tests/test_remediation_validation.py`:

```python
from pathlib import Path

from rescue.cli import _get_guides_dir, _get_modules_dir
from rescue.guides import load_guide
from rescue.registry import discover_modules
from rescue.remediation import load_remediation_walkthroughs

REM_DIR = _get_guides_dir() / "remediation"


def test_every_remediates_code_is_declared_by_some_module():
    declared = set()
    for mod in discover_modules(_get_modules_dir()):
        declared.update(getattr(mod, "emits_codes", []))
    if not REM_DIR.is_dir():
        return
    for path in REM_DIR.glob("*.md"):
        for code in load_guide(path).remediates:
            assert code in declared, f"{path.name}: code {code} not in any emits_codes"


def test_no_two_walkthroughs_claim_the_same_code():
    if not REM_DIR.is_dir():
        return
    seen: dict[str, str] = {}
    for path in sorted(REM_DIR.glob("*.md")):
        for code in load_guide(path).remediates:
            assert code not in seen, f"{code} claimed by both {seen[code]} and {path.name}"
            seen[code] = path.name


def test_all_walkthroughs_parse_and_have_steps():
    if not REM_DIR.is_dir():
        return
    for path in REM_DIR.glob("*.md"):
        g = load_guide(path)
        assert g.remediates, f"{path.name} declares no remediates codes"
        assert g.steps, f"{path.name} has no steps"
```

- [ ] **Step 2: Run it (passes trivially until content exists)**

Run: `pytest tests/test_remediation_validation.py -v`
Expected: PASS (no `guides/remediation/` yet → early returns)

- [ ] **Step 3: Commit**

```bash
git add tests/test_remediation_validation.py
git commit -m "test: whole-catalog validation gate for remediation walkthroughs"
```

---

### Task 11: Starter content — `ai_worm_persistence` (worked example)

**Files:**
- Modify: `modules/security/ai_worm_persistence/__init__.py` (add `emits_codes`; set `code=` on each `Finding(...)`)
- Create: `guides/remediation/remove_miasma_persistence.md`
- Test: `tests/test_module_ai_worm_persistence.py` (assert emitted codes ⊆ `emits_codes`)
- Regenerate: `docs/REMEDIATION_CATALOG.md`

**Interfaces:**
- Consumes: `Finding.code`, `emits_codes`, walkthrough front-matter.

- [ ] **Step 1: Enumerate the module's finding types**

Read `modules/security/ai_worm_persistence/__init__.py`; list each distinct `Finding(...)` construction and assign a slug. Example set (verify against the actual code and adjust slugs to match real finding types):
- `security.ai_worm_persistence.known_malicious_launchagent`
- `security.ai_worm_persistence.deadman_switch_launchagent`
- `security.ai_worm_persistence.heuristic_persistence_artifact`
- `security.ai_worm_persistence.malicious_systemd_unit`

- [ ] **Step 2: Write the failing test**

Add to `tests/test_module_ai_worm_persistence.py`:

```python
def test_emitted_codes_are_declared():
    from modules.security.ai_worm_persistence import Module  # adjust to real class/factory
    mod = Module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    # Every declared code uses the correct namespace:
    assert all(c.startswith("security.ai_worm_persistence.") for c in declared)
```

(If the module exposes its instance differently, match the existing test file's construction pattern.)

- [ ] **Step 3: Run it to verify it fails**

Run: `pytest tests/test_module_ai_worm_persistence.py -k emitted_codes -v`
Expected: FAIL (`emits_codes` empty)

- [ ] **Step 4: Add `emits_codes` and `code=`**

In the module class, add the attribute:

```python
    emits_codes = [
        "security.ai_worm_persistence.known_malicious_launchagent",
        "security.ai_worm_persistence.deadman_switch_launchagent",
        "security.ai_worm_persistence.heuristic_persistence_artifact",
        "security.ai_worm_persistence.malicious_systemd_unit",
    ]
```

At each `Finding(...)` construction, add the matching `code=`. Example:

```python
Finding(
    title="Known malicious LaunchAgent: com.user.update-monitor",
    description="...",
    severity=Severity.CRITICAL,
    category="security",
    code="security.ai_worm_persistence.known_malicious_launchagent",
    data={...},
)
```

Use `deadman_switch_launchagent` specifically for the `com.user.gh-token-monitor` finding.

- [ ] **Step 5: Author the walkthrough**

Create `guides/remediation/remove_miasma_persistence.md`. Front-matter MUST list all four codes; **Step 1 MUST disable `com.user.gh-token-monitor` before any other removal** (dead-man switch):

```markdown
---
title: "Remove Miasma worm persistence safely"
estimated_time: "20 minutes"
platforms: [macos, linux]
remediates:
  - security.ai_worm_persistence.deadman_switch_launchagent
  - security.ai_worm_persistence.known_malicious_launchagent
  - security.ai_worm_persistence.heuristic_persistence_artifact
  - security.ai_worm_persistence.malicious_systemd_unit
automatable_steps: []
human_only_steps: [1, 2, 3, 4]
---

## Step 1: Neutralize the dead-man switch FIRST

The `com.user.gh-token-monitor` LaunchAgent runs `rm -rf ~/` if its stolen
GitHub token starts returning 4xx. Do NOT revoke the token or remove other
persistence yet. First disconnect from the network, then disable this agent
while it cannot detect revocation. [Author the exact, verified steps here.]

## Step 2: Remove the remaining known-malicious agents

[Verified removal steps for com.user.update-monitor and systemd equivalents.]

## Step 3: Investigate heuristic artifacts

[How to inspect `bun`-referencing background agents before deleting.]

## Step 4: Rotate credentials from a known-clean device

[Only after persistence is gone and you are offline-clean.]
```

> The prose in brackets is authored during execution against verified
> remediation steps — it is security-critical content, not code.

- [ ] **Step 6: Run module + validation tests**

Run: `pytest tests/test_module_ai_worm_persistence.py tests/test_remediation_validation.py -v`
Expected: PASS

- [ ] **Step 7: Regenerate the catalog**

Run: `python -m rescue.cli remediation-catalog`
Expected: `ai_worm_persistence` codes now show the walkthrough title.

- [ ] **Step 8: Commit**

```bash
git add modules/security/ai_worm_persistence/__init__.py guides/remediation/remove_miasma_persistence.md tests/test_module_ai_worm_persistence.py docs/REMEDIATION_CATALOG.md
git commit -m "feat: remediation codes + walkthrough for ai_worm_persistence"
```

---

### Task 12: Starter content — remaining `ai_worm_*` + `mvt_spyware_scan`

Repeat the Task 11 mechanical pattern for each module below. Each is its own
commit. For each: (a) read the module's `check()` and enumerate distinct
finding types; (b) add `emits_codes = [...]` with `security.<module>.<slug>`
codes; (c) set `code=` on every `Finding(...)`; (d) author
`guides/remediation/<slug>.md` with a `remediates:` list covering those codes
and real `## Step N:` content; (e) add the `test_emitted_codes_are_declared`
test mirroring Task 11 Step 2 (namespace prefix `security.<module>.`);
(f) `python -m rescue.cli remediation-catalog`; (g) commit.

Modules, in order:

- [ ] `ai_worm_filesystem` → `guides/remediation/clean_ai_worm_filesystem.md`
- [ ] `ai_worm_git_ssh` → `guides/remediation/secure_git_ssh_after_worm.md`
- [ ] `ai_worm_network` → `guides/remediation/cut_ai_worm_c2.md`
- [ ] `ai_worm_lateral` → `guides/remediation/contain_lateral_movement.md`
- [ ] `mvt_spyware_scan` → `guides/remediation/respond_to_mobile_spyware.md`

Commit message pattern per module:

```bash
git commit -m "feat: remediation codes + walkthrough for <module>"
```

---

### Task 13: Starter content — top-severity generic scans

Repeat the Task 11 pattern for these high-value generic scans, each its own
commit, each with the `test_emitted_codes_are_declared` test and a
catalog regeneration:

- [ ] `ssh_key_audit` → `guides/remediation/harden_ssh_keys.md`
- [ ] `launchd_persistence_audit` (and/or `launch_agent_audit`) → `guides/remediation/review_launch_persistence.md`
- [ ] `remote_login_check` (macOS) and `win_rdp_check` (Windows) → `guides/remediation/disable_unwanted_remote_access.md` (one walkthrough may `remediates:` both platforms' codes)
- [ ] `firewall_audit` → `guides/remediation/enable_and_tighten_firewall.md`

- [ ] **Final step: Regenerate catalog + full test run + commit**

```bash
python -m rescue.cli remediation-catalog
pytest -q
git add -A
git commit -m "feat: remediation walkthroughs for top-severity generic scans"
```

---

## Self-Review Notes

- Spec §1 Finding codes → Task 1. §2 emits_codes → Task 2. §3 walkthrough content + §4 parser → Task 3 + Tasks 11-13. §5 reverse index → Task 4, loaded in Task 5. §6 TUI → Tasks 6-8. §7 statelessness → Task 6 (no session writes). §8 catalog → Task 9; validation gate → Task 10. §9 starter content → Tasks 11-13.
- Types consistent across tasks: `load_remediation_walkthroughs(dir) -> dict[str, Guide]`, `walkthrough_for(index, code)`, `WalkthroughScreen(guide)`, `highest_severity_walkthrough(index, check)`, `build_catalog(modules, index)`, `render_catalog_markdown(rows)`.
- Task 11 Step 2/4 flag that the module's real class/construction and exact finding types must be matched against the actual file — the enumerated slugs are the expected shape, verified during execution.
