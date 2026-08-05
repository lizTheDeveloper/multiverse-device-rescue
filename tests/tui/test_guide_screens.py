"""Tests for the TUI guide flow that replaced the Plan-3 placeholder.

The behaviour that matters is persistence: a checklist someone works through
during a compromise recovery has to survive closing the app, has to agree with
what `rescue guide <profile>` shows, and has to allow un-ticking a step that
turned out not to have worked.
"""

from pathlib import Path

from textual.app import App
from textual.widgets import Checkbox, Markdown, OptionList

from rescue.guides import discover_guides, parse_guide_markdown
from rescue.session import SessionStore
from rescue.tui.screens.guide import (
    GuidePhasesScreen,
    GuideSetsScreen,
    GuideStepDetailScreen,
    GuideStepsScreen,
    discover_guide_sets,
)

PHASE_0 = """---
profile: demo_recovery
phase: 0
title: "Stabilise"
estimated_time: "20 minutes"
automatable_steps: [1]
human_only_steps: [2]
---

## Step 1: Run the device checks

Run the read-only scan and read what it found.

## Step 2: Change your email password

Do this from a device you trust. Nothing on this machine can do it for you.
"""

PHASE_1 = """---
profile: demo_recovery
phase: 1
title: "Rebuild"
estimated_time: "1 hour"
automatable_steps: []
human_only_steps: [1]
---

## Step 1: Turn on two-factor authentication

At each provider, in the order the guide lists.
"""


def _guides_dir(tmp_path: Path) -> Path:
    guides = tmp_path / "guides" / "demo_recovery"
    guides.mkdir(parents=True)
    (guides / "phase_0.md").write_text(PHASE_0)
    (guides / "phase_1.md").write_text(PHASE_1)
    # A remediation directory exists in the real tree and is reached from a
    # finding, not from this menu; it must not appear as a walkthrough.
    remediation = tmp_path / "guides" / "remediation"
    remediation.mkdir()
    (remediation / "x.md").write_text(
        "---\ntitle: Fix a thing\nremediates:\n  - a.b.c\n---\n\n## Step 1: Do it\n\nBody.\n"
    )
    return tmp_path / "guides"


def _store(tmp_path: Path) -> SessionStore:
    return SessionStore(session_dir=tmp_path / "sessions")


class _Host(App):
    def __init__(self, screen_factory):
        super().__init__()
        self._screen_factory = screen_factory

    def on_mount(self) -> None:
        self.push_screen(self._screen_factory())


def test_discover_guide_sets_skips_remediation(tmp_path):
    sets = discover_guide_sets(_guides_dir(tmp_path))
    assert [name for name, _ in sets] == ["demo_recovery"]
    assert len(sets[0][1]) == 2


def test_discover_guide_sets_handles_a_missing_directory(tmp_path):
    assert discover_guide_sets(tmp_path / "absent") == []


async def test_guide_sets_screen_lists_walkthroughs_with_progress(tmp_path):
    guides_dir = _guides_dir(tmp_path)
    store = _store(tmp_path)
    app = _Host(lambda: GuideSetsScreen(guides_dir, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        options = app.screen.query_one("#guide-set-list", OptionList)
        assert options.option_count == 1
        assert "0/3 steps done" in str(options.get_option_at_index(0).prompt)


async def test_guide_sets_screen_reports_no_content(tmp_path):
    app = _Host(lambda: GuideSetsScreen(tmp_path / "absent", _store(tmp_path)))
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.query_one("#guide-empty")


async def test_phases_screen_marks_the_current_phase(tmp_path):
    guides_dir = _guides_dir(tmp_path)
    store = _store(tmp_path)
    store.advance_phase("demo_recovery", 1)
    guides = discover_guides(guides_dir, "demo_recovery")
    app = _Host(lambda: GuidePhasesScreen("demo_recovery", guides, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        options = app.screen.query_one("#guide-phase-list", OptionList)
        assert not str(options.get_option_at_index(0).prompt).startswith("▶")
        assert str(options.get_option_at_index(1).prompt).startswith("▶")


async def test_steps_screen_labels_automatable_and_human_steps(tmp_path):
    guide = parse_guide_markdown(PHASE_0)
    app = _Host(lambda: GuideStepsScreen("demo_recovery", guide, _store(tmp_path)))
    async with app.run_test() as pilot:
        await pilot.pause()
        labels = [str(cb.label) for cb in app.screen.query(Checkbox)]
        assert any("tool-assisted" in label for label in labels)
        assert any("you do this" in label for label in labels)


async def test_ticking_a_step_persists_to_the_session_store(tmp_path):
    """The CLI reads the same store, so this is also CLI/TUI agreement."""
    guide = parse_guide_markdown(PHASE_0)
    store = _store(tmp_path)
    app = _Host(lambda: GuideStepsScreen("demo_recovery", guide, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#guide-step-1", Checkbox).value = True
        await pilot.pause()

    assert store.load("demo_recovery").completed_steps[0] == [1]


async def test_unticking_a_step_removes_it_again(tmp_path):
    """A step marked done that turned out not to work has to be reversible."""
    guide = parse_guide_markdown(PHASE_0)
    store = _store(tmp_path)
    store.mark_step_complete("demo_recovery", 0, 1)
    app = _Host(lambda: GuideStepsScreen("demo_recovery", guide, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        checkbox = app.screen.query_one("#guide-step-1", Checkbox)
        assert checkbox.value is True
        checkbox.value = False
        await pilot.pause()

    assert store.load("demo_recovery").completed_steps[0] == []


async def test_completing_every_step_advances_the_phase(tmp_path):
    guide = parse_guide_markdown(PHASE_0)
    store = _store(tmp_path)
    app = _Host(lambda: GuideStepsScreen("demo_recovery", guide, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#guide-step-1", Checkbox).value = True
        await pilot.pause()
        assert store.load("demo_recovery").current_phase == 0
        app.screen.query_one("#guide-step-2", Checkbox).value = True
        await pilot.pause()

    assert store.load("demo_recovery").current_phase == 1


async def test_saved_progress_is_shown_when_the_screen_reopens(tmp_path):
    guide = parse_guide_markdown(PHASE_0)
    store = _store(tmp_path)
    store.mark_step_complete("demo_recovery", 0, 2)
    app = _Host(lambda: GuideStepsScreen("demo_recovery", guide, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        assert app.screen.query_one("#guide-step-1", Checkbox).value is False
        assert app.screen.query_one("#guide-step-2", Checkbox).value is True


async def test_step_detail_screen_renders_the_step_body(tmp_path):
    guide = parse_guide_markdown(PHASE_0)
    step = guide.steps[1]
    app = _Host(lambda: GuideStepDetailScreen(step))
    async with app.run_test() as pilot:
        await pilot.pause()
        body = app.screen.query_one("#guide-step-detail-body", Markdown)
        assert "Change your email password" in body.source
        assert "cannot do it for you" in body.source


async def test_selecting_a_set_opens_its_phases(tmp_path):
    guides_dir = _guides_dir(tmp_path)
    store = _store(tmp_path)
    app = _Host(lambda: GuideSetsScreen(guides_dir, store))
    async with app.run_test() as pilot:
        await pilot.pause()
        app.screen.query_one("#guide-set-list", OptionList).action_select()
        await pilot.pause()
        assert isinstance(app.screen, GuidePhasesScreen)

        phase_list = app.screen.query_one("#guide-phase-list", OptionList)
        phase_list.highlighted = 0
        phase_list.action_select()
        await pilot.pause()
        assert isinstance(app.screen, GuideStepsScreen)
