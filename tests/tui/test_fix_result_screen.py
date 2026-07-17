from textual.app import App
from textual.widgets import Static

from rescue.models import Action, ActionKind, CheckResult, FixResult, Platform, RiskLevel
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
                kind=ActionKind.MUTATION,
                executed=True,
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
