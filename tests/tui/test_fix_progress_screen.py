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
