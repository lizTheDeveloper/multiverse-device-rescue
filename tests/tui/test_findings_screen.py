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
        assert len(app.screen.query(Button)) == 0


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
