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
