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
