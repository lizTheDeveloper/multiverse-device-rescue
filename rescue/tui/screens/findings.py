"""Findings screen — shows every finding for a single module, color coded by
severity, with a button to move to fix selection."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from rescue.models import CheckResult, RiskLevel
from rescue.module_base import ModuleBase
from rescue.remediation import walkthrough_for
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
        if self.check.error:
            yield Static(f"{self.mod.name}: check unavailable — {self.check.error}", id="findings-empty")
        elif not self.check.has_issues:
            yield Static(f"{self.mod.name}: no issues found.", id="findings-empty")
        else:
            with VerticalScroll(id="findings-list"):
                self._wt_by_button: dict[str, object] = {}
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
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "apply-fixes":
            self.run_worker(self.start_fix_flow())
        elif event.button.id in getattr(self, "_wt_by_button", {}):
            from rescue.tui.screens.walkthrough import WalkthroughScreen
            self.app.push_screen(WalkthroughScreen(self._wt_by_button[event.button.id]))

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
