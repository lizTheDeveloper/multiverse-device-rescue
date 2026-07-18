"""Fix result screen — shows what actions were taken and whether they
succeeded, with a link to the relevant remediation walkthrough when available."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Button, Footer, Header, Static

from rescue.models import Action, ActionKind, CheckResult, FixResult
from rescue.module_base import ModuleBase


def format_action_line(action: Action) -> str:
    if action.kind == ActionKind.GUIDANCE:
        return f"[yellow]MANUAL[/yellow] {action.title} — {action.description}"
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
            if not self.fix.applied_actions:
                yield Static("No automatic changes were made. Review the manual actions below.", id="fix-result-summary")
            elif self.fix.all_succeeded:
                yield Static(f"All {len(self.fix.actions)} action(s) succeeded.", id="fix-result-summary")
            else:
                yield Static("Some actions failed.", id="fix-result-summary")
            for action in self.fix.actions:
                yield Static(format_action_line(action), classes="action-row")
        from rescue.tui.screens._pick import highest_severity_walkthrough
        self._wt = highest_severity_walkthrough(
            getattr(self.app, "remediation_index", {}), self.check)
        if self._wt is not None:
            yield Button("View Walkthrough", id="view-guide")
        yield Button("Back to Categories", id="back-to-categories", variant="primary")
        yield Footer()

    def on_button_pressed(self, event: Button.Pressed) -> None:
        if event.button.id == "view-guide":
            from rescue.tui.screens.walkthrough import WalkthroughScreen

            self.app.push_screen(WalkthroughScreen(self._wt))
        elif event.button.id == "back-to-categories":
            self.app.pop_screen_to_categories()
