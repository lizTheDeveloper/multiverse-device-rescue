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
