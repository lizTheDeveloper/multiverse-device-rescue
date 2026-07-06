"""Fix progress screen — runs a module's fix() in a background thread so the
UI stays responsive, then shows the result."""

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static

from rescue.models import CheckResult, FixResult, Mode
from rescue.module_base import ModuleBase


class FixProgressScreen(Screen):
    """Shown while a module's fix() is running."""

    def __init__(self, mod: ModuleBase, check: CheckResult):
        super().__init__()
        self.mod = mod
        self.check = check

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static(f"Applying fixes for {self.mod.name}…", id="fix-status"),
            ProgressBar(show_eta=False, id="fix-progress"),
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#fix-progress", ProgressBar).update(total=None)
        self.run_fix()

    @work(thread=True)
    def run_fix(self) -> None:
        fix_result = self.mod.fix(self.check, Mode.MANUAL)
        self.app.call_from_thread(self.on_fix_complete, fix_result)

    def on_fix_complete(self, fix_result: FixResult) -> None:
        from rescue.tui.screens.fix_result import FixResultScreen

        self.app.switch_screen(FixResultScreen(self.mod, self.check, fix_result))
