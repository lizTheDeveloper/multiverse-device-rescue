"""The interactive TUI entry point. Launched by `rescue` with no subcommand."""

from pathlib import Path

from textual.app import App

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.loading import LoadingScreen

_CSS_PATH = Path(__file__).parent / "app.tcss"


class RescueApp(App):
    """Multiverse Device Rescue interactive TUI."""

    CSS_PATH = _CSS_PATH
    TITLE = "Multiverse Device Rescue"
    BINDINGS = [("q", "quit", "Quit")]

    def __init__(self, modules_dir: Path):
        super().__init__()
        self.modules_dir = modules_dir
        self.orchestrator = Orchestrator(modules_dir=modules_dir)

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen(self.orchestrator))

    def on_checks_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None:
        """Called by LoadingScreen once the orchestrator has finished running
        checks. Replaces the loading screen with the category menu."""
        self.switch_screen(CategoryMenuScreen(results))

    def pop_screen_to_categories(self) -> None:
        """Pop screens until the category menu (index 1, just above the
        default screen) is on top."""
        while len(self.screen_stack) > 2:
            self.pop_screen()


def run_tui(modules_dir: Path) -> None:
    app = RescueApp(modules_dir=modules_dir)
    app.run()
