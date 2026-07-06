"""Loading screen: profiles the system and runs all module checks via the
Orchestrator, then hands off to the category menu."""

from textual import work
from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Footer, Header, ProgressBar, Static

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator


class LoadingScreen(Screen):
    """Shown on startup while the orchestrator profiles the system and runs checks."""

    def __init__(self, orchestrator: Orchestrator):
        super().__init__()
        self.orchestrator = orchestrator

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static("Profiling system and running checks…", id="loading-status"),
            ProgressBar(show_eta=False, id="loading-progress"),
            id="loading-container",
        )
        yield Footer()

    def on_mount(self) -> None:
        self.query_one("#loading-progress", ProgressBar).update(total=None)
        self.run_scan()

    @work(thread=True)
    def run_scan(self) -> None:
        results = self.orchestrator.run_checks()
        self.app.call_from_thread(self.on_scan_complete, results)

    def on_scan_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None:
        self.app.on_checks_complete(results)
