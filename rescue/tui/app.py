"""The interactive TUI entry point. Launched by `rescue` with no subcommand."""

from pathlib import Path

from textual.app import App

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.orchestrator import Orchestrator
from rescue.remediation import load_remediation_walkthroughs
from rescue.session import SessionStore
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.loading import LoadingScreen

_CSS_PATH = Path(__file__).parent / "app.tcss"

_DEFAULT_SESSION_DIR = Path.home() / ".rescue" / "sessions"


class RescueApp(App):
    """Multiverse Device Rescue interactive TUI."""

    CSS_PATH = _CSS_PATH
    TITLE = "Multiverse Device Rescue"
    BINDINGS = [
        ("q", "quit", "Quit"),
        ("g", "guides", "Guides"),
    ]

    def __init__(
        self,
        modules_dir: Path,
        guides_dir: Path | None = None,
        session_dir: Path | None = None,
    ):
        super().__init__()
        self.modules_dir = modules_dir
        self.guides_dir = guides_dir
        self.orchestrator = Orchestrator(modules_dir=modules_dir)
        self.remediation_index = (
            load_remediation_walkthroughs(guides_dir / "remediation")
            if guides_dir is not None
            else {}
        )
        # Shared with `rescue guide <profile>` on the CLI, so progress made in
        # either place is the same progress rather than two disagreeing records.
        self.session_dir = session_dir or _DEFAULT_SESSION_DIR

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen(self.orchestrator))

    def on_checks_complete(self, results: list[tuple[ModuleBase, CheckResult]]) -> None:
        """Called by LoadingScreen once the orchestrator has finished running
        checks. Replaces the loading screen with the category menu."""
        self.switch_screen(CategoryMenuScreen(results))

    def action_guides(self) -> None:
        """Open the guided-walkthrough flow (bound to `g`).

        Available from any screen, including while checks are still running: the
        recovery walkthroughs are the part of this tool someone needs *first*
        after a compromise, and making them wait for a full scan to finish would
        put a progress bar in front of the advice.
        """
        if self.guides_dir is None:
            self.notify("No guide content is installed.", severity="warning")
            return
        from rescue.tui.screens.guide import GuideSetsScreen

        self.push_screen(GuideSetsScreen(self.guides_dir, SessionStore(self.session_dir)))

    def pop_screen_to_categories(self) -> None:
        """Pop screens until the category menu (index 1, just above the
        default screen) is on top."""
        while len(self.screen_stack) > 2:
            self.pop_screen()


def run_tui(
    modules_dir: Path,
    guides_dir: Path | None = None,
    session_dir: Path | None = None,
) -> None:
    app = RescueApp(
        modules_dir=modules_dir, guides_dir=guides_dir, session_dir=session_dir
    )
    app.run()
