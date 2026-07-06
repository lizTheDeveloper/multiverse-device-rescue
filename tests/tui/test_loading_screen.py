from unittest.mock import MagicMock

from textual.app import App
from textual.widgets import ProgressBar

from rescue.tui.screens.loading import LoadingScreen


class LoadingHostApp(App):
    """Minimal host that records the results handed back by LoadingScreen."""

    def __init__(self, orchestrator):
        super().__init__()
        self.orchestrator = orchestrator
        self.received_results = None

    def on_mount(self) -> None:
        self.push_screen(LoadingScreen(self.orchestrator))

    def on_checks_complete(self, results) -> None:
        self.received_results = results


async def test_loading_screen_runs_checks_and_hands_off():
    fake_results = [("mod1", "check1")]
    orchestrator = MagicMock()
    orchestrator.run_checks.return_value = fake_results

    app = LoadingHostApp(orchestrator)
    async with app.run_test() as pilot:
        for _ in range(20):
            await pilot.pause(0.05)
            if app.received_results is not None:
                break

    assert app.received_results == fake_results
    orchestrator.run_checks.assert_called_once()


async def test_loading_screen_shows_indeterminate_progress():
    orchestrator = MagicMock()
    orchestrator.run_checks.return_value = []

    app = LoadingHostApp(orchestrator)
    async with app.run_test() as pilot:
        await pilot.pause()
        progress = app.screen.query_one("#loading-progress", ProgressBar)
        assert progress.total is None
