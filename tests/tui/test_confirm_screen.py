from textual.app import App, ComposeResult
from textual.screen import Screen
from textual.widgets import Static

from rescue.tui.screens.confirm import ConfirmScreen


class ConfirmHostScreen(Screen):
    """Hosts a button that triggers the modal and records the result."""

    def compose(self) -> ComposeResult:
        yield Static("waiting", id="result")

    def on_mount(self) -> None:
        self.run_worker(self.ask())

    async def ask(self) -> None:
        result = await self.app.push_screen_wait(ConfirmScreen("Proceed?"))
        self.query_one("#result", Static).update(f"result:{result}")


class ConfirmHostApp(App):
    def on_mount(self) -> None:
        self.push_screen(ConfirmHostScreen())


async def test_confirm_screen_yes():
    app = ConfirmHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#confirm-yes")
        await pilot.pause()
        assert app.screen.query_one("#result", Static).content == "result:True"


async def test_confirm_screen_no():
    app = ConfirmHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.click("#confirm-no")
        await pilot.pause()
        assert app.screen.query_one("#result", Static).content == "result:False"
