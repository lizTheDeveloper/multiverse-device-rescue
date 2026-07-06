from textual.app import App
from textual.widgets import Checkbox, Static

from rescue.models import Platform
from rescue.module_base import ModuleBase
from rescue.tui.screens.guide_placeholder import GuidePlaceholderScreen


class FakeMod(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class GuideHostApp(App):
    def on_mount(self) -> None:
        self.push_screen(GuidePlaceholderScreen(FakeMod()))


async def test_guide_placeholder_shows_disabled_checklist():
    app = GuideHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        checkboxes = list(app.screen.query(Checkbox))
        assert len(checkboxes) == 3
        for cb in checkboxes:
            assert cb.disabled

        message = app.screen.query_one("#guide-placeholder-message", Static)
        assert "disk_space" in str(message.content)
        assert "Plan 3" in str(message.content)
