from textual.app import App
from textual.widgets import OptionList

from rescue.models import CheckResult, Platform
from rescue.module_base import ModuleBase
from rescue.tui.screens.modules import ModuleListScreen


class PerfModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class ModuleListHostApp(App):
    def __init__(self, category, results):
        super().__init__()
        self.category = category
        self.results = results

    def on_mount(self) -> None:
        self.push_screen(ModuleListScreen(self.category, self.results))


async def test_module_list_shows_modules_in_category():
    results = [(PerfModule(), CheckResult(module_name="disk_space"))]
    app = ModuleListHostApp("performance", results)
    async with app.run_test() as pilot:
        await pilot.pause()
        option_list = app.screen.query_one("#module-list", OptionList)
        assert option_list.get_option_at_index(0).id == "disk_space"
