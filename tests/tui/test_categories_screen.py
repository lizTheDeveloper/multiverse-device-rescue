from textual.app import App
from textual.widgets import OptionList

from rescue.models import CheckResult, Finding, Platform, Severity
from rescue.module_base import ModuleBase
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.modules import ModuleListScreen


class PerfModule(ModuleBase):
    name = "disk_space"
    category = "performance"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


class SecurityModule(ModuleBase):
    name = "firewall_audit"
    category = "security"
    platforms = [Platform.DARWIN]

    def check(self, profile):
        pass

    def fix(self, findings, mode):
        pass


def _make_results():
    perf_check = CheckResult(
        module_name="disk_space",
        findings=[
            Finding(title="Disk full", description="90%", severity=Severity.WARNING, category="performance")
        ],
    )
    sec_check = CheckResult(module_name="firewall_audit")
    return [(PerfModule(), perf_check), (SecurityModule(), sec_check)]


class CategoryHostApp(App):
    def __init__(self, results):
        super().__init__()
        self.results = results

    def on_mount(self) -> None:
        self.push_screen(CategoryMenuScreen(self.results))


async def test_category_menu_lists_categories_sorted():
    app = CategoryHostApp(_make_results())
    async with app.run_test() as pilot:
        await pilot.pause()
        option_list = app.screen.query_one("#category-list", OptionList)
        ids = [option_list.get_option_at_index(i).id for i in range(option_list.option_count)]
        assert ids == ["performance", "security"]


async def test_selecting_category_pushes_module_list_screen():
    app = CategoryHostApp(_make_results())
    async with app.run_test() as pilot:
        await pilot.pause()
        option_list = app.screen.query_one("#category-list", OptionList)
        option_list.action_select()
        await pilot.pause()
        assert isinstance(app.screen, ModuleListScreen)
        assert app.screen.category == "performance"
        module_list = app.screen.query_one("#module-list", OptionList)
        assert module_list.get_option_at_index(0).id == "disk_space"
