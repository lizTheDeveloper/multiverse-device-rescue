"""Category menu screen — the entry point after checks have run. Lists each
module category with an aggregate issue count."""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList
from textual.widgets.option_list import Option

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.tui.formatting import format_category_summary, group_by_category


class CategoryMenuScreen(Screen):
    """Displays module categories discovered on this system."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, results: list[tuple[ModuleBase, CheckResult]]):
        super().__init__()
        self.results = results
        self.results_by_name = {mod.name: check for mod, check in results}
        self.groups = group_by_category([mod for mod, _ in results])

    def compose(self) -> ComposeResult:
        yield Header()
        options = [
            Option(
                format_category_summary(category, mods, self.results_by_name),
                id=category,
            )
            for category, mods in self.groups.items()
        ]
        yield OptionList(*options, id="category-list")
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        category = event.option.id
        assert category is not None
        category_results = [
            (mod, check) for mod, check in self.results if mod.category == category
        ]
        from rescue.tui.screens.modules import ModuleListScreen

        self.app.push_screen(ModuleListScreen(category, category_results))
