"""Module list screen — shows the modules within a category and their check
results; selecting one drills into its findings."""

from textual.app import ComposeResult
from textual.screen import Screen
from textual.widgets import Footer, Header, OptionList
from textual.widgets.option_list import Option

from rescue.models import CheckResult
from rescue.module_base import ModuleBase
from rescue.tui.formatting import format_module_summary


class ModuleListScreen(Screen):
    """Displays modules within a single category."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, category: str, results: list[tuple[ModuleBase, CheckResult]]):
        super().__init__()
        self.category = category
        self.results = results
        self.results_by_name = {mod.name: (mod, check) for mod, check in results}

    def compose(self) -> ComposeResult:
        yield Header()
        options = [
            Option(format_module_summary(mod, check), id=mod.name)
            for mod, check in self.results
        ]
        yield OptionList(*options, id="module-list")
        yield Footer()

    def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
        module_name = event.option.id
        assert module_name is not None
        mod, check = self.results_by_name[module_name]
        from rescue.tui.screens.findings import FindingsScreen

        self.app.push_screen(FindingsScreen(mod, check))
