"""Walkthrough screen — renders a remediation walkthrough's steps. Stateless:
nothing is written to session/SessionState."""

from textual.app import ComposeResult
from textual.containers import VerticalScroll
from textual.screen import Screen
from textual.widgets import Footer, Header, Static

from rescue.guides import Guide


def _render_walkthrough(guide: Guide) -> str:
    lines = [f"[b]{guide.title}[/b]"]
    if guide.estimated_time:
        lines.append(f"[dim]Estimated time: {guide.estimated_time}[/dim]")
    lines.append("")
    for step in guide.steps:
        marker = " [cyan](automatable)[/cyan]" if step.automatable else ""
        lines.append(f"[b]Step {step.number}: {step.title}[/b]{marker}")
        lines.append(step.body)
        lines.append("")
    return "\n".join(lines)


class WalkthroughScreen(Screen):
    """Displays one remediation walkthrough."""

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, guide: Guide):
        super().__init__()
        self.guide = guide

    def compose(self) -> ComposeResult:
        yield Header()
        with VerticalScroll(id="walkthrough-list"):
            yield Static(_render_walkthrough(self.guide), id="walkthrough-body")
        yield Footer()
