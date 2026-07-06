"""Placeholder for the guide/walkthrough system (Plan 3). Shows what a
step-by-step guided walkthrough checklist will look like, without any real
guide content or progress persistence wired up yet."""

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import Screen
from textual.widgets import Checkbox, Footer, Header, Static

from rescue.module_base import ModuleBase

PLACEHOLDER_STEPS = [
    "Review the finding details",
    "Apply the recommended change",
    "Confirm the change took effect",
]


class GuidePlaceholderScreen(Screen):
    """Stub screen for guide/walkthrough rendering.

    This is a hook point for Plan 3 (Profile System & Guide Engine). Once
    markdown guide content with frontmatter is parsed, this screen will be
    replaced with real step content driven by the guide's `automatable_steps`
    and `human_only_steps` metadata. For now it renders a static, disabled
    checklist so the eventual UI shape is visible.
    """

    BINDINGS = [("escape", "app.pop_screen", "Back")]

    def __init__(self, mod: ModuleBase):
        super().__init__()
        self.mod = mod

    def compose(self) -> ComposeResult:
        yield Header()
        yield Vertical(
            Static(
                f"Guides & interactive walkthroughs for '{self.mod.name}' are "
                f"coming in Plan 3 (Profile System & Guide Engine).",
                id="guide-placeholder-message",
            ),
            Static("Preview of the walkthrough checklist UI:", id="guide-placeholder-preview-label"),
            *[Checkbox(step, disabled=True) for step in PLACEHOLDER_STEPS],
        )
        yield Footer()
