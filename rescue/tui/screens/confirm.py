"""Reusable yes/no confirmation modal, used before applying moderate or
destructive fixes."""

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.screen import ModalScreen
from textual.widgets import Button, Static


class ConfirmScreen(ModalScreen[bool]):
    """A modal that resolves to True (confirmed) or False (cancelled)."""

    def __init__(self, message: str):
        super().__init__()
        self.message = message

    def compose(self) -> ComposeResult:
        yield Vertical(
            Static(self.message, id="confirm-message"),
            Button("Confirm", id="confirm-yes", variant="success"),
            Button("Cancel", id="confirm-no", variant="error"),
            id="confirm-container",
        )

    def on_button_pressed(self, event: Button.Pressed) -> None:
        self.dismiss(event.button.id == "confirm-yes")
