from textual.app import App
from textual.widgets import Markdown

from rescue.guides import parse_guide_markdown
from rescue.tui.screens.walkthrough import WalkthroughScreen, _walkthrough_markdown

WT = parse_guide_markdown(
    "---\ntitle: \"Reset SSH keys\"\nestimated_time: \"15 minutes\"\n"
    "remediates:\n  - security.ssh_key_audit.world_readable_key\n"
    "automatable_steps: []\nhuman_only_steps: [1]\n---\n"
    "## Step 1: Revoke the key\n\nRemove the world-readable private key.\n"
)


class WalkthroughHostApp(App):
    def on_mount(self) -> None:
        self.push_screen(WalkthroughScreen(WT))


def test_walkthrough_markdown_helper():
    rendered = _walkthrough_markdown(WT)
    assert "# Reset SSH keys" in rendered
    assert "## Step 1: Revoke the key" in rendered
    assert "Remove the world-readable private key." in rendered


async def test_walkthrough_screen_renders_title_and_step():
    app = WalkthroughHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        widget = app.screen.query_one("#walkthrough-body")
        assert isinstance(widget, Markdown)
        source = widget.source
        assert "Reset SSH keys" in source
        assert "Revoke the key" in source


async def test_escape_pops_walkthrough_screen():
    app = WalkthroughHostApp()
    async with app.run_test() as pilot:
        await pilot.pause()
        assert isinstance(app.screen, WalkthroughScreen)
        await pilot.press("escape")
        await pilot.pause()
        assert not isinstance(app.screen, WalkthroughScreen)
