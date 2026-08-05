"""The `g` binding must reach the guides from anywhere in the app.

Someone opens this tool after being hacked. The recovery walkthrough is the
part they need first, and it must not be behind a completed scan — so the
binding is tested while the loading screen is still up.
"""

from pathlib import Path

from rescue.tui.app import RescueApp
from rescue.tui.screens.guide import GuideSetsScreen

REPO_ROOT = Path(__file__).parent.parent.parent


async def test_g_opens_the_guides_from_the_loading_screen(tmp_path):
    app = RescueApp(
        modules_dir=REPO_ROOT / "modules",
        guides_dir=REPO_ROOT / "guides",
        session_dir=tmp_path / "sessions",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("g")
        await pilot.pause()
        assert isinstance(app.screen, GuideSetsScreen)


async def test_shipped_guide_sets_are_discovered(tmp_path):
    """The real guides/ directory must produce real walkthroughs, not an empty menu."""
    app = RescueApp(
        modules_dir=REPO_ROOT / "modules",
        guides_dir=REPO_ROOT / "guides",
        session_dir=tmp_path / "sessions",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("g")
        await pilot.pause()
        names = [name for name, _ in app.screen.sets]
        assert "digital_security_reset" in names
        assert "remediation" not in names


async def test_missing_guide_content_notifies_instead_of_crashing(tmp_path):
    app = RescueApp(modules_dir=REPO_ROOT / "modules", session_dir=tmp_path / "sessions")
    async with app.run_test() as pilot:
        await pilot.pause()
        await pilot.press("g")
        await pilot.pause()
        assert not isinstance(app.screen, GuideSetsScreen)
