"""The `g` binding must reach the guides from anywhere in the app.

Someone opens this tool after being hacked. The recovery walkthrough is the
part they need first, and it must not be behind a completed scan — so the
binding is tested while the loading screen is still up.

The orchestrator is stubbed out in every test here. Without that, constructing
a RescueApp starts a real scan of the real module tree: on Linux only a handful
of modules match the platform and it is cheap, but on Windows the loading
screen fires roughly a hundred checks that shell out to powershell, manage-bde,
driverquery and tasklist. The tests still pass, and then the job spends sixteen
minutes reaping orphaned processes and printing "Module check timed out". Tests
that reach real system state are exactly the environment coupling this suite
has been bitten by before.
"""

from pathlib import Path
from unittest.mock import patch

import pytest

from rescue.models import Platform, SystemProfile
from rescue.tui.app import RescueApp
from rescue.tui.screens.guide import GuideSetsScreen

REPO_ROOT = Path(__file__).parent.parent.parent


def _profile() -> SystemProfile:
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


@pytest.fixture
def no_real_scan():
    """Keep the loading screen's orchestrator from touching the host."""
    with patch("rescue.orchestrator.gather_profile", return_value=_profile()), \
         patch("rescue.orchestrator.discover_modules", return_value=[]):
        yield


async def _open_guides(app, pilot, attempts=100):
    """Press `g` and wait for the guides screen, rather than assuming one tick."""
    await pilot.press("g")
    for _ in range(attempts):
        if isinstance(app.screen, GuideSetsScreen):
            return
        await pilot.pause(0.05)


async def test_g_opens_the_guides_from_the_loading_screen(tmp_path, no_real_scan):
    app = RescueApp(
        modules_dir=REPO_ROOT / "modules",
        guides_dir=REPO_ROOT / "guides",
        session_dir=tmp_path / "sessions",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        await _open_guides(app, pilot)
        assert isinstance(app.screen, GuideSetsScreen)


async def test_shipped_guide_sets_are_discovered(tmp_path, no_real_scan):
    """The real guides/ directory must produce real walkthroughs, not an empty menu."""
    app = RescueApp(
        modules_dir=REPO_ROOT / "modules",
        guides_dir=REPO_ROOT / "guides",
        session_dir=tmp_path / "sessions",
    )
    async with app.run_test() as pilot:
        await pilot.pause()
        await _open_guides(app, pilot)
        names = [name for name, _ in app.screen.sets]
        assert "digital_security_reset" in names
        assert "remediation" not in names


async def test_missing_guide_content_notifies_instead_of_crashing(tmp_path, no_real_scan):
    app = RescueApp(modules_dir=REPO_ROOT / "modules", session_dir=tmp_path / "sessions")
    async with app.run_test() as pilot:
        await pilot.pause()
        await _open_guides(app, pilot, attempts=10)
        assert not isinstance(app.screen, GuideSetsScreen)
