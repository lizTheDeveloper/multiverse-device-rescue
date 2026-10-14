import asyncio
from pathlib import Path
from unittest.mock import patch

from textual.widgets import Button, OptionList

from rescue.models import DiskInfo, Platform, SystemProfile
from rescue.tui.app import RescueApp
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.findings import FindingsScreen
from rescue.tui.screens.fix_result import FixResultScreen
from rescue.tui.screens.modules import ModuleListScreen
from rescue.registry import discover_modules


def _profile(used_pct: float) -> SystemProfile:
    total = 500 * 1024**3
    used = int(total * used_pct)
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        disks=[
            DiskInfo(
                device="/dev/disk1",
                mount_point="/",
                total_bytes=total,
                used_bytes=used,
                free_bytes=total - used,
                filesystem="apfs",
            )
        ],
    )


async def _wait_for_screen(pilot, app, screen_type, timeout=30.0):
    """Wait until `app.screen` is `screen_type`, then let it finish settling.

    This used to poll a fixed number of times and then return silently, so a
    slow runner (Windows CI) surfaced as a bare `assert False` on the next
    line, with no hint which transition was late. Two things made it flaky:

    * the deadline was a handful of seconds of sleeping, which a loaded runner
      can miss; and
    * `app.screen` flips to the new screen before that screen's widgets are
      mounted and laid out, so acting on it straight away raced the layout.

    Now the wait is a generous wall-clock deadline that fails loudly naming the
    screen it was waiting for, and once the screen is current we drain the
    message queue (`pilot.pause()` with no delay waits for pending messages)
    so its widgets exist before the test touches them.
    """
    loop = asyncio.get_running_loop()
    deadline = loop.time() + timeout
    while not isinstance(app.screen, screen_type):
        if loop.time() > deadline:
            raise AssertionError(
                f"timed out after {timeout}s waiting for {screen_type.__name__}; "
                f"current screen is {type(app.screen).__name__}"
            )
        await pilot.pause(0.02)
    await pilot.pause()


async def _press(pilot, app, selector):
    """Press a button by id without depending on screen size or layout.

    `pilot.click` needs the widget on screen at known coordinates; on a small
    CI terminal the button can be scrolled out of view and the click misses.
    `Button.press()` posts the same Pressed message the click would.
    """
    app.screen.query_one(selector, Button).press()
    await pilot.pause()


async def test_full_flow_category_to_fix_result():
    """End-to-end: loading -> categories -> modules -> findings -> fix ->
    result -> back to categories, using the real disk_space module shipped
    in modules/performance/disk_space, with a mocked-full-disk profile so it
    reliably produces a finding."""
    modules_dir = Path(__file__).parent.parent.parent / "modules"
    disk_space_module = next(
        module for module in discover_modules(modules_dir) if module.name == "disk_space"
    )

    with patch("rescue.orchestrator.gather_profile", return_value=_profile(0.85)), \
         patch("rescue.orchestrator.discover_modules", return_value=[disk_space_module]):
        app = RescueApp(modules_dir=modules_dir)
        async with app.run_test() as pilot:
            await _wait_for_screen(pilot, app, CategoryMenuScreen)
            assert isinstance(app.screen, CategoryMenuScreen)

            category_list = app.screen.query_one("#category-list", OptionList)
            performance_index = next(
                i
                for i in range(category_list.option_count)
                if category_list.get_option_at_index(i).id == "performance"
            )
            category_list.highlighted = performance_index
            category_list.action_select()
            await _wait_for_screen(pilot, app, ModuleListScreen)
            assert isinstance(app.screen, ModuleListScreen)

            module_list = app.screen.query_one("#module-list", OptionList)
            assert module_list.get_option_at_index(0).id == "disk_space"
            module_list.action_select()
            await _wait_for_screen(pilot, app, FindingsScreen)
            assert isinstance(app.screen, FindingsScreen)

            await _press(pilot, app, "#apply-fixes")
            await _wait_for_screen(pilot, app, FixResultScreen)
            assert isinstance(app.screen, FixResultScreen)
            assert app.screen.fix.all_succeeded

            await _press(pilot, app, "#back-to-categories")
            await _wait_for_screen(pilot, app, CategoryMenuScreen)
            assert isinstance(app.screen, CategoryMenuScreen)
