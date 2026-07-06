from pathlib import Path
from unittest.mock import patch

from textual.widgets import OptionList

from rescue.models import DiskInfo, Platform, SystemProfile
from rescue.tui.app import RescueApp
from rescue.tui.screens.categories import CategoryMenuScreen
from rescue.tui.screens.findings import FindingsScreen
from rescue.tui.screens.fix_result import FixResultScreen
from rescue.tui.screens.modules import ModuleListScreen


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


async def test_full_flow_category_to_fix_result():
    """End-to-end: loading -> categories -> modules -> findings -> fix ->
    result -> back to categories, using the real disk_space module shipped
    in modules/performance/disk_space, with a mocked-full-disk profile so it
    reliably produces a finding."""
    modules_dir = Path(__file__).parent.parent.parent / "modules"

    with patch("rescue.orchestrator.gather_profile", return_value=_profile(0.85)):
        app = RescueApp(modules_dir=modules_dir)
        async with app.run_test() as pilot:
            # The integrity/update_checker module shells out to the real
            # `softwareupdate -l` (and `brew outdated`) commands. Its own
            # estimated_duration is "30s", so poll comfortably past that
            # worst case rather than assume checks finish instantly. The
            # loop breaks as soon as the screen transitions, so a generous
            # cap costs nothing in the common (fast) case.
            for _ in range(1200):
                await pilot.pause(0.05)
                if isinstance(app.screen, CategoryMenuScreen):
                    break
            assert isinstance(app.screen, CategoryMenuScreen)

            # Categories are sorted alphabetically by group_by_category, so
            # with the real modules/ tree "performance" is not necessarily
            # first (bloatware and integrity sort before it). Find it by id
            # rather than assuming a fixed index.
            category_list = app.screen.query_one("#category-list", OptionList)
            performance_index = next(
                i
                for i in range(category_list.option_count)
                if category_list.get_option_at_index(i).id == "performance"
            )
            category_list.highlighted = performance_index
            category_list.action_select()
            await pilot.pause()
            assert isinstance(app.screen, ModuleListScreen)

            module_list = app.screen.query_one("#module-list", OptionList)
            assert module_list.get_option_at_index(0).id == "disk_space"
            module_list.action_select()
            await pilot.pause()
            assert isinstance(app.screen, FindingsScreen)

            await pilot.click("#apply-fixes")
            for _ in range(100):
                await pilot.pause(0.05)
                if isinstance(app.screen, FixResultScreen):
                    break
            assert isinstance(app.screen, FixResultScreen)
            assert app.screen.fix.all_succeeded

            await pilot.click("#back-to-categories")
            await pilot.pause()
            assert isinstance(app.screen, CategoryMenuScreen)
