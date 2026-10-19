import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
from unittest.mock import patch, MagicMock
import subprocess
import time

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "large_files_finder")


class TestLargeFilesFinderDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "large_files_finder"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 65
        assert mod.estimated_duration == "30s"
        assert mod.depends_on == []


class TestLargeFilesFinderEmpty:
    def test_no_large_files(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=[]):
                result = mod.check(_make_profile())

        # With mocked empty results, should not have issues
        top_files = next((f for f in result.findings if f.data.get("type") == "top_large_files"), None)
        assert top_files is None


class TestLargeFilesFinderTopFiles:
    def test_top_large_files_detected(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Mock large files
        large_files = [
            {"path": "/path/to/video.mp4", "size": 2 * 1024 * 1024 * 1024},
            {"path": "/path/to/image.iso", "size": 5 * 1024 * 1024 * 1024},
            {"path": "/path/to/backup.zip", "size": 3 * 1024 * 1024 * 1024},
        ]

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=large_files):
                result = mod.check(_make_profile())

        assert result.has_issues
        top_files = next((f for f in result.findings if f.data.get("type") == "top_large_files"), None)
        assert top_files is not None
        assert top_files.data["file_count"] == 3
        assert top_files.severity == Severity.INFO

    def test_top_files_sorted_by_size(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        large_files = [
            {"path": "/path/to/small.mp4", "size": 1 * 1024 * 1024 * 1024},
            {"path": "/path/to/large.iso", "size": 5 * 1024 * 1024 * 1024},
            {"path": "/path/to/medium.zip", "size": 3 * 1024 * 1024 * 1024},
        ]

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=large_files):
                result = mod.check(_make_profile())

        top_files = next((f for f in result.findings if f.data.get("type") == "top_large_files"), None)
        assert top_files is not None
        # Verify largest file is listed first
        assert top_files.data["files"][0]["size"] == 5 * 1024 * 1024 * 1024


class TestLargeFilesFinderCategorization:
    def test_categorize_videos(self, tmp_path):
        mod = _get_module()
        files = [
            {"path": "/path/to/movie.mp4", "size": 2 * 1024 * 1024 * 1024},
            {"path": "/path/to/video.mkv", "size": 3 * 1024 * 1024 * 1024},
        ]

        categorized = mod._categorize_files(files)
        assert "Videos" in categorized
        assert len(categorized["Videos"]) == 2

    def test_categorize_disk_images(self, tmp_path):
        mod = _get_module()
        files = [
            {"path": "/path/to/installer.dmg", "size": 2 * 1024 * 1024 * 1024},
            {"path": "/path/to/system.iso", "size": 3 * 1024 * 1024 * 1024},
        ]

        categorized = mod._categorize_files(files)
        assert "Disk Images" in categorized
        assert len(categorized["Disk Images"]) == 2

    def test_categorize_archives(self, tmp_path):
        mod = _get_module()
        files = [
            {"path": "/path/to/backup.zip", "size": 2 * 1024 * 1024 * 1024},
            {"path": "/path/to/tarball.tar.gz", "size": 3 * 1024 * 1024 * 1024},
        ]

        categorized = mod._categorize_files(files)
        assert "Archives" in categorized
        assert len(categorized["Archives"]) == 2

    def test_categorize_vm_images(self, tmp_path):
        mod = _get_module()
        files = [
            {"path": "/path/to/machine.vmdk", "size": 2 * 1024 * 1024 * 1024},
            {"path": "/path/to/disk.vdi", "size": 3 * 1024 * 1024 * 1024},
        ]

        categorized = mod._categorize_files(files)
        assert "VM Images" in categorized
        assert len(categorized["VM Images"]) == 2

    def test_categorize_mixed_files(self, tmp_path):
        mod = _get_module()
        files = [
            {"path": "/path/to/movie.mp4", "size": 1 * 1024 * 1024 * 1024},
            {"path": "/path/to/installer.dmg", "size": 2 * 1024 * 1024 * 1024},
            {"path": "/path/to/backup.zip", "size": 3 * 1024 * 1024 * 1024},
            {"path": "/path/to/unknown.bin", "size": 4 * 1024 * 1024 * 1024},
        ]

        categorized = mod._categorize_files(files)
        assert "Videos" in categorized
        assert "Disk Images" in categorized
        assert "Archives" in categorized
        assert "Other" in categorized


class TestLargeFilesFinderOldDownloads:
    def test_old_downloads_detected(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Create a small file to represent old large one
        old_file = downloads / "old_download.zip"
        old_file.write_text("old")
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_file, (old_time, old_time))

        # Mock _find_old_large_downloads to return detected old files
        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=[]):
                with patch.object(mod, "_find_old_large_downloads", return_value=[
                    {"path": str(old_file), "size": 600 * 1024 * 1024}
                ]):
                    result = mod.check(_make_profile())

        old_downloads = next((f for f in result.findings if f.data.get("type") == "old_downloads"), None)
        assert old_downloads is not None
        assert old_downloads.severity == Severity.WARNING
        assert old_downloads.data["file_count"] == 1
        assert old_downloads.data["size_bytes"] == 600 * 1024 * 1024

    def test_recent_large_downloads_ignored(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Create a small file to represent recent large one
        recent_file = downloads / "recent_download.zip"
        recent_file.write_text("recent")

        # Mock _find_old_large_downloads to return empty (recent file ignored)
        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=[]):
                with patch.object(mod, "_find_old_large_downloads", return_value=[]):
                    result = mod.check(_make_profile())

        old_downloads = next((f for f in result.findings if f.data.get("type") == "old_downloads"), None)
        # Recent file should not trigger old downloads finding
        assert old_downloads is None

    def test_old_small_downloads_ignored(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Create an old but small file (< 500MB)
        old_file = downloads / "old_small.txt"
        old_file.write_bytes(b"x" * (100 * 1024 * 1024))  # 100 MB
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_file, (old_time, old_time))

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=[]):
                result = mod.check(_make_profile())

        old_downloads = next((f for f in result.findings if f.data.get("type") == "old_downloads"), None)
        # Small old file should not trigger warning
        assert old_downloads is None


class TestLargeFilesFinderDesktop:
    def test_desktop_files_detected(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Create small file to represent large one
        desktop_file = desktop / "large_video.mp4"
        desktop_file.write_bytes(b"x" * 1000)

        # Mock the _find_large_desktop_files to return a large file
        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=[]):
                with patch.object(mod, "_find_large_desktop_files", return_value=[
                    {"path": str(desktop_file), "size": 2 * 1024 * 1024 * 1024}
                ]):
                    result = mod.check(_make_profile())

        desktop_finding = next((f for f in result.findings if f.data.get("type") == "desktop_files"), None)
        assert desktop_finding is not None
        assert desktop_finding.severity == Severity.INFO
        assert desktop_finding.data["file_count"] == 1

    def test_no_desktop_files(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=[]):
                result = mod.check(_make_profile())

        desktop_finding = next((f for f in result.findings if f.data.get("type") == "desktop_files"), None)
        assert desktop_finding is None


class TestLargeFilesFinderCriticalThreshold:
    def test_critical_threshold_50gb(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Mock large files exceeding 50GB threshold
        large_files = [
            {"path": "/path/to/video1.mp4", "size": 30 * 1024 * 1024 * 1024},
            {"path": "/path/to/video2.mp4", "size": 25 * 1024 * 1024 * 1024},
        ]

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=large_files):
                result = mod.check(_make_profile())

        # Should have warning for critical threshold
        critical = next((f for f in result.findings if f.data.get("type") == "critical_large_files"), None)
        assert critical is not None
        assert critical.severity == Severity.WARNING

    def test_no_critical_under_50gb(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        large_files = [
            {"path": "/path/to/video.mp4", "size": 5 * 1024 * 1024 * 1024},
        ]

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=large_files):
                result = mod.check(_make_profile())

        critical = next((f for f in result.findings if f.data.get("type") == "critical_large_files"), None)
        assert critical is None


class TestLargeFilesFinderFix:
    def test_fix_returns_actions(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        large_files = [
            {"path": "/path/to/video.mp4", "size": 2 * 1024 * 1024 * 1024},
        ]

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=large_files):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        assert fix.all_succeeded
        assert len(fix.actions) > 0
        assert all(a.success for a in fix.actions)
        assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)

    def test_fix_informational_only(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()
        desktop = home / "Desktop"
        desktop.mkdir()

        # Create small files to represent large ones
        video = desktop / "large.mp4"
        video.write_bytes(b"x" * 1000)

        large_files = [
            {"path": str(video), "size": 2 * 1024 * 1024 * 1024},
        ]

        with patch.object(Path, "home", return_value=home):
            with patch.object(mod, "_find_large_files", return_value=large_files):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        # Verify actions are informational
        assert fix.all_succeeded
        for action in fix.actions:
            assert action.success
            assert action.description is not None

        # Verify files are not deleted
        assert video.exists()


class TestLargeFilesFinderErrorHandling:
    def test_missing_downloads_directory(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        # Don't create Downloads directory

        with patch.object(Path, "home", return_value=home):
            # Should not crash
            result = mod.check(_make_profile())
            assert isinstance(result.findings, list)

    def test_missing_desktop_directory(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        downloads = home / "Downloads"
        downloads.mkdir()

        with patch.object(Path, "home", return_value=home):
            result = mod.check(_make_profile())
            assert isinstance(result.findings, list)


def _cmd(stdout="", returncode=0, timed_out=False, stderr="", truncated=False):
    from rescue.command import CommandResult

    return CommandResult(
        args=["find"], returncode=None if timed_out else returncode, stdout=stdout,
        stderr=stderr, timed_out=timed_out,
        error="timed out after 1s" if timed_out else None,
        duration_s=0.0, truncated=truncated,
    )


def _patch_run(mod, **kw):
    return patch.object(sys.modules[type(mod).__module__], "run", **kw)


class TestLargeFilesFinderFindCommand:
    def test_find_large_files_command_mocked(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        large_file = home / "large.bin"
        large_file.write_text("mock")

        with _patch_run(mod, return_value=_cmd(f"{home}/large.bin\n")):
            files = mod._find_large_files(home)
        assert len(files) == 1
        assert files[0]["path"] == str(large_file)
        assert mod._search_incomplete is False

    def test_find_multiple_large_files_mocked(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        file1 = home / "file1.bin"
        file2 = home / "file2.bin"
        file1.write_text("mock1")
        file2.write_text("mock2")

        with _patch_run(mod, return_value=_cmd(f"{file1}\n{file2}\n")):
            files = mod._find_large_files(home)
        assert len(files) == 2

    def test_unreadable_folders_do_not_discard_results(self, tmp_path):
        """find exits 1 when some folder can't be read; what it printed still counts."""
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        big = home / "big.bin"
        big.write_text("x")

        with _patch_run(mod, return_value=_cmd(f"{big}\n", returncode=1)):
            files = mod._find_large_files(home)
        assert [f["path"] for f in files] == [str(big)]

    def test_find_ignores_small_files(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()

        # Create small files
        small_file = home / "small.txt"
        small_file.write_bytes(b"x" * 1000)

        files = mod._find_large_files(home)
        assert len(files) == 0

    def test_likely_folders_are_searched_first(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        (home / "Downloads").mkdir(parents=True)
        calls = []

        def fake(cmd, **kw):
            calls.append(cmd)
            return _cmd("")

        with _patch_run(mod, side_effect=fake):
            mod._find_large_files(home)
        assert str(home / "Downloads") in calls[0]
        # The last pass, over the rest of home, skips what was already searched.
        assert ["-path", str(home / "Downloads")] == calls[-1][calls[-1].index("-path"):][:2]

    def test_a_huge_folder_does_not_lose_the_others(self, tmp_path):
        """Each folder gets its own find, so one that is stopped keeps the rest."""
        mod = _get_module()
        home = tmp_path / "home"
        for name in ("Desktop", "Documents"):
            (home / name).mkdir(parents=True)
        big = home / "Desktop" / "big.mov"
        big.write_text("x")
        timeouts = []

        def fake(cmd, timeout, **kw):
            timeouts.append(timeout)
            if cmd[1] == str(home / "Desktop"):
                return _cmd(f"{big}\n")
            if cmd[1] == str(home / "Documents"):
                return _cmd("", timed_out=True)  # lost its buffered output
            return _cmd("")

        with _patch_run(mod, side_effect=fake):
            files = mod._find_large_files(home)
        assert [f["path"] for f in files] == [str(big)]
        assert mod._unfinished_folders == ["~/Documents"]
        assert max(timeouts) <= 10.0


class TestLargeFilesFinderTimeBudget:
    """Regression: the whole-home `find` used the engine's full 60s, so the
    check always timed out and reported nothing."""

    def test_hanging_find_returns_within_budget_and_keeps_what_it_found(self, tmp_path):
        mod = _get_module()
        mod.search_budget_s = 1.0
        home = tmp_path / "home"
        (home / "Downloads").mkdir(parents=True)
        found = home / "Downloads" / "movie.mov"
        found.write_text("x")

        def hang(cmd, timeout, **kw):
            assert timeout <= 1.0  # never more than what is left of the budget
            # A stopped find: one full path, then a line cut off mid-way.
            return _cmd(f"{found}\n{home}/Downloads/cut-of", timed_out=True)

        start = time.monotonic()
        with patch.object(Path, "home", return_value=home), _patch_run(mod, side_effect=hang):
            result = mod.check(_make_profile())
        assert time.monotonic() - start < 5

        top = next(f for f in result.findings if f.data.get("type") == "top_large_files")
        assert [f["path"] for f in top.data["files"]] == [str(found)]
        note = next(f for f in result.findings if f.data.get("type") == "search_incomplete")
        assert note.severity == Severity.INFO
        assert "didn't finish" in note.title
        assert "~/Downloads" in note.data["unfinished"]
        assert "may be missing" in note.description
        assert result.complete is False

    def test_real_hanging_command_is_stopped(self, tmp_path):
        """With the real command runner, a find that never ends is killed."""
        mod = _get_module()
        mod.search_budget_s = 1.5
        home = tmp_path / "home"
        home.mkdir()
        from rescue import command as real_command

        def sleeper(cmd, timeout, **kw):
            return real_command.run([sys.executable, "-c", "import time; time.sleep(30)"], timeout=timeout)

        start = time.monotonic()
        with patch.object(Path, "home", return_value=home), _patch_run(mod, side_effect=sleeper):
            result = mod.check(_make_profile())
        assert time.monotonic() - start < 6
        assert any(f.data.get("type") == "search_incomplete" for f in result.findings)
        assert result.complete is False

    def test_finished_search_has_no_incomplete_note(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        home.mkdir()
        with patch.object(Path, "home", return_value=home), _patch_run(mod, return_value=_cmd("")):
            result = mod.check(_make_profile())
        assert not any(f.data.get("type") == "search_incomplete" for f in result.findings)
        assert result.complete is True


class TestLargeFilesFinderUnreadable:
    """Review: a folder find couldn't open, or a run cut short, was counted as searched."""

    def test_top_folder_without_access_is_not_searched(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        for name in ("Desktop", "Documents"):
            (home / name).mkdir(parents=True)
        docs = home / "Documents"

        def fake(cmd, timeout, **kw):
            if cmd[1] == str(docs):
                return _cmd("", returncode=1, stderr=f"find: {docs}: Operation not permitted\n")
            return _cmd("")

        with _patch_run(mod, side_effect=fake):
            mod._find_large_files(home)
        assert mod._unfinished_folders == ["~/Documents (couldn't be opened)"]
        assert mod._search_incomplete is True

    def test_unreadable_subfolder_still_counts_as_searched(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        (home / "Desktop").mkdir(parents=True)
        big = home / "Desktop" / "big.bin"
        big.write_text("x")
        sub = home / "Desktop" / "Private"

        def fake(cmd, timeout, **kw):
            if cmd[1] == str(home / "Desktop"):
                return _cmd(f"{big}\n", returncode=1,
                            stderr=f"find: {sub}: Permission denied\n")
            return _cmd("")

        with _patch_run(mod, side_effect=fake):
            files = mod._find_large_files(home)
        assert [f["path"] for f in files] == [str(big)]
        assert mod._unfinished_folders == []

    def test_truncated_output_is_unfinished(self, tmp_path):
        mod = _get_module()
        home = tmp_path / "home"
        (home / "Desktop").mkdir(parents=True)
        big = home / "Desktop" / "big.bin"
        big.write_text("x")

        def fake(cmd, timeout, **kw):
            if cmd[1] == str(home / "Desktop"):
                return _cmd(f"{big}\n{home}/Desktop/cut", truncated=True)
            return _cmd("")

        with _patch_run(mod, side_effect=fake):
            files = mod._find_large_files(home)
        assert mod._unfinished_folders == ["~/Desktop"]
        assert [f["path"] for f in files] == [str(big)]
