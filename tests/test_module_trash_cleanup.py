import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

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
    return next(m for m in modules if m.name == "trash_cleanup")


class TestTrashCleanupDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "trash_cleanup"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 65
        assert mod.estimated_duration == "5s"
        assert mod.depends_on == []


class TestTrashCleanupEmptyTrash:
    def test_empty_trash(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                result = mod.check(_make_profile())

        assert not result.has_issues

    def test_missing_trash_directory(self, tmp_path):
        mod = _get_module()
        # Don't create trash directory

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                result = mod.check(_make_profile())

        assert not result.has_issues


class TestTrashCleanupLocalTrash:
    def test_trash_with_single_file(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create a file in trash
        trash_file = trash / "deleted_file.txt"
        trash_file.write_text("deleted content")

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                result = mod.check(_make_profile())

        assert result.has_issues
        trash_status = next((f for f in result.findings if f.data.get("type") == "trash_status"), None)
        assert trash_status is not None
        assert trash_status.data["item_count"] == 1
        assert trash_status.data["size_bytes"] == len("deleted content")

    def test_trash_with_multiple_files(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create multiple files
        trash_file1 = trash / "file1.txt"
        trash_file1.write_text("content1")
        trash_file2 = trash / "file2.txt"
        trash_file2.write_text("content2")

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                result = mod.check(_make_profile())

        assert result.has_issues
        trash_status = next((f for f in result.findings if f.data.get("type") == "trash_status"), None)
        assert trash_status is not None
        assert trash_status.data["item_count"] == 2

    def test_trash_with_directory(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create a directory in trash with files
        deleted_dir = trash / "deleted_app"
        deleted_dir.mkdir()
        (deleted_dir / "file1.txt").write_text("content1")
        (deleted_dir / "file2.txt").write_text("content2")

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                result = mod.check(_make_profile())

        assert result.has_issues
        trash_status = next((f for f in result.findings if f.data.get("type") == "trash_status"), None)
        assert trash_status is not None
        # Directory + 2 files = 3 items
        assert trash_status.data["item_count"] == 3
        assert trash_status.data["size_bytes"] > 0


class TestTrashCleanupLargeTrashWarning:
    def test_warning_for_large_trash_5gb(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create a small file to satisfy mock
        small_file = downloads / "dummy"
        small_file.write_text("x")

        # Mock _scan_trash to return > 5GB
        large_trash_size = 5 * 1024 * 1024 * 1024 + 100 * 1024 * 1024
        with patch.object(mod, "_scan_trash", return_value={"size": large_trash_size, "count": 500}):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                with patch.object(Path, "home", return_value=tmp_path):
                    result = mod.check(_make_profile())

        # Should have warning
        large_trash_warning = next((f for f in result.findings if f.data.get("type") == "large_trash"), None)
        assert large_trash_warning is not None
        assert large_trash_warning.severity == Severity.WARNING

    def test_no_warning_under_5gb(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create small file (under 5GB threshold)
        trash_file = trash / "small_file.txt"
        trash_file.write_text("small content")

        with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

        # Should not have large_trash warning
        large_trash_warning = next((f for f in result.findings if f.data.get("type") == "large_trash"), None)
        assert large_trash_warning is None


class TestTrashCleanupTooManyItemsWarning:
    def test_warning_for_1000_items(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Mock _scan_trash to return > 1000 items
        with patch.object(mod, "_scan_trash", return_value={"size": 100 * 1024 * 1024, "count": 1050}):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                with patch.object(Path, "home", return_value=tmp_path):
                    result = mod.check(_make_profile())

        # Should have warning for too many items
        too_many_items_warning = next((f for f in result.findings if f.data.get("type") == "too_many_trash_items"), None)
        assert too_many_items_warning is not None
        assert too_many_items_warning.severity == Severity.WARNING

    def test_no_warning_under_1000_items(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create files, just under 1000 items
        for i in range(500):
            (trash / f"file{i}.txt").write_text("x")

        with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

        # Should not have too_many_trash_items warning
        too_many_items_warning = next((f for f in result.findings if f.data.get("type") == "too_many_trash_items"), None)
        assert too_many_items_warning is None


class TestTrashCleanupExternalTrash:
    def test_external_trash_detection(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Mock external trash scanning
        external_trash_size = 100 * 1024 * 1024
        external_item_count = 50

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": external_trash_size, "count": external_item_count}):
                result = mod.check(_make_profile())

        # Should find trash status with external trash included
        trash_status = next((f for f in result.findings if f.data.get("type") == "trash_status"), None)
        assert trash_status is not None
        assert trash_status.data["size_bytes"] >= external_trash_size

    def test_combined_local_and_external_trash(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create local trash
        local_file = trash / "local.txt"
        local_file.write_text("local content")

        # Mock external trash
        external_trash_size = 100 * 1024 * 1024
        external_item_count = 50

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": external_trash_size, "count": external_item_count}):
                result = mod.check(_make_profile())

        # Should combine both
        trash_status = next((f for f in result.findings if f.data.get("type") == "trash_status"), None)
        assert trash_status is not None
        assert trash_status.data["item_count"] > 50  # Local + external


class TestTrashCleanupCombinedWarnings:
    def test_both_warnings_large_and_many_items(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Mock both conditions: large size AND many items
        large_trash_size = 5 * 1024 * 1024 * 1024 + 100 * 1024 * 1024
        many_items = 1050

        with patch.object(mod, "_scan_trash", return_value={"size": large_trash_size, "count": many_items}):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                with patch.object(Path, "home", return_value=tmp_path):
                    result = mod.check(_make_profile())

        # Should have both warnings plus status
        large_trash_warning = next((f for f in result.findings if f.data.get("type") == "large_trash"), None)
        too_many_items_warning = next((f for f in result.findings if f.data.get("type") == "too_many_trash_items"), None)
        trash_status = next((f for f in result.findings if f.data.get("type") == "trash_status"), None)

        assert large_trash_warning is not None
        assert too_many_items_warning is not None
        assert trash_status is not None
        assert large_trash_warning in result.findings[:2]  # Warnings first


class TestTrashCleanupFix:
    def test_fix_returns_informational_actions(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create a file
        trash_file = trash / "deleted.txt"
        trash_file.write_text("content")

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        assert fix.all_succeeded
        assert len(fix.actions) > 0
        assert all(a.success for a in fix.actions)
        assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)

    def test_fix_never_deletes_files(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create a file
        trash_file = trash / "deleted.txt"
        trash_file.write_text("content")

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        # Verify file still exists (fix is informational only)
        assert trash_file.exists()

    def test_fix_includes_instructions(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create a file
        trash_file = trash / "deleted.txt"
        trash_file.write_text("content")

        with patch.object(Path, "home", return_value=tmp_path):
            with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        # Verify actions contain clear instructions
        descriptions = " ".join(a.description for a in fix.actions)
        assert "Empty Trash" in descriptions or "empty trash" in descriptions or "rm -rf" in descriptions


class TestTrashCleanupErrorHandling:
    def test_permission_error_handling(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create a file
        test_file = trash / "test.txt"
        test_file.write_text("test")

        # Remove read permissions
        try:
            trash.chmod(0o000)

            with patch.object(Path, "home", return_value=tmp_path):
                with patch.object(mod, "_scan_external_trash", return_value={"size": 0, "count": 0}):
                    result = mod.check(_make_profile())

            # Should handle gracefully
            assert isinstance(result.findings, list)
        finally:
            # Restore permissions
            trash.chmod(0o755)

    def test_nonexistent_volumes_dir(self):
        mod = _get_module()

        # Mock Path to simulate /Volumes not existing
        def mock_volumes_exists():
            return False

        with patch.object(Path, "exists", side_effect=lambda: mock_volumes_exists()):
            result = mod._scan_external_trash()

        assert result["size"] == 0
        assert result["count"] == 0
