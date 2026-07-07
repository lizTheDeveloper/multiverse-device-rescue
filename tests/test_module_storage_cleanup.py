import sys
import os
from pathlib import Path
from datetime import datetime, timedelta
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
    return next(m for m in modules if m.name == "storage_cleanup")


class TestStorageCleanupDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "storage_cleanup"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 70
        assert mod.estimated_duration == "15s"
        assert mod.depends_on == []


class TestStorageCleanupOldDownloads:
    def test_old_downloads_empty(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())
        assert not result.has_issues

    def test_old_downloads_single_file(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create a file older than 90 days
        old_file = downloads / "old_file.txt"
        old_file.write_text("test")
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_file, (old_time, old_time))

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert result.has_issues
        old_downloads = next((f for f in result.findings if f.data.get("type") == "old_downloads"), None)
        assert old_downloads is not None
        assert old_downloads.data["file_count"] == 1
        assert old_downloads.data["size_bytes"] == 4

    def test_old_downloads_recent_file_ignored(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create a recent file
        recent_file = downloads / "recent_file.txt"
        recent_file.write_text("test")

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert not result.has_issues


class TestStorageCleanupLargeCaches:
    def test_large_caches_empty(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert not result.has_issues

    def test_large_caches_detection(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Mock _get_directory_size to return a large size
        with patch.object(mod, "_get_directory_size", return_value=600 * 1024 * 1024):
            app_cache = caches / "com.example.app"
            app_cache.mkdir()

            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

        assert result.has_issues
        large_caches = next((f for f in result.findings if f.data.get("type") == "large_caches"), None)
        assert large_caches is not None
        assert large_caches.data["directory_count"] == 1

    def test_small_caches_ignored(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create a small cache directory
        app_cache = caches / "com.example.app"
        app_cache.mkdir()
        small_file = app_cache / "cache.dat"
        small_file.write_bytes(b"x" * (100 * 1024 * 1024))  # 100 MB

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        # Should not detect small caches
        large_caches = next((f for f in result.findings if f.data.get("type") == "large_caches"), None)
        assert large_caches is None


class TestStorageCleanupTrash:
    def test_trash_empty(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert not result.has_issues

    def test_trash_with_files(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create files in trash
        trash_file = trash / "deleted_file.txt"
        trash_file.write_text("deleted content")

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert result.has_issues
        trash_finding = next((f for f in result.findings if f.data.get("type") == "trash"), None)
        assert trash_finding is not None
        assert trash_finding.data["size_bytes"] == len("deleted content")

    def test_trash_with_directories(self, tmp_path):
        mod = _get_module()
        trash = tmp_path / ".Trash"
        trash.mkdir()

        # Create directory with files in trash
        deleted_dir = trash / "deleted_app"
        deleted_dir.mkdir()
        (deleted_dir / "file1.txt").write_text("content1")
        (deleted_dir / "file2.txt").write_text("content2")

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert result.has_issues
        trash_finding = next((f for f in result.findings if f.data.get("type") == "trash"), None)
        assert trash_finding is not None
        # Should include both files
        assert trash_finding.data["size_bytes"] > 0


class TestStorageCleanupDmgFiles:
    def test_no_dmg_files(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        dmg_finding = next((f for f in result.findings if f.data.get("type") == "dmg_files"), None)
        assert dmg_finding is None

    def test_dmg_files_detected(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create .dmg files
        dmg1 = downloads / "installer1.dmg"
        dmg1.write_bytes(b"x" * 1000)  # Small file for testing
        dmg2 = downloads / "installer2.dmg"
        dmg2.write_bytes(b"x" * 2000)  # Small file for testing

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        dmg_finding = next((f for f in result.findings if f.data.get("type") == "dmg_files"), None)
        assert dmg_finding is not None
        assert dmg_finding.data["file_count"] == 2
        assert dmg_finding.data["size_bytes"] == 3000

    def test_dmg_case_insensitive(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create .DMG file (uppercase)
        dmg = downloads / "installer.DMG"
        dmg.write_bytes(b"x" * 100)

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        dmg_finding = next((f for f in result.findings if f.data.get("type") == "dmg_files"), None)
        assert dmg_finding is not None
        assert dmg_finding.data["file_count"] == 1


class TestStorageCleanupAppSupport:
    def test_app_support_empty(self, tmp_path):
        mod = _get_module()
        app_support = tmp_path / "Library" / "Application Support"
        app_support.mkdir(parents=True)

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert not result.has_issues

    def test_app_support_directories(self, tmp_path):
        mod = _get_module()
        app_support = tmp_path / "Library" / "Application Support"
        app_support.mkdir(parents=True)

        # Create app support directories
        app1 = app_support / "com.example.app1"
        app1.mkdir()
        (app1 / "data.plist").write_text("plist content")

        app2 = app_support / "com.example.app2"
        app2.mkdir()
        (app2 / "config.json").write_text("json content")

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        app_support_finding = next((f for f in result.findings if f.data.get("type") == "app_support"), None)
        assert app_support_finding is not None
        assert app_support_finding.data["directory_count"] == 2


class TestStorageCleanupWarningThreshold:
    def test_warning_triggered_at_1gb(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create a file and mock _scan_old_downloads to return > 1GB
        old_file = downloads / "large_old_file"
        old_file.write_text("test")

        with patch.object(mod, "_scan_old_downloads", return_value={"size": 1024 * 1024 * 1024 + 100 * 1024 * 1024, "count": 1}):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

        # Should have warning finding
        warning_finding = next((f for f in result.findings if f.severity == Severity.WARNING), None)
        assert warning_finding is not None
        assert warning_finding.data.get("type") == "total_reclaimable"

    def test_no_warning_under_1gb(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create a file with old timestamp (under threshold)
        old_file = downloads / "medium_old_file"
        old_file.write_text("test")
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_file, (old_time, old_time))

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        # Should not have warning
        warning_finding = next((f for f in result.findings if f.severity == Severity.WARNING), None)
        assert warning_finding is None


class TestStorageCleanupFix:
    def test_fix_returns_actions(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        old_file = downloads / "old_file.txt"
        old_file.write_text("test")
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_file, (old_time, old_time))

        with patch.object(Path, "home", return_value=tmp_path):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

        assert fix.all_succeeded
        assert len(fix.actions) > 0
        assert all(a.success for a in fix.actions)
        assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)

    def test_fix_informational_only(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create multiple types of files
        old_file = downloads / "old_file.txt"
        old_file.write_text("test content here")
        old_time = (datetime.now() - timedelta(days=100)).timestamp()
        os.utime(old_file, (old_time, old_time))

        dmg_file = downloads / "installer.dmg"
        dmg_file.write_bytes(b"x" * 1000)

        with patch.object(Path, "home", return_value=tmp_path):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

        # Verify actions are informational and don't delete files
        assert fix.all_succeeded
        for action in fix.actions:
            assert action.success
            assert "to clean:" in action.description.lower() or \
                   "remove" in action.description.lower() or \
                   "delete" in action.description.lower() or \
                   "clean" in action.description.lower()

        # Verify original files still exist
        assert old_file.exists()
        assert dmg_file.exists()


class TestStorageCleanupErrorHandling:
    def test_permission_error_handling(self, tmp_path):
        mod = _get_module()
        downloads = tmp_path / "Downloads"
        downloads.mkdir()

        # Create a file
        test_file = downloads / "test.txt"
        test_file.write_text("test")

        # Remove read permissions (may not work on all systems)
        try:
            downloads.chmod(0o000)

            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

            # Should handle gracefully without crashing
            assert isinstance(result.findings, list)
        finally:
            # Restore permissions for cleanup
            downloads.chmod(0o755)

    def test_missing_directories_ignored(self, tmp_path):
        mod = _get_module()
        # Create minimal home structure
        (tmp_path / "Downloads").mkdir()

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        # Should not crash on missing directories
        assert isinstance(result.findings, list)
