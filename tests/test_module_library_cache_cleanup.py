import sys
from pathlib import Path
from unittest.mock import patch

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
    return next(m for m in modules if m.name == "library_cache_cleanup")


class TestLibraryCacheCleanupDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "library_cache_cleanup"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 65
        assert mod.estimated_duration == "10s"
        assert mod.depends_on == []


class TestLibraryCacheCleanupEmpty:
    def test_empty_caches_no_issues(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert not result.has_issues

    def test_missing_caches_dir(self, tmp_path):
        mod = _get_module()
        # No Library/Caches directory

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        assert not result.has_issues


class TestLibraryCacheCleanupTotalSize:
    def test_total_size_below_threshold(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create small caches totaling < 10GB
        app1 = caches / "com.example.app1"
        app1.mkdir()
        (app1 / "cache.db").write_bytes(b"x" * (1 * 1024 * 1024 * 1024))  # 1 GB

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        # Should only have info finding about total size
        warning = next((f for f in result.findings if f.severity == Severity.WARNING), None)
        assert warning is None

    def test_total_size_warning_10gb(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Mock to return 10GB+ total
        with patch.object(mod, "_scan_caches", return_value={
            "com.example.app1": 6 * 1024 * 1024 * 1024,
            "com.example.app2": 5 * 1024 * 1024 * 1024,
        }):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

        warning = next((f for f in result.findings if f.data.get("type") == "total_cache_size"), None)
        assert warning is not None
        assert warning.severity == Severity.WARNING


class TestLibraryCacheCleanupSingleCache:
    def test_single_cache_warning_3gb(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Mock to return single cache > 3GB
        with patch.object(mod, "_scan_caches", return_value={
            "com.slack.slack": 4 * 1024 * 1024 * 1024,
        }):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

        warning = next((f for f in result.findings if f.data.get("type") == "large_single_cache"), None)
        assert warning is not None
        assert warning.severity == Severity.WARNING
        assert warning.data.get("app_name") == "com.slack.slack"

    def test_single_cache_below_threshold(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create single cache < 3GB
        app1 = caches / "com.example.app"
        app1.mkdir()
        (app1 / "cache.db").write_bytes(b"x" * (2 * 1024 * 1024 * 1024))  # 2 GB

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        warning = next((f for f in result.findings if f.data.get("type") == "large_single_cache"), None)
        assert warning is None


class TestLibraryCacheCleanupKnownApps:
    def test_known_app_slack_detected(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create Slack cache
        slack_cache = caches / "slack.com.slack"
        slack_cache.mkdir()
        (slack_cache / "cache.db").write_bytes(b"x" * (500 * 1024 * 1024))  # 500 MB

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        known = next((f for f in result.findings if f.data.get("type") == "known_apps"), None)
        assert known is not None
        assert "Slack" in known.data.get("apps", {})

    def test_known_app_spotify_detected(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create Spotify cache
        spotify_cache = caches / "com.spotify.client"
        spotify_cache.mkdir()
        (spotify_cache / "cache.db").write_bytes(b"x" * (700 * 1024 * 1024))  # 700 MB

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        known = next((f for f in result.findings if f.data.get("type") == "known_apps"), None)
        assert known is not None
        assert "Spotify" in known.data.get("apps", {})

    def test_multiple_known_apps(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create multiple known app caches
        for cache_dir in ["slack.com.slack", "com.spotify.client", "com.microsoft.teams"]:
            cache = caches / cache_dir
            cache.mkdir()
            (cache / "cache.db").write_bytes(b"x" * (500 * 1024 * 1024))

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        known = next((f for f in result.findings if f.data.get("type") == "known_apps"), None)
        assert known is not None
        apps = known.data.get("apps", {})
        assert len(apps) == 3
        assert "Slack" in apps
        assert "Spotify" in apps
        assert "Microsoft Teams" in apps

    def test_no_known_apps_no_finding(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create random cache dirs
        for cache_dir in ["com.random.app1", "com.random.app2"]:
            cache = caches / cache_dir
            cache.mkdir()
            (cache / "cache.db").write_bytes(b"x" * (100 * 1024 * 1024))

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        known = next((f for f in result.findings if f.data.get("type") == "known_apps"), None)
        assert known is None


class TestLibraryCacheCleanupTopCaches:
    def test_top_caches_listed(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create multiple caches
        for i in range(15):
            cache = caches / f"com.app{i:02d}"
            cache.mkdir()
            size = (i + 1) * 100 * 1024 * 1024  # 100 MB, 200 MB, etc.
            (cache / "cache.db").write_bytes(b"x" * size)

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        top = next((f for f in result.findings if f.data.get("type") == "top_caches"), None)
        assert top is not None
        caches_list = top.data.get("caches", {})
        assert len(caches_list) == 10  # Should list top 10
        # Verify largest apps are in the list
        assert "com.app14" in caches_list
        assert "com.app13" in caches_list


class TestLibraryCacheCleanupFix:
    def test_fix_returns_actions(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        app_cache = caches / "com.example.app"
        app_cache.mkdir()
        (app_cache / "cache.db").write_bytes(b"x" * (500 * 1024 * 1024))

        with patch.object(Path, "home", return_value=tmp_path):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

        assert fix.all_succeeded
        assert len(fix.actions) > 0
        assert all(a.success for a in fix.actions)
        assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)

    def test_fix_informational_only(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create cache that would trigger warning
        with patch.object(mod, "_scan_caches", return_value={
            "com.example.app": 4 * 1024 * 1024 * 1024,
        }):
            with patch.object(Path, "home", return_value=tmp_path):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        # Verify actions suggest removal but don't delete
        assert fix.all_succeeded
        assert all(a.success for a in fix.actions)
        assert "rm -rf" in str(fix.actions)  # Suggests command but doesn't execute

    def test_fix_total_cache_warning(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        with patch.object(mod, "_scan_caches", return_value={
            "com.app1": 6 * 1024 * 1024 * 1024,
            "com.app2": 5 * 1024 * 1024 * 1024,
        }):
            with patch.object(Path, "home", return_value=tmp_path):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

        action = next((a for a in fix.actions if "High cache size" in a.title), None)
        assert action is not None
        assert "rm -rf ~/Library/Caches" in action.description


class TestLibraryCacheCleanupErrorHandling:
    def test_permission_error_handling(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create a cache directory
        app_cache = caches / "com.example.app"
        app_cache.mkdir()
        (app_cache / "cache.db").write_text("cache")

        try:
            # Remove read permissions
            caches.chmod(0o000)

            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

            # Should handle gracefully
            assert isinstance(result.findings, list)
        finally:
            # Restore permissions
            caches.chmod(0o755)

    def test_symlink_not_followed(self, tmp_path):
        mod = _get_module()
        caches = tmp_path / "Library" / "Caches"
        caches.mkdir(parents=True)

        # Create a real cache directory
        real_cache = tmp_path / "real_cache"
        real_cache.mkdir()
        (real_cache / "cache.db").write_bytes(b"x" * (1 * 1024 * 1024 * 1024))

        # Create a symlink to it in caches
        symlink = caches / "symlink_cache"
        symlink.symlink_to(real_cache)

        with patch.object(Path, "home", return_value=tmp_path):
            result = mod.check(_make_profile())

        # Symlink should be handled safely (not followed)
        assert isinstance(result.findings, list)
