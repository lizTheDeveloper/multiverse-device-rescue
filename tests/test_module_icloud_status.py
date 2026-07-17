import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile

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
    return next(m for m in modules if m.name == "icloud_status")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_not_signed_in():
    """iCloud is not signed in"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result(stderr="User defaults out of range.", returncode=1)
        elif "defaults read" in cmd_str and "iCloudDrive" in cmd_str:
            return _make_subprocess_result(stderr="", returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_signed_in_no_sync():
    """iCloud is signed in but Desktop & Documents sync is disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result(stdout="""(
    {
        MobileMeAccountDisplay = "alice@icloud.com";
    }
)
""")
        elif "defaults read" in cmd_str and "iCloudDrive" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result()
    return fake_run


def _fake_run_signed_in_with_sync():
    """iCloud is signed in and Desktop & Documents sync is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "defaults read" in cmd_str and "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result(stdout="""(
    {
        MobileMeAccountDisplay = "alice@icloud.com";
    }
)
""")
        elif "defaults read" in cmd_str and "iCloudDrive" in cmd_str:
            return _make_subprocess_result(stdout="1")
        return _make_subprocess_result()
    return fake_run


def test_icloud_status_discovered():
    mod = _get_module()
    assert mod.name == "icloud_status"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_icloud_status_not_signed_in():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_signed_in()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "icloud_account" for f in result.findings)


def test_icloud_status_signed_in_no_sync():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_signed_in_no_sync()):
        with patch.object(mod, '_count_icloud_placeholder_files', return_value=0):
            with patch.object(mod, '_get_icloud_cache_size', return_value=0):
                result = mod.check(_make_profile())
    # Should have at least one finding about account status
    assert len(result.findings) > 0
    assert any(f.data.get("check") == "icloud_account" for f in result.findings)


def test_icloud_status_signed_in_with_sync():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_signed_in_with_sync()):
        with patch.object(mod, '_count_icloud_placeholder_files', return_value=5):
            with patch.object(mod, '_get_icloud_cache_size', return_value=5 * 1024**3):
                result = mod.check(_make_profile())
    # Should have findings about iCloud status
    assert len(result.findings) > 0


def test_icloud_status_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_signed_in_with_sync()):
        with patch.object(mod, '_count_icloud_placeholder_files', return_value=5):
            with patch.object(mod, '_get_icloud_cache_size', return_value=5 * 1024**3):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded


def test_icloud_status_many_icloud_files():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_signed_in_with_sync()):
        with patch.object(mod, '_count_icloud_placeholder_files', return_value=50):
            with patch.object(mod, '_get_icloud_cache_size', return_value=5 * 1024**3):
                result = mod.check(_make_profile())
    # Should warn about sync issues if many .icloud files exist
    assert len(result.findings) > 0
    assert any(f.severity == Severity.WARNING for f in result.findings)
