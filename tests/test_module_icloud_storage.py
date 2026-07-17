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
    return next(m for m in modules if m.name == "icloud_storage")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: iCloud storage under 90%, small cache, no sync enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "MobileMeAccounts" in cmd_str:
            # Return mock iCloud storage info: 200GB quota, 50GB used
            return _make_subprocess_result(
                """(
    MobileMeAccountDisplay = "user@icloud.com";
    StorageQuota = 214748364800;
    StorageUsageTotal = 53687091200;
)"""
            )
        elif "iCloudDriveEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "DesktopAndDocumentsManagedByiCloud" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="does not exist")
        return _make_subprocess_result()
    return fake_run


def _fake_run_storage_full():
    """iCloud storage >90% full"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "MobileMeAccounts" in cmd_str:
            # Return mock iCloud storage info: 200GB quota, 190GB used (95%)
            return _make_subprocess_result(
                """(
    MobileMeAccountDisplay = "user@icloud.com";
    StorageQuota = 214748364800;
    StorageUsageTotal = 204204518400;
)"""
            )
        elif "iCloudDriveEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "DesktopAndDocumentsManagedByiCloud" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="does not exist")
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_icloud():
    """iCloud not available"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="does not exist")
        elif "iCloudDriveEnabled" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="does not exist")
        elif "DesktopAndDocumentsManagedByiCloud" in cmd_str:
            return _make_subprocess_result(returncode=1, stderr="does not exist")
        return _make_subprocess_result()
    return fake_run


def _fake_run_desktop_docs_sync():
    """Desktop & Documents sync enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "MobileMeAccounts" in cmd_str:
            return _make_subprocess_result(
                """(
    MobileMeAccountDisplay = "user@icloud.com";
    StorageQuota = 214748364800;
    StorageUsageTotal = 53687091200;
)"""
            )
        elif "iCloudDriveEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        elif "DesktopAndDocumentsManagedByiCloud" in cmd_str:
            return _make_subprocess_result(stdout="1\n")
        return _make_subprocess_result()
    return fake_run


def test_icloud_storage_discovered():
    mod = _get_module()
    assert mod.name == "icloud_storage"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_icloud_storage_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(Path, "exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have findings but no critical warnings
    assert result.has_issues
    # Should have iCloud storage info
    assert any(f.data.get("check") == "icloud_storage" for f in result.findings)
    # Should all be INFO or WARNING, but not for storage being full
    storage_findings = [f for f in result.findings if f.data.get("check") == "icloud_storage"]
    assert storage_findings[0].severity == Severity.INFO


def test_icloud_storage_full():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_storage_full()):
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(Path, "exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have findings with WARNING for storage full
    assert result.has_issues
    storage_findings = [f for f in result.findings if f.data.get("check") == "icloud_storage"]
    assert len(storage_findings) > 0
    assert storage_findings[0].severity == Severity.WARNING


def test_icloud_storage_no_icloud():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_no_icloud()):
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(Path, "exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have finding about unavailable iCloud
    assert result.has_issues
    assert any(
        f.data.get("check") == "icloud_storage" and not f.data.get("available", True)
        for f in result.findings
    )


def test_icloud_storage_desktop_docs_sync():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_desktop_docs_sync()):
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(Path, "exists", return_value=False):
                result = mod.check(_make_profile())
    # Should have findings about Desktop & Documents sync
    assert result.has_issues
    assert any(
        f.data.get("check") == "desktop_docs_sync" and f.data.get("enabled")
        for f in result.findings
    )


def test_icloud_storage_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_storage_full()):
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(Path, "exists", return_value=False):
                check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) > 0


def test_icloud_storage_check_result_attributes():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.exists", return_value=False):
            with patch.object(Path, "exists", return_value=False):
                result = mod.check(_make_profile())
    # Check that findings have required attributes
    for finding in result.findings:
        assert finding.title
        assert finding.description
        assert finding.severity in [Severity.INFO, Severity.WARNING, Severity.CRITICAL]
        assert finding.category == "integrity"
        assert isinstance(finding.data, dict)
