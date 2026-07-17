import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
from datetime import datetime, timedelta

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
    return next(m for m in modules if m.name == "clamav_scanner")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_not_installed():
    """ClamAV is not installed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which clamscan" in cmd_str or (isinstance(cmd, list) and "clamscan" in cmd):
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_healthy():
    """ClamAV installed, up-to-date definitions, clamd running"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which clamscan" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "clamscan"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/clamscan\n")
        elif "which freshclam" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "freshclam"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/freshclam\n")
        elif "--version" in cmd_str or (isinstance(cmd, list) and "--version" in cmd):
            return _make_subprocess_result(stdout="ClamAV 0.103.7/26551/Wed Dec 19 12:31:08 2024\n")
        elif "sigtool" in cmd_str or (isinstance(cmd, list) and "sigtool" in cmd):
            return _make_subprocess_result(stdout="Version: 26551\nTime: 2024-12-19 12:31:08 +0000\n")
        elif "pgrep clamd" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "pgrep" and cmd[1] == "clamd"):
            return _make_subprocess_result(stdout="12345\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_outdated_definitions():
    """ClamAV installed but definitions are >30 days old"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which clamscan" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "clamscan"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/clamscan\n")
        elif "which freshclam" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "freshclam"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/freshclam\n")
        elif "--version" in cmd_str or (isinstance(cmd, list) and "--version" in cmd):
            return _make_subprocess_result(stdout="ClamAV 0.103.7/26551/Wed Dec 19 12:31:08 2024\n")
        elif "sigtool" in cmd_str or (isinstance(cmd, list) and "sigtool" in cmd):
            return _make_subprocess_result(stdout="Version: 26500\nTime: 2024-05-15 12:31:08 +0000\n")
        elif "pgrep clamd" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "pgrep" and cmd[1] == "clamd"):
            return _make_subprocess_result(stdout="12345\n")
        return _make_subprocess_result()
    return fake_run


def _fake_run_daemon_not_running():
    """ClamAV installed with fresh definitions but daemon not running"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which clamscan" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "clamscan"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/clamscan\n")
        elif "which freshclam" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "freshclam"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/freshclam\n")
        elif "--version" in cmd_str or (isinstance(cmd, list) and "--version" in cmd):
            return _make_subprocess_result(stdout="ClamAV 0.103.7/26551/Wed Dec 19 12:31:08 2024\n")
        elif "sigtool" in cmd_str or (isinstance(cmd, list) and "sigtool" in cmd):
            return _make_subprocess_result(stdout="Version: 26551\nTime: 2024-12-19 12:31:08 +0000\n")
        elif "pgrep clamd" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "pgrep" and cmd[1] == "clamd"):
            return _make_subprocess_result(returncode=1)  # Not running
        return _make_subprocess_result()
    return fake_run


def _fake_run_no_definitions():
    """ClamAV installed but no definitions found"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which clamscan" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "clamscan"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/clamscan\n")
        elif "which freshclam" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "which" and cmd[1] == "freshclam"):
            return _make_subprocess_result(stdout="/opt/homebrew/bin/freshclam\n")
        elif "--version" in cmd_str or (isinstance(cmd, list) and "--version" in cmd):
            return _make_subprocess_result(stdout="ClamAV 0.103.7/26551/Wed Dec 19 12:31:08 2024\n")
        elif "sigtool" in cmd_str or (isinstance(cmd, list) and "sigtool" in cmd):
            # Definitions not found
            return _make_subprocess_result(returncode=1)
        elif "pgrep clamd" in cmd_str or (isinstance(cmd, list) and len(cmd) > 0 and cmd[0] == "pgrep" and cmd[1] == "clamd"):
            return _make_subprocess_result(stdout="12345\n")
        return _make_subprocess_result()
    return fake_run


def test_clamav_scanner_discovered():
    """Test module is discovered"""
    mod = _get_module()
    assert mod.name == "clamav_scanner"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_clamav_not_installed():
    """ClamAV not installed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_installed()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["check"] == "clamav_not_installed"


def test_clamav_healthy():
    """ClamAV healthy: installed, definitions up-to-date, daemon running"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("os.path.exists", return_value=True):
            with patch("os.path.stat") as mock_stat:
                # Mock file modification time to be recent (within 30 days)
                mock_stat_result = MagicMock()
                mock_stat_result.st_mtime = datetime.now().timestamp()
                mock_stat = MagicMock(return_value=mock_stat_result)

                result = mod.check(_make_profile())

    assert result.has_issues  # Always has findings (INFO at minimum)
    # Check for version, definitions, and daemon running
    severity_list = [f.severity for f in result.findings]
    assert Severity.INFO in severity_list
    # Should NOT have CRITICAL (definitions outdated)
    critical_checks = [f.data.get("check") for f in result.findings if f.severity == Severity.CRITICAL]
    assert "clamav_outdated_definitions" not in critical_checks


def test_clamav_outdated_definitions():
    """ClamAV with outdated definitions (>30 days)"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_outdated_definitions()):
        with patch("os.path.exists", return_value=True):
            # Mock file modification time to be 45 days old
            mock_stat_result = MagicMock()
            old_time = datetime.now() - timedelta(days=45)
            mock_stat_result.st_mtime = old_time.timestamp()

            with patch("pathlib.Path.stat", return_value=mock_stat_result):
                result = mod.check(_make_profile())

    assert result.has_issues
    # Should have CRITICAL finding for outdated definitions
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any(f.data.get("check") == "clamav_outdated_definitions" for f in critical_findings)


def test_clamav_daemon_not_running():
    """ClamAV installed but daemon not running"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_daemon_not_running()):
        with patch("os.path.exists", return_value=True):
            with patch("os.path.stat") as mock_stat:
                mock_stat_result = MagicMock()
                mock_stat_result.st_mtime = datetime.now().timestamp()
                mock_stat = MagicMock(return_value=mock_stat_result)

                result = mod.check(_make_profile())

    assert result.has_issues
    # Should have WARNING for daemon not running
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check") == "clamd_not_running" for f in warning_findings)


def test_clamav_fix_not_installed():
    """Fix for ClamAV not installed"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_installed()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert any("Install ClamAV" in a.title for a in fix.actions)


def test_clamav_fix_outdated():
    """Fix for outdated definitions"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_outdated_definitions()):
        with patch("os.path.exists", return_value=True):
            mock_stat_result = MagicMock()
            old_time = datetime.now() - timedelta(days=45)
            mock_stat_result.st_mtime = old_time.timestamp()

            with patch("pathlib.Path.stat", return_value=mock_stat_result):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert any("Update ClamAV" in a.title for a in fix.actions)


def test_clamav_fix_daemon_not_running():
    """Fix for daemon not running"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_daemon_not_running()):
        with patch("os.path.exists", return_value=True):
            mock_stat_result = MagicMock()
            mock_stat_result.st_mtime = datetime.now().timestamp()

            with patch("pathlib.Path.stat", return_value=mock_stat_result):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert any("Start clamd" in a.title for a in fix.actions)


def test_clamav_fix_healthy():
    """Fix for healthy ClamAV state"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("os.path.exists", return_value=True):
            mock_stat_result = MagicMock()
            mock_stat_result.st_mtime = datetime.now().timestamp()

            with patch("pathlib.Path.stat", return_value=mock_stat_result):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    # Healthy state should have no actions needed
    assert len(fix.actions) == 0
