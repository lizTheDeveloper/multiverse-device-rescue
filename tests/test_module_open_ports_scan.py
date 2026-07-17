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
    return next(m for m in modules if m.name == "open_ports_scan")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_no_ports():
    """No listening ports"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "lsof" in cmd[0]:
            return _make_subprocess_result(
                "COMMAND  PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_normal_ports():
    """Normal listening ports: SSH and HTTP"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "lsof" in cmd[0]:
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "sshd      123 root   4  IPv4  0x123456 0t0 TCP 0.0.0.0:22 (LISTEN)\n"
                "nginx     456 www    5  IPv4  0x234567 0t0 TCP 0.0.0.0:80 (LISTEN)\n"
                "nginx     456 www    6  IPv4  0x345678 0t0 TCP 0.0.0.0:443 (LISTEN)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_exposed_mysql():
    """MySQL exposed to 0.0.0.0 - risky"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "lsof" in cmd[0]:
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "sshd      123 root   4  IPv4  0x123456 0t0 TCP 0.0.0.0:22 (LISTEN)\n"
                "mysqld    789 mysql  7  IPv4  0x456789 0t0 TCP 0.0.0.0:3306 (LISTEN)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_localhost_mysql():
    """MySQL bound to localhost - safe"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "lsof" in cmd[0]:
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "mysqld    789 mysql  7  IPv4  0x456789 0t0 TCP 127.0.0.1:3306 (LISTEN)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_risky():
    """Multiple risky ports exposed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and "lsof" in cmd[0]:
            return _make_subprocess_result(
                "COMMAND   PID  USER  FD   TYPE             DEVICE SIZE/OFF NODE NAME\n"
                "mysqld    123 mysql  4  IPv4  0x123456 0t0 TCP 0.0.0.0:3306 (LISTEN)\n"
                "postgres  456 postgres 5 IPv4 0x234567 0t0 TCP 0.0.0.0:5432 (LISTEN)\n"
                "mongod    789 mongodb  6  IPv4  0x345678 0t0 TCP 0.0.0.0:27017 (LISTEN)\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_open_ports_scan_discovered():
    mod = _get_module()
    assert mod.name == "open_ports_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_open_ports_scan_no_ports():
    mod = _get_module()
    with patch("modules.security.open_ports_scan.subprocess.run", side_effect=_fake_run_no_ports()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_open_ports_scan_normal_ports():
    mod = _get_module()
    with patch("modules.security.open_ports_scan.subprocess.run", side_effect=_fake_run_normal_ports()):
        result = mod.check(_make_profile())
    # Normal ports should show as INFO, no warnings
    assert result.has_issues
    assert any(f.data.get("check") == "listening_ports" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_open_ports_scan_exposed_mysql():
    mod = _get_module()
    with patch("modules.security.open_ports_scan.subprocess.run", side_effect=_fake_run_exposed_mysql()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "exposed_risky_ports" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_open_ports_scan_localhost_mysql():
    mod = _get_module()
    with patch("modules.security.open_ports_scan.subprocess.run", side_effect=_fake_run_localhost_mysql()):
        result = mod.check(_make_profile())
    # MySQL on localhost is safe, should be INFO only
    assert result.has_issues
    assert any(f.data.get("check") == "listening_ports" for f in result.findings)
    assert not any(f.severity == Severity.WARNING for f in result.findings)


def test_open_ports_scan_multiple_risky():
    mod = _get_module()
    with patch("modules.security.open_ports_scan.subprocess.run", side_effect=_fake_run_multiple_risky()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have warning for exposed risky ports
    assert any(f.severity == Severity.WARNING for f in result.findings)
    # Should have info for listening ports
    assert any(f.data.get("check") == "listening_ports" for f in result.findings)


def test_open_ports_scan_fix_is_informational():
    mod = _get_module()
    with patch("modules.security.open_ports_scan.subprocess.run", side_effect=_fake_run_exposed_mysql()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action per finding
    assert len(fix.actions) > 0
