import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


# Realistic reg query output examples

RDP_DISABLED = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
    fDenyTSConnections    REG_DWORD    0x1
"""

RDP_ENABLED = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server
    fDenyTSConnections    REG_DWORD    0x0
"""

NLA_ENABLED = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    UserAuthentication    REG_DWORD    0x1
"""

NLA_DISABLED = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    UserAuthentication    REG_DWORD    0x0
"""

PORT_DEFAULT = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    PortNumber    REG_DWORD    0xd3d
"""

PORT_CUSTOM = r"""
HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Terminal Server\WinStations\RDP-Tcp
    PortNumber    REG_DWORD    0x1869
"""

REG_QUERY_ERROR = ""


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.22621",
        architecture="AMD64",
        cpu_model="Intel(R) Core(TM) i7-9700K",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_rdp_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _check_reg_query(cmd, value_name):
    """Helper to check if a reg query command matches a specific value name"""
    # cmd is a list like ["reg", "query", "path", "/v", "fDenyTSConnections"]
    return isinstance(cmd, list) and len(cmd) >= 5 and cmd[-1] == value_name


def _fake_run_rdp_disabled():
    """RDP is disabled (secure default)"""
    def fake_run(cmd, **kwargs):
        if _check_reg_query(cmd, "fDenyTSConnections"):
            return _make_subprocess_result(stdout=RDP_DISABLED)
        elif _check_reg_query(cmd, "UserAuthentication"):
            return _make_subprocess_result(stdout=NLA_DISABLED)
        elif _check_reg_query(cmd, "PortNumber"):
            return _make_subprocess_result(stdout=PORT_DEFAULT)
        return _make_subprocess_result()
    return fake_run


def _fake_run_rdp_enabled_with_nla():
    """RDP is enabled with NLA (less risky but unnecessary)"""
    def fake_run(cmd, **kwargs):
        if _check_reg_query(cmd, "fDenyTSConnections"):
            return _make_subprocess_result(stdout=RDP_ENABLED)
        elif _check_reg_query(cmd, "UserAuthentication"):
            return _make_subprocess_result(stdout=NLA_ENABLED)
        elif _check_reg_query(cmd, "PortNumber"):
            return _make_subprocess_result(stdout=PORT_DEFAULT)
        return _make_subprocess_result()
    return fake_run


def _fake_run_rdp_enabled_without_nla():
    """RDP is enabled without NLA (critical security risk)"""
    def fake_run(cmd, **kwargs):
        if _check_reg_query(cmd, "fDenyTSConnections"):
            return _make_subprocess_result(stdout=RDP_ENABLED)
        elif _check_reg_query(cmd, "UserAuthentication"):
            return _make_subprocess_result(stdout=NLA_DISABLED)
        elif _check_reg_query(cmd, "PortNumber"):
            return _make_subprocess_result(stdout=PORT_DEFAULT)
        return _make_subprocess_result()
    return fake_run


def _fake_run_rdp_enabled_custom_port():
    """RDP is enabled on a custom port with NLA"""
    def fake_run(cmd, **kwargs):
        if _check_reg_query(cmd, "fDenyTSConnections"):
            return _make_subprocess_result(stdout=RDP_ENABLED)
        elif _check_reg_query(cmd, "UserAuthentication"):
            return _make_subprocess_result(stdout=NLA_ENABLED)
        elif _check_reg_query(cmd, "PortNumber"):
            return _make_subprocess_result(stdout=PORT_CUSTOM)
        return _make_subprocess_result()
    return fake_run


def _fake_run_reg_error():
    """Registry queries fail (e.g., no RDP installed)"""
    def fake_run(cmd, **kwargs):
        return _make_subprocess_result(stdout="", returncode=1)
    return fake_run


def test_win_rdp_check_discovered():
    mod = _get_module()
    assert mod.name == "win_rdp_check"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_rdp_check_disabled_is_info():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_rdp_disabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["rdp_enabled"] is False


def test_win_rdp_check_enabled_with_nla_is_warning():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_rdp_enabled_with_nla()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["rdp_enabled"] is True
    assert result.findings[0].data["nla_enabled"] is True


def test_win_rdp_check_enabled_without_nla_is_critical():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_rdp_enabled_without_nla()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].severity == Severity.CRITICAL
    assert result.findings[0].data["rdp_enabled"] is True
    assert result.findings[0].data["nla_enabled"] is False


def test_win_rdp_check_custom_port():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_rdp_enabled_custom_port()):
        result = mod.check(_make_profile())
    assert result.has_issues
    # 0x1869 = 6249 in decimal
    assert result.findings[0].data["rdp_port"] == 6249


def test_win_rdp_check_reg_error_defaults_to_disabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_reg_error()):
        result = mod.check(_make_profile())
    # When reg queries fail, we assume RDP is disabled (safe default)
    assert result.has_issues
    assert result.findings[0].severity == Severity.INFO
    assert result.findings[0].data["rdp_enabled"] is False


def test_win_rdp_check_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_rdp_enabled_without_nla()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.win_rdp_check.") for c in declared)
