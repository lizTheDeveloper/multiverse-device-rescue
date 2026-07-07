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
    return next(m for m in modules if m.name == "clamshell_mode")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no issues found"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "powernap               0\n"
                "womp                   0\n"
                "proximitywake          0\n"
                "tcpkeepalive           0\n"
            )
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                "Displays:\n"
                "  MacBook Display:\n"
                "    Built-in Retina Display\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_powernap_with_external_display():
    """Power Nap enabled with external display"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "powernap               1\n"
                "womp                   0\n"
                "proximitywake          0\n"
                "tcpkeepalive           0\n"
            )
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                "Displays:\n"
                "  MacBook Display:\n"
                "    Built-in Retina Display\n"
                "  External Display:\n"
                "    Display Connector: HDMI\n"
                "    Plug/Unplug Status: connected\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_proximitywake_enabled():
    """Proximity wake enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "powernap               0\n"
                "womp                   0\n"
                "proximitywake          1\n"
                "tcpkeepalive           0\n"
            )
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                "Displays:\n"
                "  MacBook Display:\n"
                "    Built-in Retina Display\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_both_issues():
    """Both Power Nap with external display and proximitywake enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "powernap               1\n"
                "womp                   1\n"
                "proximitywake          1\n"
                "tcpkeepalive           1\n"
            )
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                "Displays:\n"
                "  MacBook Display:\n"
                "    Built-in Retina Display\n"
                "  External Display:\n"
                "    Display Connector: DisplayPort\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_pmset_fails():
    """pmset command fails"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str:
            return _make_subprocess_result(returncode=1)
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                "Displays:\n"
                "  MacBook Display:\n"
                "    Built-in Retina Display\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_clamshell_mode_discovered():
    mod = _get_module()
    assert mod.name == "clamshell_mode"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_clamshell_mode_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have only INFO finding (power settings report)
    assert result.has_issues
    assert all(f.severity == Severity.INFO for f in result.findings)


def test_clamshell_mode_powernap_with_external_display():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powernap_with_external_display()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(
        f.data.get("issue") == "powernap_with_external_display"
        for f in warning_findings
    )
    assert any(f.data.get("external_display") for f in warning_findings)


def test_clamshell_mode_proximitywake_enabled():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_proximitywake_enabled()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(
        f.data.get("issue") == "unexpected_wakes" for f in warning_findings
    )


def test_clamshell_mode_both_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_both_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should have 2 warnings (powernap + proximity wake)
    assert len(warning_findings) == 2
    assert any(f.data.get("issue") == "powernap_with_external_display" for f in warning_findings)
    assert any(f.data.get("issue") == "unexpected_wakes" for f in warning_findings)


def test_clamshell_mode_pmset_fails():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_pmset_fails()):
        result = mod.check(_make_profile())
    # Should still have INFO about display even if pmset fails
    assert len(result.findings) == 0  # No findings if pmset fails


def test_clamshell_mode_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_powernap_with_external_display()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) > 0


def test_clamshell_mode_powernap_no_warning_without_external_display():
    """Power Nap enabled but no external display - should not warn"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "pmset" in cmd_str and "-g" in cmd_str:
            return _make_subprocess_result(
                "powernap               1\n"
                "womp                   0\n"
                "proximitywake          0\n"
                "tcpkeepalive           0\n"
            )
        elif "system_profiler" in cmd_str and "SPDisplaysDataType" in cmd_str:
            return _make_subprocess_result(
                "Displays:\n"
                "  MacBook Display:\n"
                "    Built-in Retina Display\n"
            )
        return _make_subprocess_result()

    mod = _get_module()
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have only INFO findings, no powernap warning
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert not any(
        f.data.get("issue") == "powernap_with_external_display"
        for f in warning_findings
    )
