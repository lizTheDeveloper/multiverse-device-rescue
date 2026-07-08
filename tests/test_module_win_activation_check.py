import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    return next(m for m in modules if m.name == "win_activation_check")


def _make_run_result(xpr_output=None, dli_output=None):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # slmgr /xpr command
        if "/xpr" in cmd_str:
            if xpr_output is not None:
                result.stdout = xpr_output
            else:
                # Default: activated
                result.stdout = "The machine is permanently activated."

        # slmgr /dli command
        elif "/dli" in cmd_str:
            if dli_output is not None:
                result.stdout = dli_output
            else:
                # Default: activated, retail
                result.stdout = (
                    "Microsoft Windows 11 Pro\n"
                    "License Status: Initial grace period\n"
                    "License Edition: Retail\n"
                )

        return result

    return fake_run


def test_win_activation_check_discovered():
    mod = _get_module()
    assert mod.name == "win_activation_check"
    assert mod.category == "integrity"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_activation_check_activated():
    """Test when Windows is properly activated."""
    mod = _get_module()
    xpr = "The machine is permanently activated."
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Licensed\n"
        "License Edition: Retail\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "activated" for f in result.findings)
    activated = [f for f in result.findings if f.data.get("check") == "activated"]
    assert activated[0].severity == Severity.INFO


def test_win_activation_check_not_activated():
    """Test when Windows is in grace period (not yet activated)."""
    mod = _get_module()
    xpr = "The initial grace period"
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Initial grace period\n"
        "License Edition: Retail\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "grace_period" for f in result.findings)
    grace = [f for f in result.findings if f.data.get("check") == "grace_period"]
    assert grace[0].severity == Severity.WARNING


def test_win_activation_check_grace_period():
    """Test when Windows is in grace period."""
    mod = _get_module()
    xpr = "The initial grace period"
    dli = (
        "Microsoft Windows 11 Home\n"
        "License Status: Initial grace period\n"
        "License Edition: OEM\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "grace_period" for f in result.findings)
    grace = [f for f in result.findings if f.data.get("check") == "grace_period"]
    assert grace[0].severity == Severity.WARNING
    assert "OEM" in grace[0].description


def test_win_activation_check_volume_license():
    """Test with Volume license type."""
    mod = _get_module()
    xpr = "The machine is permanently activated."
    dli = (
        "Microsoft Windows 11 Enterprise\n"
        "License Status: Licensed\n"
        "License Edition: Volume\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "activated" for f in result.findings)
    activated = [f for f in result.findings if f.data.get("check") == "activated"]
    assert activated[0].severity == Severity.INFO
    assert "Volume" in activated[0].description


def test_win_activation_check_digital_license():
    """Test with digital license indicator."""
    mod = _get_module()
    xpr = "The machine is permanently activated."
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Licensed\n"
        "License Edition: Retail\n"
        "Digital License: Yes\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "activated" for f in result.findings)
    activated = [f for f in result.findings if f.data.get("check") == "activated"]
    assert activated[0].data.get("is_digital") is True


def test_win_activation_check_product_key():
    """Test with product key based license."""
    mod = _get_module()
    xpr = "The machine is permanently activated."
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Licensed\n"
        "License Edition: Retail\n"
        "Product Key: Available\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "activated" for f in result.findings)
    activated = [f for f in result.findings if f.data.get("check") == "activated"]
    assert activated[0].data.get("is_digital") is False


def test_win_activation_check_not_activated_critical():
    """Test when Windows is not activated (CRITICAL severity)."""
    mod = _get_module()
    xpr = "Notification"
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Notification\n"
        "License Edition: Retail\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "not_activated" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "not_activated"]
    assert critical[0].severity == Severity.CRITICAL


def test_win_activation_check_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should have a failure finding
    assert result.has_issues
    assert any(f.data.get("check") == "activation_check_failed" for f in result.findings)
    failed = [f for f in result.findings if f.data.get("check") == "activation_check_failed"]
    assert failed[0].severity == Severity.WARNING


def test_win_activation_check_fix_not_activated():
    """Test fix recommendation for not activated Windows."""
    mod = _get_module()
    xpr = "Notification"
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Notification\n"
        "License Edition: Volume\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    not_activated = [a for a in fix.actions if "not activated" in a.title.lower()]
    assert len(not_activated) > 0
    assert not_activated[0].success is True


def test_win_activation_check_fix_grace_period():
    """Test fix recommendation for grace period."""
    mod = _get_module()
    xpr = "Initial grace period"
    dli = (
        "Microsoft Windows 11 Home\n"
        "License Status: Initial grace period\n"
        "License Edition: OEM\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    grace_action = [a for a in fix.actions if "grace period" in a.title.lower()]
    assert len(grace_action) > 0
    assert grace_action[0].success is True


def test_win_activation_check_fix_activated():
    """Test fix recommendation when activated."""
    mod = _get_module()
    xpr = "The machine is permanently activated."
    dli = (
        "Microsoft Windows 11 Pro\n"
        "License Status: Licensed\n"
        "License Edition: Retail\n"
    )
    fake_run = _make_run_result(xpr_output=xpr, dli_output=dli)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    activated_action = [a for a in fix.actions if "properly activated" in a.title.lower()]
    assert len(activated_action) > 0
    assert activated_action[0].success is True
