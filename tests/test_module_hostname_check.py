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
    return next(m for m in modules if m.name == "hostname_check")


def _fake_run(computer_name, local_hostname, hostname=None, error=None):
    """Mock subprocess.run for scutil calls."""
    def fake_run(cmd, **kwargs):
        if error:
            raise error
        result = MagicMock()
        if cmd == ["scutil", "--get", "ComputerName"]:
            result.stdout = computer_name
            result.returncode = 0
        elif cmd == ["scutil", "--get", "LocalHostName"]:
            result.stdout = local_hostname
            result.returncode = 0
        elif cmd == ["scutil", "--get", "HostName"]:
            if hostname is None:
                result.returncode = 1  # Not set
                result.stdout = ""
            else:
                result.stdout = hostname
                result.returncode = 0
        else:
            raise AssertionError(f"unexpected command {cmd}")
        return result
    return fake_run


def test_hostname_check_discovered():
    mod = _get_module()
    assert mod.name == "hostname_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_hostname_check_healthy_consistent():
    """Test when all hostnames are consistent and normal."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("MyMac", "mymac", "mymac")):
        result = mod.check(_make_profile())
    # Should only have INFO about configured names, no warnings
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_hostname_check_inconsistent_names():
    """Test WARNING when ComputerName and LocalHostName are inconsistent."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("MyMac", "othername", "othername")):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("inconsistent" in f.title.lower() for f in warnings)


def test_hostname_check_hostname_with_spaces():
    """Test WARNING when hostname contains spaces."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("My Mac", "my-mac", "my-mac")):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("space" in f.title.lower() or "invalid" in f.title.lower() for f in warnings)


def test_hostname_check_default_mac():
    """Test WARNING for default 'Mac' hostname."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("Mac", "mac", "mac")):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("default" in f.title.lower() or "Mac" in f.title for f in warnings)


def test_hostname_check_default_macbook():
    """Test WARNING for default 'MacBook' hostname."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("MacBook", "macbook", "macbook")):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("default" in f.title.lower() or "MacBook" in f.title for f in warnings)


def test_hostname_check_special_characters():
    """Test WARNING when hostname contains special characters."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("MyMac@Home", "mymac-home", "mymac@home")):
        result = mod.check(_make_profile())
    assert result.has_issues
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("special" in f.title.lower() or "character" in f.title.lower() for f in warnings)


def test_hostname_check_hostname_not_set():
    """Test when HostName is not set (returncode 1)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("MyMac", "mymac", hostname=None)):
        result = mod.check(_make_profile())
    # Should not crash, may or may not have findings depending on other names


def test_hostname_check_subprocess_error():
    """Test graceful handling of scutil errors."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("", "", error=OSError("scutil not found"))):
        result = mod.check(_make_profile())
    # Should not crash


def test_hostname_check_fix_is_informational():
    """Test that fix() is informational and doesn't modify system."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run("MyMac", "othername", "othername")):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)
    # fix() should succeed but only provide guidance
    assert fix.all_succeeded
    for action in fix.actions:
        assert "scutil" in action.description or "system" in action.description.lower()
