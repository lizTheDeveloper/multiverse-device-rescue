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
    return next(m for m in modules if m.name == "keychain_health")


def _fake_run_healthy_keychain():
    """Mock subprocess for healthy keychain."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db" <unlocked>'
        elif "list-keychains" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db"\n"/Library/Keychains/System.keychain"'
        elif "default-keychain" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db"'
        return result
    return fake_run


def _fake_run_locked_keychain():
    """Mock subprocess for locked keychain."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db" <locked>'
        elif "list-keychains" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db"\n"/Library/Keychains/System.keychain"'
        elif "default-keychain" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db"'
        return result
    return fake_run


def _fake_run_wrong_default_keychain():
    """Mock subprocess for wrong default keychain."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "show-keychain-info" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db" <unlocked>'
        elif "list-keychains" in cmd_str:
            result.stdout = '"/Users/test/Library/Keychains/login.keychain-db"\n"/Library/Keychains/System.keychain"'
        elif "default-keychain" in cmd_str:
            result.stdout = '"/Library/Keychains/System.keychain"'
        return result
    return fake_run


def test_keychain_health_discovered():
    mod = _get_module()
    assert mod.name == "keychain_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_keychain_health_healthy(tmp_path):
    mod = _get_module()
    # Create fake keychain file
    keychain_dir = tmp_path / ".home" / "Library" / "Keychains"
    keychain_dir.mkdir(parents=True, exist_ok=True)
    keychain_file = keychain_dir / "login.keychain-db"
    keychain_file.write_bytes(b"fake keychain content")

    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = tmp_path / ".home"
        with patch("subprocess.run", side_effect=_fake_run_healthy_keychain()):
            result = mod.check(_make_profile())

    assert not result.has_issues or all(f.severity == Severity.INFO for f in result.findings)


def test_keychain_health_locked(tmp_path):
    mod = _get_module()
    # Create fake keychain file
    keychain_dir = tmp_path / ".home" / "Library" / "Keychains"
    keychain_dir.mkdir(parents=True, exist_ok=True)
    keychain_file = keychain_dir / "login.keychain-db"
    keychain_file.write_bytes(b"fake keychain content")

    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = tmp_path / ".home"
        with patch("subprocess.run", side_effect=_fake_run_locked_keychain()):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "keychain_locked" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_keychain_health_missing_keychain():
    mod = _get_module()
    # Don't create a keychain file, so it will be missing
    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = Path("/nonexistent/home")
        with patch("subprocess.run", side_effect=_fake_run_healthy_keychain()):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "missing_login_keychain" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_keychain_health_large_keychain(tmp_path):
    mod = _get_module()
    # Create a large fake keychain file (>100MB)
    keychain_dir = tmp_path / ".home" / "Library" / "Keychains"
    keychain_dir.mkdir(parents=True, exist_ok=True)
    keychain_file = keychain_dir / "login.keychain-db"
    # Create a file >100MB
    keychain_file.write_bytes(b"x" * (101 * 1024 * 1024))

    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = tmp_path / ".home"
        with patch("subprocess.run", side_effect=_fake_run_healthy_keychain()):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "large_keychain" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_keychain_health_wrong_default_keychain(tmp_path):
    mod = _get_module()
    # Create fake keychain file
    keychain_dir = tmp_path / ".home" / "Library" / "Keychains"
    keychain_dir.mkdir(parents=True, exist_ok=True)
    keychain_file = keychain_dir / "login.keychain-db"
    keychain_file.write_bytes(b"fake keychain content")

    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = tmp_path / ".home"
        with patch("subprocess.run", side_effect=_fake_run_wrong_default_keychain()):
            result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "default_keychain_mismatch" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_keychain_health_fix_locked(tmp_path):
    mod = _get_module()
    # Create fake keychain file
    keychain_dir = tmp_path / ".home" / "Library" / "Keychains"
    keychain_dir.mkdir(parents=True, exist_ok=True)
    keychain_file = keychain_dir / "login.keychain-db"
    keychain_file.write_bytes(b"fake keychain content")

    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = tmp_path / ".home"
        with patch("subprocess.run", side_effect=_fake_run_locked_keychain()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)


def test_keychain_health_fix_missing(tmp_path):
    mod = _get_module()
    # Don't create a keychain file
    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = Path("/nonexistent/home")
        with patch("subprocess.run", side_effect=_fake_run_healthy_keychain()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
    assert any("rebuild" in a.description.lower() or "restore" in a.description.lower() for a in fix.actions)


def test_keychain_health_fix_healthy(tmp_path):
    mod = _get_module()
    # Create fake keychain file
    keychain_dir = tmp_path / ".home" / "Library" / "Keychains"
    keychain_dir.mkdir(parents=True, exist_ok=True)
    keychain_file = keychain_dir / "login.keychain-db"
    keychain_file.write_bytes(b"fake keychain content")

    with patch("pathlib.Path.home") as mock_home:
        mock_home.return_value = tmp_path / ".home"
        with patch("subprocess.run", side_effect=_fake_run_healthy_keychain()):
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert all(a.success for a in fix.actions)
