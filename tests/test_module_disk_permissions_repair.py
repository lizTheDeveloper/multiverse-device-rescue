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
    return next(m for m in modules if m.name == "disk_permissions_repair")


def _make_stat_result(st_uid=501, st_gid=20, st_mode=0o40755):
    """Create a mock stat result."""
    result = MagicMock()
    result.st_uid = st_uid
    result.st_gid = st_gid
    result.st_mode = st_mode
    return result


def _mock_owner_method(uid):
    """Return a mock owner method that returns the expected user."""
    def owner_method():
        if uid == 501:
            return "testuser"
        elif uid == 0:
            return "root"
        else:
            return f"user_{uid}"
    return owner_method


def _fake_run_healthy():
    """Normal case: no issues found"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "stat" in cmd_str and "%Su" in cmd_str:
            result = MagicMock()
            result.returncode = 0
            result.stdout = "testuser\n"
            result.stderr = ""
            return result
        return MagicMock(returncode=0, stdout="", stderr="")

    return fake_run


def _fake_run_home_ownership_mismatch():
    """Home directory owned by wrong user"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "stat" in cmd_str and "%Su" in cmd_str:
            result = MagicMock()
            result.returncode = 0
            result.stdout = "root\n"
            result.stderr = ""
            return result
        return MagicMock(returncode=0, stdout="", stderr="")

    return fake_run


def _fake_run_tmp_permissions_bad():
    """stat result shows tmp has bad permissions"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "stat" in cmd_str and "%Su" in cmd_str:
            result = MagicMock()
            result.returncode = 0
            result.stdout = "testuser\n"
            result.stderr = ""
            return result
        return MagicMock(returncode=0, stdout="", stderr="")

    return fake_run


def test_disk_permissions_repair_discovered():
    """Module should be discoverable with correct metadata."""
    mod = _get_module()
    assert mod.name == "disk_permissions_repair"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_disk_permissions_repair_healthy():
    """Healthy case: no permission issues found."""
    mod = _get_module()

    def mock_stat(path_self):
        # Return healthy stat result based on path
        path_str = str(path_self)
        if "/tmp" in path_str or "/var/tmp" in path_str:
            # /tmp and /var/tmp need sticky bit + 777 permissions
            return _make_stat_result(st_uid=501, st_mode=0o41777)  # 0o40000 (dir) + 0o01000 (sticky) + 0o777 (perms)
        else:
            # Other directories: normal user directory
            return _make_stat_result(st_uid=501, st_mode=0o40755)

    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.stat", mock_stat):
                with patch("pathlib.Path.owner", return_value="testuser"):
                    with patch("os.access", return_value=True):
                        result = mod.check(_make_profile())
    # Should have an INFO finding indicating health
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_disk_permissions_repair_home_ownership_mismatch():
    """Home directory owned by wrong user."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_home_ownership_mismatch()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.stat", return_value=_make_stat_result(st_uid=501)):
                with patch("pathlib.Path.owner", return_value="testuser"):
                    with patch("os.access", return_value=True):
                        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(
        f.data.get("issue") == "home_ownership_mismatch" for f in result.findings
    )
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_disk_permissions_repair_tmp_permissions():
    """Check /tmp with bad permissions (no sticky bit)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.exists", return_value=True):
            # Regular directory mode without sticky bit (0o40755 = drwxr-xr-x)
            with patch("pathlib.Path.stat", return_value=_make_stat_result(st_uid=501, st_mode=0o40755)):
                with patch("pathlib.Path.owner", return_value="testuser"):
                    with patch("os.access", return_value=True):
                        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have a finding about tmp permissions
    tmp_findings = [f for f in result.findings if "/tmp" in f.title or "/var/tmp" in f.title]
    assert len(tmp_findings) > 0


def test_disk_permissions_repair_usr_local_root():
    """Check /usr/local owned by root (Homebrew issue)."""
    mod = _get_module()

    def mock_stat(path_self):
        # Return different stat results based on path
        path_str = str(path_self)
        if "/usr/local" in path_str:
            # /usr/local owned by root
            return _make_stat_result(st_uid=0, st_mode=0o40755)
        elif "/tmp" in path_str or "/var/tmp" in path_str:
            # /tmp and /var/tmp with correct sticky bit permissions
            return _make_stat_result(st_uid=501, st_mode=0o41777)
        else:
            # Other directories: normal user directory
            return _make_stat_result(st_uid=501, st_mode=0o40755)

    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.stat", mock_stat):
                with patch("pathlib.Path.owner", return_value="testuser"):
                    with patch("os.access", return_value=True):
                        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("issue") == "usr_local_root_owned" for f in result.findings)


def test_disk_permissions_repair_fix_is_informational():
    """fix() should always succeed with informational messages."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_home_ownership_mismatch()):
        with patch("pathlib.Path.exists", return_value=True):
            with patch("pathlib.Path.stat", return_value=_make_stat_result(st_uid=501)):
                with patch("pathlib.Path.owner", return_value="testuser"):
                    with patch("os.access", return_value=True):
                        check = mod.check(_make_profile())
                        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for the home ownership issue
    assert len(fix.actions) > 0
