import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, call

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="13.0",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "launchd_persistence_audit")


def _make_defaults_result(key_name, return_value, returncode=0):
    """Helper to create subprocess result for defaults read."""
    result = MagicMock()
    result.returncode = returncode
    result.stdout = str(return_value) if returncode == 0 else ""
    result.stderr = ""
    return result


def _make_fake_defaults_run(plist_data):
    """Create a fake subprocess.run for defaults command.

    plist_data is a dict where keys are plist filenames and values are dicts
    of {field_name: value} for each plist.
    """

    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list) and cmd[0] == "defaults" and cmd[1] == "read":
            plist_path = cmd[2]
            field_name = cmd[3] if len(cmd) > 3 else None

            # Extract plist filename for lookup
            plist_file = Path(plist_path).name
            plist_name = plist_file.replace(".plist", "")

            if plist_name in plist_data and field_name in plist_data[plist_name]:
                value = plist_data[plist_name][field_name]
                result = MagicMock()
                result.returncode = 0
                result.stdout = str(value) + "\n"
                result.stderr = ""
                return result
            else:
                result = MagicMock()
                result.returncode = 1
                result.stdout = ""
                result.stderr = ""
                return result

        return MagicMock(returncode=1, stdout="", stderr="")

    return fake_run


def test_launchd_persistence_audit_discovered():
    """Test that module is discovered with correct properties."""
    mod = _get_module()
    assert mod.name == "launchd_persistence_audit"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_launchd_persistence_audit_no_items():
    """Test when no launchd items are found."""
    mod = _get_module()

    with patch.object(Path, "exists", return_value=False):
        with patch.object(Path, "glob", return_value=[]):
            result = mod.check(_make_profile())

    assert not result.has_issues


def test_launchd_persistence_audit_known_malware():
    """Test detection of known malware labels."""
    mod = _get_module()

    plist_data = {
        "com.vsearch.helper": {
            "Label": "com.vsearch.helper",
            "Program": "/tmp/malware",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.vsearch.helper.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.vsearch.helper.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "known_malware" for f in result.findings)
    malware_finding = [f for f in result.findings if f.data.get("check") == "known_malware"]
    assert malware_finding[0].severity == Severity.CRITICAL


def test_launchd_persistence_audit_suspicious_path_tmp():
    """Test detection of launchd items in /tmp."""
    mod = _get_module()

    plist_data = {
        "com.example.app": {
            "Label": "com.example.app",
            "Program": "/tmp/suspicious",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.example.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.example.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "suspicious_path" for f in result.findings)
    path_finding = [f for f in result.findings if f.data.get("check") == "suspicious_path"]
    assert path_finding[0].severity == Severity.CRITICAL


def test_launchd_persistence_audit_suspicious_path_hidden():
    """Test detection of launchd items in hidden directories."""
    mod = _get_module()

    plist_data = {
        "com.example.app": {
            "Label": "com.example.app",
            "Program": "/Users/admin/.hidden/malware",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.example.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.example.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "suspicious_path" for f in result.findings)


def test_launchd_persistence_audit_keepalive_runatload():
    """Test detection of KeepAlive + RunAtLoad combination."""
    mod = _get_module()

    plist_data = {
        "com.thirdparty.app": {
            "Label": "com.thirdparty.app",
            "Program": "/Applications/App.app/Contents/MacOS/app",
            "KeepAlive": "1",
            "RunAtLoad": "1",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.thirdparty.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.thirdparty.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "keepalive_runatload" for f in result.findings)
    persist_finding = [
        f for f in result.findings if f.data.get("check") == "keepalive_runatload"
    ]
    assert persist_finding[0].severity == Severity.WARNING


def test_launchd_persistence_audit_non_apple_info():
    """Test that non-Apple items are flagged as INFO."""
    mod = _get_module()

    plist_data = {
        "com.thirdparty.app": {
            "Label": "com.thirdparty.app",
            "Program": "/Applications/App.app/Contents/MacOS/app",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.thirdparty.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.thirdparty.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "non_apple_info" for f in result.findings)
    info_finding = [f for f in result.findings if f.data.get("check") == "non_apple_info"]
    assert info_finding[0].severity == Severity.INFO


def test_launchd_persistence_audit_apple_no_info():
    """Test that Apple items don't get flagged."""
    mod = _get_module()

    plist_data = {
        "com.apple.someservice": {
            "Label": "com.apple.someservice",
            "Program": "/System/Library/CoreServices/app",
            "KeepAlive": "1",
            "RunAtLoad": "1",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.apple.someservice.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.apple.someservice.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    # Apple items should not be flagged
    assert not result.has_issues


def test_launchd_persistence_audit_program_arguments():
    """Test extraction of Program from ProgramArguments when Program is missing."""
    mod = _get_module()

    plist_data = {
        "com.example.app": {
            "Label": "com.example.app",
            "ProgramArguments": (
                "(\n"
                "    /Applications/App.app/Contents/MacOS/app,\n"
                "    -arg1,\n"
                "    -arg2\n"
                ")"
            ),
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.example.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.example.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    assert result.has_issues
    assert any(f.data.get("check") == "non_apple_info" for f in result.findings)


def test_launchd_persistence_audit_scan_multiple_dirs():
    """Test scanning of all three directories."""
    mod = _get_module()

    # Test data for each directory
    plist_data = {
        "com.user.app": {
            "Label": "com.user.app",
            "Program": "/Applications/App.app/Contents/MacOS/app",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        },
        "com.system.app": {
            "Label": "com.system.app",
            "Program": "/System/Library/CoreServices/app",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        },
    }

    fake_run = _make_fake_defaults_run(plist_data)

    # Create mock plists for each directory
    user_plist = MagicMock()
    user_plist.name = "com.user.app.plist"
    user_plist.__str__ = MagicMock(
        return_value="/Users/test/Library/LaunchAgents/com.user.app.plist"
    )

    system_plist = MagicMock()
    system_plist.name = "com.system.app.plist"
    system_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.system.app.plist")

    call_count = [0]
    def glob_side_effect(pattern):
        # Return different plists based on call order
        call_count[0] += 1
        if call_count[0] == 1:  # First call (user LaunchAgents)
            return [user_plist]
        elif call_count[0] == 2:  # Second call (system LaunchAgents)
            return [system_plist]
        else:  # Third call (LaunchDaemons)
            return []

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", side_effect=glob_side_effect):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    # Should find user agents
    assert any(f.data.get("label") == "com.user.app" for f in result.findings)


def test_launchd_persistence_audit_fix_known_malware():
    """Test fix action for known malware."""
    mod = _get_module()

    plist_data = {
        "com.pcv.malware": {
            "Label": "com.pcv.malware",
            "Program": "/tmp/malware",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.pcv.malware.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.pcv.malware.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("Remove known malware" in a.title for a in fix.actions)
    # Actions should succeed (informational)
    assert all(a.success for a in fix.actions)


def test_launchd_persistence_audit_fix_suspicious_path():
    """Test fix action for suspicious path."""
    mod = _get_module()

    plist_data = {
        "com.example.app": {
            "Label": "com.example.app",
            "Program": "/tmp/badapp",
            "KeepAlive": "0",
            "RunAtLoad": "0",
        }
    }

    fake_run = _make_fake_defaults_run(plist_data)

    mock_plist = MagicMock()
    mock_plist.name = "com.example.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.example.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    assert len(fix.actions) > 0
    assert any("Remove suspicious" in a.title for a in fix.actions)


def test_launchd_persistence_audit_multiple_findings():
    """Test when multiple issues are detected."""
    mod = _get_module()

    plist_data = {
        "com.vsearch.helper": {
            "Label": "com.vsearch.helper",
            "Program": "/tmp/vsearch",
            "KeepAlive": "1",
            "RunAtLoad": "1",
        },
        "com.thirdparty.app": {
            "Label": "com.thirdparty.app",
            "Program": "/Applications/App.app/Contents/MacOS/app",
            "KeepAlive": "1",
            "RunAtLoad": "1",
        },
    }

    fake_run = _make_fake_defaults_run(plist_data)

    malware_plist = MagicMock()
    malware_plist.name = "com.vsearch.helper.plist"
    malware_plist.__str__ = MagicMock(
        return_value="/Library/LaunchAgents/com.vsearch.helper.plist"
    )

    app_plist = MagicMock()
    app_plist.name = "com.thirdparty.app.plist"
    app_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.thirdparty.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[malware_plist, app_plist]):
            with patch("subprocess.run", side_effect=fake_run):
                result = mod.check(_make_profile())

    # Should detect known malware (and stop checking that item)
    assert any(f.data.get("check") == "known_malware" for f in result.findings)
    # Should detect non-Apple persistence pattern
    assert any(f.data.get("check") == "keepalive_runatload" for f in result.findings)


def test_launchd_persistence_audit_handles_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    mock_plist = MagicMock()
    mock_plist.name = "com.example.app.plist"
    mock_plist.__str__ = MagicMock(return_value="/Library/LaunchAgents/com.example.app.plist")

    with patch.object(Path, "exists", return_value=True):
        with patch.object(Path, "glob", return_value=[mock_plist]):
            with patch("subprocess.run", side_effect=error_run):
                result = mod.check(_make_profile())

    # Should complete without crashing
    assert isinstance(result.findings, list)
    # No items should be extracted due to error
    assert not result.has_issues
