import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


# Sample reg query outputs
REG_QUERY_HKLM_RUN_CLEAN = """
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    Windows Defender    REG_SZ    C:\\Program Files\\Windows Defender\\MSASCuiL.exe
    SecurityHealth    REG_SZ    C:\\Windows\\system32\\SecurityHealthSystray.exe
"""

REG_QUERY_HKLM_RUN_MALWARE = """
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    Windows Defender    REG_SZ    C:\\Program Files\\Windows Defender\\MSASCuiL.exe
    MalwarePath    REG_SZ    C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe
"""

REG_QUERY_HKCU_RUN_OBFUSCATED = """
HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

HKEY_CURRENT_USER\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run
    OneDrive    REG_SZ    C:\\Users\\User\\AppData\\Local\\Microsoft\\OneDrive\\OneDrive.exe
    ObfuscatedEntry    REG_SZ    powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcATQBhAGwAdwBhAHIAZQAnAA==
"""

REG_QUERY_EMPTY = """
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run

ERROR: The system was unable to find the specified registry key or value.
"""

STARTUP_FOLDER_CLEAN = """
Chrome Shortcut.lnk
Firefox Shortcut.lnk
"""

STARTUP_FOLDER_WITH_SUSPICIOUS = """
Chrome Shortcut.lnk
Firefox Shortcut.lnk
MaliciousStartup.exe
SuspiciousApp.bat
"""

STARTUP_FOLDER_EMPTY = ""


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
    return next(m for m in modules if m.name == "win_autoruns_audit")


def _fake_subprocess_run_clean(cmd, **kwargs):
    """Mocks subprocess.run to return clean registry/startup entries."""
    result = MagicMock()
    result.returncode = 0
    result.stderr = ""

    if isinstance(cmd, list) and cmd[0] == "reg":
        result.stdout = REG_QUERY_HKLM_RUN_CLEAN
    elif isinstance(cmd, list) and cmd[0] == "powershell":
        result.stdout = STARTUP_FOLDER_CLEAN
    else:
        result.stdout = ""
    return result


def _fake_subprocess_run_malware(cmd, **kwargs):
    """Mocks subprocess.run to return malware entries."""
    result = MagicMock()
    result.returncode = 0
    result.stderr = ""

    if isinstance(cmd, list) and cmd[0] == "reg":
        if "Run" in str(cmd):
            result.stdout = REG_QUERY_HKLM_RUN_MALWARE
        else:
            result.stdout = REG_QUERY_EMPTY
    elif isinstance(cmd, list) and cmd[0] == "powershell":
        result.stdout = STARTUP_FOLDER_EMPTY
    else:
        result.stdout = ""
    return result


def _fake_subprocess_run_obfuscated(cmd, **kwargs):
    """Mocks subprocess.run to return obfuscated entries."""
    result = MagicMock()
    result.returncode = 0
    result.stderr = ""

    if isinstance(cmd, list) and cmd[0] == "reg":
        result.stdout = REG_QUERY_HKCU_RUN_OBFUSCATED
    elif isinstance(cmd, list) and cmd[0] == "powershell":
        result.stdout = STARTUP_FOLDER_EMPTY
    else:
        result.stdout = ""
    return result


def _fake_subprocess_run_excessive(cmd, **kwargs):
    """Mocks subprocess.run to return many autorun entries."""
    result = MagicMock()
    result.returncode = 0
    result.stderr = ""

    if isinstance(cmd, list) and cmd[0] == "reg":
        # Check if this is HKLM\...\Run query
        cmd_str = " ".join(cmd)
        if "HKLM" in cmd_str and "Run" in cmd_str and "RunOnce" not in cmd_str:
            # Create 21 entries to trigger the excessive warning (>20)
            entries = ""
            for i in range(21):
                entries += f"    Entry{i}    REG_SZ    C:\\Program Files\\App{i}\\app{i}.exe\n"
            result.stdout = (
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n\n"
                "HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                + entries
            )
        else:
            result.stdout = REG_QUERY_EMPTY
    elif isinstance(cmd, list) and cmd[0] == "powershell":
        result.stdout = STARTUP_FOLDER_EMPTY
    else:
        result.stdout = ""
    return result


def test_win_autoruns_audit_discovered():
    """Test that module is discovered with correct metadata."""
    mod = _get_module()
    assert mod.name == "win_autoruns_audit"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_win_autoruns_audit_healthy():
    """Test module with clean autorun entries."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run_clean):
        result = mod.check(_make_profile())
    # Should have at least the INFO inventory finding
    assert result.has_issues
    # Check that no CRITICAL or WARNING findings for suspicious entries
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical_findings) == 0
    assert len(warning_findings) == 0


def test_win_autoruns_audit_detects_temp_directory():
    """Test detection of autorun entries from temp directory."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run_malware):
        result = mod.check(_make_profile())
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) > 0
    assert any("temp" in f.title.lower() for f in critical_findings)


def test_win_autoruns_audit_detects_obfuscated_commands():
    """Test detection of obfuscated autorun commands."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run_obfuscated):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("obfuscated" in f.title.lower() for f in warning_findings)


def test_win_autoruns_audit_detects_excessive_entries():
    """Test detection of excessive autorun entries."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run_excessive):
        result = mod.check(_make_profile())
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("excessive" in f.title.lower() for f in warning_findings)
    # Verify the count is correct (21 entries)
    excessive = next(f for f in warning_findings if "excessive" in f.title.lower())
    assert "21" in excessive.title


def test_win_autoruns_audit_lists_all_entries():
    """Test that all entries are listed in INFO finding."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run_clean):
        result = mod.check(_make_profile())
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0
    # Should have an inventory listing
    inventory = next((f for f in info_findings if "inventory" in f.title.lower()), None)
    assert inventory is not None


def test_win_autoruns_audit_fix_provides_removal_guidance():
    """Test that fix provides informational guidance for removal."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_subprocess_run_malware):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # Should have actions for critical findings
    assert len(fix.actions) > 0
    # Fixes should be informational (not successful because manual)
    for action in fix.actions:
        assert not action.success
        assert "Manual" in action.error or "informational" in action.description.lower()


def test_win_autoruns_audit_parse_reg_query():
    """Test parsing of reg query output."""
    mod = _get_module()
    parsed = mod._parse_reg_query_output(REG_QUERY_HKLM_RUN_CLEAN)
    assert "Windows Defender" in parsed
    assert parsed["Windows Defender"] == "C:\\Program Files\\Windows Defender\\MSASCuiL.exe"
    assert "SecurityHealth" in parsed


def test_win_autoruns_audit_temp_path_detection():
    """Test detection of temp paths."""
    mod = _get_module()
    assert mod._is_temp_path("C:\\Users\\Admin\\AppData\\Local\\Temp\\malware.exe")
    assert mod._is_temp_path("C:\\Windows\\Temp\\suspicious.exe")
    assert mod._is_temp_path("C:\\Users\\User\\Downloads\\app.exe")
    assert not mod._is_temp_path("C:\\Program Files\\Legitimate\\app.exe")


def test_win_autoruns_audit_obfuscation_detection():
    """Test detection of obfuscated commands."""
    mod = _get_module()
    assert mod._is_obfuscated_command("powershell.exe -enc VwByAGkAdABlAC0ASABvAHMAdAAgACcATQBhAGwAdwBhAHIAZQAnAA==")
    assert mod._is_obfuscated_command("powershell.exe -e VwByAGkAdABlAC0ASABvAHMAd")
    assert mod._is_obfuscated_command("cmd /c echo malware | powershell")
    assert mod._is_obfuscated_command("IEX(New-Object Net.WebClient)")
    assert not mod._is_obfuscated_command("C:\\Program Files\\Firefox\\firefox.exe")
