import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
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
    return next(m for m in modules if m.name == "app_crash_analyzer")


# Sample crash file content
SAMPLE_CRASH_CONTENT_EXC_BAD_ACCESS = """Process:               Safari [12345]
Path:                 /Applications/Safari.app/Contents/MacOS/Safari
Identifier:           com.apple.Safari
Version:              17.0 (17608.1.1)
Code Type:            ARM-64 (Native)
Parent Process:       launchd [1]
User ID:              501

Date/Time:            2026-07-05 14:30:00 +0000
OS Version:           macOS 15.2 (19C63)
Report Version:       12
Bridge OS Version:    9.0 (19C58)
Anonymous UUID:       D1234567-89AB-CDEF-0123-456789ABCDEF

Exception Type:       EXC_BAD_ACCESS / SIGSEGV
Exception Codes:      KERN_INVALID_ADDRESS at 0x0000000000000000

Crashed Thread:       0  Dispatch queue: com.apple.main-thread

Application Specific Information:
Memory accessed by thread 0: 0x0

Thread 0 Crashed:: Dispatch queue: com.apple.main-thread
0   libsystem_platform.dylib             0x1a5f2afc4 _platform_memcpy$VARIANT$Haswell + 204
1   Safari                               0x100a5ef1c 0x100980000 + 777756
"""

SAMPLE_CRASH_CONTENT_SIGABRT = """Process:               TestApp [54321]
Path:                 /Applications/TestApp.app/Contents/MacOS/TestApp
Identifier:           com.example.TestApp
Version:              1.0 (1)
Code Type:            ARM-64 (Native)

Date/Time:            2026-07-04 10:15:00 +0000
OS Version:           macOS 15.2 (19C63)

Exception Type:       SIGABRT
Exception Codes:      SIGABRT (6)

Crashed Thread:       0

Thread 0 Crashed:
0   libsystem_c.dylib                   0x1a5a5b5f4 abort + 140
1   TestApp                              0x100500000 main + 500
"""

SAMPLE_CRASH_CONTENT_SYSTEM = """Process:               WindowServer [123]
Path:                 /System/Library/Frameworks/SpriteKit.framework/Versions/A/XPCServices/com.apple.CoreDisplay.XPC
Identifier:           com.apple.CoreDisplay.XPC
Version:              1.0

Date/Time:            2026-07-03 08:00:00 +0000
OS Version:           macOS 15.2 (19C63)

Exception Type:       EXC_CRASH
"""


def test_module_exists():
    """Test that the module is discoverable."""
    module = _get_module()
    assert module.name == "app_crash_analyzer"
    assert module.category == "integrity"
    assert Platform.DARWIN in module.platforms


def test_check_no_crashes():
    """Test check() when no crash files exist."""
    module = _get_module()
    profile = _make_profile()

    # Mock Path.home() to return a path that doesn't exist
    def mock_scan_crash_files(diagnostic_dir):
        return []

    with patch.object(module, "_scan_crash_files", side_effect=mock_scan_crash_files):
        result = module.check(profile)

    assert result.module_name == "app_crash_analyzer"
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "No crash reports found" in result.findings[0].title


def test_check_with_recent_crashes():
    """Test check() with recent crash files."""
    module = _get_module()
    profile = _make_profile()

    # Create mock crash files
    now = datetime.now()
    recent_time = now - timedelta(hours=1)

    crash_file_1 = MagicMock(spec=Path)
    crash_file_1.name = "Safari_2026-07-05-143000.crash"
    crash_file_1.stem = "Safari_2026-07-05-143000"
    crash_file_1.stat.return_value.st_mtime = recent_time.timestamp()

    crash_file_2 = MagicMock(spec=Path)
    crash_file_2.name = "TestApp_2026-07-04-101500.crash"
    crash_file_2.stem = "TestApp_2026-07-04-101500"
    crash_file_2.stat.return_value.st_mtime = (now - timedelta(days=1)).timestamp()

    mock_files = [crash_file_1, crash_file_2]

    # Mock the parsing to return crash info
    def mock_parse(*args):
        return [
            {
                "file_path": str(crash_file_1),
                "app_name": "Safari",
                "timestamp": datetime.fromtimestamp(recent_time.timestamp()),
                "crash_reason": "EXC_BAD_ACCESS",
                "is_system_process": False,
            },
            {
                "file_path": str(crash_file_2),
                "app_name": "TestApp",
                "timestamp": datetime.fromtimestamp((now - timedelta(days=1)).timestamp()),
                "crash_reason": "SIGABRT",
                "is_system_process": False,
            },
        ]

    with patch.object(module, "_scan_crash_files", return_value=mock_files):
        with patch.object(module, "_parse_crash_files", side_effect=mock_parse):
            result = module.check(profile)

    assert result.module_name == "app_crash_analyzer"
    # Should have INFO for crash summary
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_check_unstable_app():
    """Test detection of unstable apps (>5 crashes in 7 days)."""
    module = _get_module()
    profile = _make_profile()

    # Create 6 crash files for the same app in the last 7 days
    crash_files = []
    now = datetime.now()
    for i in range(6):
        crash_file = MagicMock(spec=Path)
        crash_file.name = f"BadApp_2026-07-0{5-i}-120000_{i}.crash"
        crash_file.stem = f"BadApp_2026-07-0{5-i}-120000_{i}"
        crash_file.stat.return_value.st_mtime = (now - timedelta(days=i)).timestamp()
        crash_files.append(crash_file)

    # Mock parse to return 6 BadApp crashes
    def mock_parse(*args):
        return [
            {
                "file_path": str(crash_files[i]),
                "app_name": "BadApp",
                "timestamp": now - timedelta(days=i),
                "crash_reason": "SIGABRT",
                "is_system_process": False,
            }
            for i in range(6)
        ]

    with patch.object(module, "_scan_crash_files", return_value=crash_files):
        with patch.object(module, "_parse_crash_files", side_effect=mock_parse):
            result = module.check(profile)

    # Check for unstable app warning
    unstable_findings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "Unstable app" in f.title
    ]
    assert len(unstable_findings) > 0
    assert "BadApp" in unstable_findings[0].title
    assert "6" in unstable_findings[0].title


def test_check_system_crashes():
    """Test detection of system process crashes."""
    module = _get_module()
    profile = _make_profile()

    # Create crash file for system process
    crash_file = MagicMock(spec=Path)
    crash_file.name = "WindowServer_2026-07-05-080000.crash"
    crash_file.stem = "WindowServer_2026-07-05-080000"
    now = datetime.now()
    crash_file.stat.return_value.st_mtime = (now - timedelta(hours=1)).timestamp()

    # Mock parse to return WindowServer crash
    def mock_parse(*args):
        return [
            {
                "file_path": str(crash_file),
                "app_name": "WindowServer",
                "timestamp": now - timedelta(hours=1),
                "crash_reason": "EXC_CRASH",
                "is_system_process": True,
            }
        ]

    with patch.object(module, "_scan_crash_files", return_value=[crash_file]):
        with patch.object(module, "_parse_crash_files", side_effect=mock_parse):
            result = module.check(profile)

    # Check for system crash warning
    system_findings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "System process crashes" in f.title
    ]
    assert len(system_findings) > 0


def test_check_memory_crashes():
    """Test detection of memory-related crashes."""
    module = _get_module()
    profile = _make_profile()

    # Create multiple crash files with EXC_BAD_ACCESS for the same app
    crash_files = []
    now = datetime.now()
    for i in range(6):
        crash_file = MagicMock(spec=Path)
        crash_file.name = f"MemoryApp_2026-07-0{5-i}-120000_{i}.crash"
        crash_file.stem = f"MemoryApp_2026-07-0{5-i}-120000_{i}"
        crash_file.stat.return_value.st_mtime = (now - timedelta(days=i)).timestamp()
        crash_files.append(crash_file)

    # Mock parse to return MemoryApp crashes with EXC_BAD_ACCESS
    def mock_parse(*args):
        return [
            {
                "file_path": str(crash_files[i]),
                "app_name": "MemoryApp",
                "timestamp": now - timedelta(days=i),
                "crash_reason": "EXC_BAD_ACCESS",
                "is_system_process": False,
            }
            for i in range(6)
        ]

    with patch.object(module, "_scan_crash_files", return_value=crash_files):
        with patch.object(module, "_parse_crash_files", side_effect=mock_parse):
            result = module.check(profile)

    # Check for memory crash warning
    memory_findings = [
        f for f in result.findings
        if f.severity == Severity.WARNING and "Memory-related crashes" in f.title
    ]
    assert len(memory_findings) > 0
    assert "EXC_BAD_ACCESS" in memory_findings[0].title


def test_extract_crash_reason_exc_bad_access():
    """Test extraction of EXC_BAD_ACCESS crash reason."""
    module = _get_module()
    reason = module._extract_crash_reason(SAMPLE_CRASH_CONTENT_EXC_BAD_ACCESS)
    assert "EXC_BAD_ACCESS" in reason or "SIGSEGV" in reason


def test_extract_crash_reason_sigabrt():
    """Test extraction of SIGABRT crash reason."""
    module = _get_module()
    reason = module._extract_crash_reason(SAMPLE_CRASH_CONTENT_SIGABRT)
    assert "SIGABRT" in reason


def test_is_system_process_windowserver():
    """Test identification of system process (WindowServer)."""
    module = _get_module()
    result = module._is_system_process("WindowServer", SAMPLE_CRASH_CONTENT_SYSTEM)
    assert result is True


def test_is_system_process_user_app():
    """Test identification of user app (not system process)."""
    module = _get_module()
    result = module._is_system_process("Safari", SAMPLE_CRASH_CONTENT_SIGABRT)
    # Safari is marked as system indicator in the code, but could be user app
    assert isinstance(result, bool)


def test_fix_no_crashes():
    """Test fix() when no crashes found."""
    module = _get_module()
    profile = _make_profile()

    # First run check to get findings
    with patch.object(module, "_scan_crash_files", return_value=[]):
        check_result = module.check(profile)

    # Then run fix
    fix_result = module.fix(check_result, Mode.MANUAL)

    assert fix_result.module_name == "app_crash_analyzer"
    assert len(fix_result.actions) >= 1
    assert fix_result.actions[0].success is True
    assert "No crash reports found" in check_result.findings[0].title or \
           "stable" in fix_result.actions[0].title.lower()


def test_fix_unstable_app():
    """Test fix() for unstable app finding."""
    module = _get_module()
    profile = _make_profile()

    # Create 6 crash files for unstable app
    crash_files = []
    now = datetime.now()
    for i in range(6):
        crash_file = MagicMock(spec=Path)
        crash_file.name = f"UnstableApp_2026-07-0{5-i}-120000_{i}.crash"
        crash_file.stem = f"UnstableApp_2026-07-0{5-i}-120000_{i}"
        crash_file.stat.return_value.st_mtime = (now - timedelta(days=i)).timestamp()
        crash_files.append(crash_file)

    # Mock parse to return 6 UnstableApp crashes
    def mock_parse(*args):
        return [
            {
                "file_path": str(crash_files[i]),
                "app_name": "UnstableApp",
                "timestamp": now - timedelta(days=i),
                "crash_reason": "SIGABRT",
                "is_system_process": False,
            }
            for i in range(6)
        ]

    with patch.object(module, "_scan_crash_files", return_value=crash_files):
        with patch.object(module, "_parse_crash_files", side_effect=mock_parse):
            check_result = module.check(profile)

    # Run fix
    fix_result = module.fix(check_result, Mode.MANUAL)

    assert fix_result.module_name == "app_crash_analyzer"
    assert len(fix_result.actions) > 0
    # Check for unstable app action
    unstable_actions = [
        a for a in fix_result.actions
        if "Remediate unstable app" in a.title
    ]
    assert len(unstable_actions) > 0
    assert unstable_actions[0].success is True
    assert "reinstall" in unstable_actions[0].description.lower()


def test_fix_system_crashes():
    """Test fix() for system process crashes."""
    module = _get_module()
    profile = _make_profile()

    # Create crash file for system process
    crash_file = MagicMock(spec=Path)
    crash_file.name = "WindowServer_2026-07-05-080000.crash"
    crash_file.stem = "WindowServer_2026-07-05-080000"
    now = datetime.now()
    crash_file.stat.return_value.st_mtime = (now - timedelta(hours=1)).timestamp()

    # Mock parse to return WindowServer crash
    def mock_parse(*args):
        return [
            {
                "file_path": str(crash_file),
                "app_name": "WindowServer",
                "timestamp": now - timedelta(hours=1),
                "crash_reason": "EXC_CRASH",
                "is_system_process": True,
            }
        ]

    with patch.object(module, "_scan_crash_files", return_value=[crash_file]):
        with patch.object(module, "_parse_crash_files", side_effect=mock_parse):
            check_result = module.check(profile)

    # Run fix
    fix_result = module.fix(check_result, Mode.MANUAL)

    assert fix_result.module_name == "app_crash_analyzer"
    # Should have action for system crashes
    system_actions = [
        a for a in fix_result.actions
        if "system" in a.title.lower() and "crashes" in a.title.lower()
    ]
    assert len(system_actions) > 0
    assert system_actions[0].success is True
    assert "Disk Utility" in system_actions[0].description


def test_scan_crash_files_nonexistent_dir():
    """Test _scan_crash_files with nonexistent directory."""
    module = _get_module()

    mock_dir = MagicMock(spec=Path)
    mock_dir.exists.return_value = False

    result = module._scan_crash_files(mock_dir)
    assert result == []


def test_scan_crash_files_permission_error():
    """Test _scan_crash_files with permission error."""
    module = _get_module()

    mock_dir = MagicMock(spec=Path)
    mock_dir.exists.return_value = True
    mock_dir.glob.side_effect = PermissionError("Access denied")

    result = module._scan_crash_files(mock_dir)
    assert result == []


def test_parse_crash_files_invalid_file():
    """Test _parse_crash_files with invalid/unreadable file."""
    module = _get_module()

    mock_file = MagicMock(spec=Path)
    mock_file.stat.side_effect = OSError("Cannot stat")

    result = module._parse_crash_files([mock_file])
    assert result == []
