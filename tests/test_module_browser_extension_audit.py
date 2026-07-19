import json
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
    return next(m for m in modules if m.name == "browser_extension_audit")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def test_module_discovered():
    """Test that the module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "browser_extension_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_no_extensions():
    """Test case: no browser extensions installed."""
    mod = _get_module()

    # Mock all path operations to return empty
    def mock_exists(self):
        return False

    def mock_iterdir(self):
        return []

    with patch.object(Path, "exists", mock_exists):
        with patch.object(Path, "iterdir", mock_iterdir):
            with patch("subprocess.run", return_value=_make_subprocess_result()):
                result = mod.check(_make_profile())

    assert not result.has_issues


def test_malicious_extension_list():
    """Test case: malicious extension list includes known malware."""
    mod = _get_module()
    assert "superfish" in mod.MALICIOUS_EXTENSIONS
    assert "babylon" in mod.MALICIOUS_EXTENSIONS
    assert "conduit" in mod.MALICIOUS_EXTENSIONS


def test_adware_extension_list():
    """Test case: adware extension list includes known PUP."""
    mod = _get_module()
    adware = mod.ADWARE_EXTENSIONS
    assert "hola" in adware or "hola vpn" in adware
    assert "wot" in adware or "web of trust" in adware
    assert "ask" in str(adware).lower() or any("ask" in ext.lower() for ext in adware)


def test_dangerous_permissions_defined():
    """Test case: dangerous permissions list is properly defined."""
    mod = _get_module()
    dangerous = mod.DANGEROUS_PERMISSIONS
    assert "all_urls" in dangerous
    assert "webRequest" in dangerous or "webRequestBlocking" in dangerous
    assert "cookies" in dangerous
    assert "tabs" in dangerous


def test_check_returns_check_result():
    """Test that check() returns a CheckResult object."""
    mod = _get_module()

    def mock_exists(self):
        return False

    def mock_iterdir(self):
        return []

    with patch.object(Path, "exists", mock_exists):
        with patch.object(Path, "iterdir", mock_iterdir):
            with patch("subprocess.run", return_value=_make_subprocess_result()):
                result = mod.check(_make_profile())

    from rescue.models import CheckResult
    assert isinstance(result, CheckResult)
    assert result.module_name == mod.name


def test_fix_returns_fix_result():
    """Test that fix() returns a FixResult."""
    mod = _get_module()
    from rescue.models import CheckResult, FixResult

    check_result = CheckResult(module_name=mod.name, findings=[])
    fix_result = mod.fix(check_result, Mode.MANUAL)

    assert isinstance(fix_result, FixResult)
    assert fix_result.module_name == mod.name


def test_chrome_extensions_scan_method():
    """Test that _scan_chrome_extensions handles missing directory gracefully."""
    mod = _get_module()

    def mock_exists(self):
        return False

    with patch.object(Path, "exists", mock_exists):
        result = mod._scan_chrome_extensions()

    assert isinstance(result, dict)
    assert len(result) == 0


def test_firefox_extensions_scan_method():
    """Test that _scan_firefox_extensions handles missing directory gracefully."""
    mod = _get_module()

    def mock_exists(self):
        return False

    with patch.object(Path, "exists", mock_exists):
        result = mod._scan_firefox_extensions()

    assert isinstance(result, dict)
    assert len(result) == 0


def test_safari_extensions_scan_method():
    """Test that _scan_safari_extensions handles pluginkit errors gracefully."""
    mod = _get_module()

    # pluginkit returns error
    def mock_subprocess_run(cmd, **kwargs):
        return _make_subprocess_result(returncode=1)

    with patch("subprocess.run", side_effect=mock_subprocess_run):
        result = mod._scan_safari_extensions()

    assert isinstance(result, dict)
    assert len(result) == 0


def test_format_extensions_list():
    """Test that _format_extensions_list formats extensions correctly."""
    mod = _get_module()

    extension_info = {
        "Chrome: Extension 1": {"browser": "Chrome", "permissions": ["tabs", "scripting"]},
        "Firefox: Extension 2": {"browser": "Firefox", "permissions": []},
    }

    formatted = mod._format_extensions_list(extension_info)

    assert "Extension 1" in formatted
    assert "Extension 2" in formatted
    assert "tabs" in formatted


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.browser_extension_audit.") for c in declared)
