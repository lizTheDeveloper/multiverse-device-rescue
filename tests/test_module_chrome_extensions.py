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
    return next(m for m in modules if m.name == "chrome_extensions")


def _create_extension(tmp_path, ext_id, name, permissions=None):
    """Helper to create a fake Chrome extension with manifest.json"""
    if permissions is None:
        permissions = []

    extensions_dir = (
        tmp_path
        / "Library"
        / "Application Support"
        / "Google"
        / "Chrome"
        / "Default"
        / "Extensions"
    )
    extensions_dir.mkdir(parents=True, exist_ok=True)

    ext_dir = extensions_dir / ext_id
    version_dir = ext_dir / "1.0"
    version_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "name": name,
        "version": "1.0",
        "permissions": permissions,
    }

    manifest_path = version_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    return manifest_path


def test_chrome_extensions_discovered():
    mod = _get_module()
    assert mod.name == "chrome_extensions"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_chrome_extensions_no_extensions(tmp_path):
    """Test case: no Chrome extensions installed"""
    mod = _get_module()

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # No extensions means no findings
    assert not result.has_issues


def test_chrome_extensions_single_safe(tmp_path):
    """Test case: single extension with safe permissions"""
    mod = _get_module()

    _create_extension(
        tmp_path,
        "extension1",
        "Safe Extension",
        permissions=["storage", "identity"],
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have one finding: info about installed extensions
    assert result.has_issues
    assert any(f.data.get("check") == "installed_extensions" for f in result.findings)
    assert not any(
        f.data.get("check") == "broad_permissions" for f in result.findings
    )


def test_chrome_extensions_broad_permissions(tmp_path):
    """Test case: extension with broad permissions"""
    mod = _get_module()

    _create_extension(
        tmp_path,
        "extension1",
        "Tracking Extension",
        permissions=["all_urls", "tabs"],
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should flag warning for broad permissions
    assert result.has_issues
    assert any(f.data.get("check") == "broad_permissions" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_chrome_extensions_many_extensions(tmp_path):
    """Test case: >10 extensions installed"""
    mod = _get_module()

    # Create 12 extensions
    for i in range(12):
        _create_extension(
            tmp_path,
            f"extension{i}",
            f"Extension {i}",
            permissions=["storage"],
        )

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should flag warning for too many extensions
    assert result.has_issues
    assert any(f.data.get("check") == "extension_bloat" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_chrome_extensions_mixed(tmp_path):
    """Test case: mix of safe and dangerous extensions"""
    mod = _get_module()

    # Create safe extension
    _create_extension(tmp_path, "safe1", "Safe Ext", permissions=["storage"])

    # Create dangerous extension with broad permissions
    _create_extension(
        tmp_path,
        "danger1",
        "Dangerous Ext",
        permissions=["all_urls", "webRequest"],
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should have warning for broad permissions
    assert result.has_issues
    assert any(f.data.get("check") == "broad_permissions" for f in result.findings)
    assert any(f.data.get("check") == "installed_extensions" for f in result.findings)


def test_chrome_extensions_no_permissions_field(tmp_path):
    """Test case: extension manifest without permissions field"""
    mod = _get_module()

    extensions_dir = (
        tmp_path
        / "Library"
        / "Application Support"
        / "Google"
        / "Chrome"
        / "Default"
        / "Extensions"
    )
    extensions_dir.mkdir(parents=True, exist_ok=True)

    ext_dir = extensions_dir / "extension1"
    version_dir = ext_dir / "1.0"
    version_dir.mkdir(parents=True, exist_ok=True)

    manifest = {
        "name": "No Perms Extension",
        "version": "1.0",
        # No permissions field
    }

    manifest_path = version_dir / "manifest.json"
    with open(manifest_path, "w") as f:
        json.dump(manifest, f)

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should still work and list the extension
    assert result.has_issues
    assert any(f.data.get("check") == "installed_extensions" for f in result.findings)


def test_chrome_extensions_fix_is_informational(tmp_path):
    """Test that fix() is informational and always succeeds"""
    mod = _get_module()

    _create_extension(
        tmp_path,
        "extension1",
        "Extension with Perms",
        permissions=["all_urls"],
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
    # All actions should succeed
    assert all(a.success for a in fix.actions)


def test_chrome_extensions_multiple_broad_perms(tmp_path):
    """Test extension with multiple broad permissions"""
    mod = _get_module()

    _create_extension(
        tmp_path,
        "extension1",
        "Super Invasive Ext",
        permissions=["all_urls", "<all_urls>", "tabs", "webRequest", "activeTab"],
    )

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Should flag warning
    assert result.has_issues
    broad_perm_findings = [
        f for f in result.findings if f.data.get("check") == "broad_permissions"
    ]
    assert len(broad_perm_findings) > 0
    # Verify the broad permissions are listed
    found_perms = broad_perm_findings[0].data.get("permissions", [])
    assert "all_urls" in found_perms
    assert "tabs" in found_perms


def test_chrome_extensions_info_severity_for_count(tmp_path):
    """Test that individual extensions listing is INFO severity"""
    mod = _get_module()

    _create_extension(tmp_path, "ext1", "Extension 1", permissions=["storage"])

    with patch("pathlib.Path.home", return_value=tmp_path):
        result = mod.check(_make_profile())

    # Find the installed_extensions finding
    installed_findings = [
        f for f in result.findings if f.data.get("check") == "installed_extensions"
    ]
    assert len(installed_findings) > 0
    # Should be INFO severity for the listing
    assert installed_findings[0].severity == Severity.INFO


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.chrome_extensions.") for c in declared)
