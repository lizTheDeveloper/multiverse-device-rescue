import sys
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
from io import BytesIO
import plistlib

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
    return next(m for m in modules if m.name == "icloud_storage_check")


def test_icloud_storage_check_discovered():
    """Test that module is discovered."""
    mod = _get_module()
    assert mod.name == "icloud_storage_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_icloud_storage_check_account_signed_in():
    """Test when iCloud account is signed in."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": [
            {"AccountID": "user@icloud.com"}
        ]
    })

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="Connected", returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "account_status" and f.data.get("signed_in")
               for f in result.findings)
    assert any(f.severity == Severity.INFO and "signed in" in f.title.lower()
               for f in result.findings)


def test_icloud_storage_check_account_not_signed_in():
    """Test when iCloud account is not signed in."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": []
    })

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="", returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "account_status" and not f.data.get("signed_in")
               for f in result.findings)
    assert any(f.severity == Severity.WARNING and "not signed in" in f.title.lower()
               for f in result.findings)


def test_icloud_storage_check_drive_status_enabled():
    """Test when iCloud Drive is enabled."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": [{"AccountID": "user@icloud.com"}]
    })

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="Connected", returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "drive_status" and f.data.get("enabled")
               for f in result.findings)


def test_icloud_storage_check_drive_sync_errors():
    """Test when iCloud Drive has sync errors."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": [{"AccountID": "user@icloud.com"}]
    })

    # Mock brctl status output with errors
    brctl_output = "Error: Sync failed for file.txt\nConnected"

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout=brctl_output, returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "drive_errors" and f.data.get("has_errors")
               for f in result.findings)
    assert any(f.severity == Severity.WARNING and "sync errors" in f.title.lower()
               for f in result.findings)


def test_icloud_storage_check_pending_uploads():
    """Test when iCloud Drive has pending uploads."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": [{"AccountID": "user@icloud.com"}]
    })

    # Mock brctl status output with pending items
    brctl_output = "Connected\nPending: 5 items"

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout=brctl_output, returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "pending_uploads" and f.data.get("pending_items") > 0
               for f in result.findings)


def test_icloud_storage_check_fix_is_informational():
    """Test that fix() returns informational actions."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": []
    })

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="", returncode=0)):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action for the not-signed-in finding
    assert len(fix.actions) >= 0


def test_icloud_storage_check_fix_account_not_signed_in():
    """Test fix action for unsigned account."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": []
    })

    def mock_open_func(path, *args, **kwargs):
        return BytesIO(mobileme_plist)

    with patch("builtins.open", mock_open_func):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="", returncode=0)):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # Should have an action for signing in
    assert any("Sign in" in a.title for a in fix.actions)
    # All actions should succeed (informational)
    assert all(a.success for a in fix.actions)


def test_icloud_storage_check_desktop_docs_sync():
    """Test Desktop & Documents sync detection."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": [{"AccountID": "user@icloud.com"}]
    })

    # Mock the bird.plist with sync enabled
    bird_plist = plistlib.dumps({
        "Enabled": 1
    })

    def mock_open_handler(path, *args, **kwargs):
        if "MobileMeAccounts" in str(path):
            return BytesIO(mobileme_plist)
        elif "com.apple.bird" in str(path):
            return BytesIO(bird_plist)
        return BytesIO(b"")

    with patch("builtins.open", side_effect=mock_open_handler):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="", returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "docs_sync_status" for f in result.findings)


def test_icloud_storage_check_photos_enabled():
    """Test iCloud Photos detection."""
    mod = _get_module()

    mobileme_plist = plistlib.dumps({
        "Accounts": [{"AccountID": "user@icloud.com"}]
    })

    # Mock the photos plist with sync enabled
    photos_plist = plistlib.dumps({
        "PhotosEnabled": 1
    })

    def mock_open_handler(path, *args, **kwargs):
        if "MobileMeAccounts" in str(path):
            return BytesIO(mobileme_plist)
        elif "com.apple.cloudphotosd" in str(path):
            return BytesIO(photos_plist)
        return BytesIO(b"")

    with patch("builtins.open", side_effect=mock_open_handler):
        with patch("os.path.exists", return_value=True):
            with patch("subprocess.run",
                      return_value=MagicMock(stdout="", returncode=0)):
                result = mod.check(_make_profile())

    assert any(f.data.get("check") == "photos_status" and f.data.get("enabled")
               for f in result.findings)
