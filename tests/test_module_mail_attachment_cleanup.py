import sys
from pathlib import Path
from unittest.mock import patch

# Add project root so modules/ is importable via discover_modules
sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    SystemProfile,
    Platform,
    Severity,
    RiskLevel,
    Mode,
)
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
    return next(m for m in modules if m.name == "mail_attachment_cleanup")


def test_mail_attachment_cleanup_discovered():
    """Module is discoverable by the registry."""
    mod = _get_module()
    assert mod.name == "mail_attachment_cleanup"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE


def test_empty_mail_directories(tmp_path):
    """No issues when Mail directories are empty or nonexistent."""
    mod = _get_module()

    # Mock _get_directory_size to return 0
    with patch.object(mod, "_get_directory_size", return_value=0):
        result = mod.check(_make_profile())

    # Should have one INFO finding about minimal storage
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "minimal" in result.findings[0].title.lower()


def test_small_mail_data_info(tmp_path):
    """Small Mail data generates INFO finding."""
    mod = _get_module()

    # 2 GB Mail data (below 10 GB warning threshold)
    mail_data_size = 2 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return 0
        return mail_data_size

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    mail_findings = [f for f in result.findings if f.data.get("type") == "mail_data"]
    assert len(mail_findings) == 1
    assert mail_findings[0].severity == Severity.INFO
    assert "2.0 GB" in mail_findings[0].title


def test_large_mail_data_warning(tmp_path):
    """Large Mail data (>10GB) generates WARNING."""
    mod = _get_module()

    # 15 GB Mail data (exceeds 10 GB warning threshold)
    mail_data_size = 15 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return 0
        return mail_data_size

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    mail_findings = [f for f in result.findings if f.data.get("type") == "mail_data"]
    assert len(mail_findings) == 1
    assert mail_findings[0].severity == Severity.WARNING
    assert "15.0 GB" in mail_findings[0].title


def test_large_mail_attachments_warning(tmp_path):
    """Large Mail attachment cache (>2GB) generates WARNING."""
    mod = _get_module()

    # 3 GB attachment cache (exceeds 2 GB warning threshold)
    attachments_size = 3 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return attachments_size
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    attach_findings = [f for f in result.findings if f.data.get("type") == "mail_attachments"]
    assert len(attach_findings) == 1
    assert attach_findings[0].severity == Severity.WARNING
    assert "3.0 GB" in attach_findings[0].title


def test_both_directories_with_warnings(tmp_path):
    """Both Mail data and attachments above thresholds generate warnings."""
    mod = _get_module()

    mail_data_size = 15 * 1024 * 1024 * 1024
    attachments_size = 3 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return attachments_size
        return mail_data_size

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 2

    # Verify both warnings are present
    mail_findings = [f for f in result.findings if f.data.get("type") == "mail_data"]
    attach_findings = [f for f in result.findings if f.data.get("type") == "mail_attachments"]

    assert len(mail_findings) == 1
    assert mail_findings[0].severity == Severity.WARNING
    assert len(attach_findings) == 1
    assert attach_findings[0].severity == Severity.WARNING


def test_attachment_cache_small_info(tmp_path):
    """Small attachment cache generates INFO finding."""
    mod = _get_module()

    # 500 MB attachment cache (below 2 GB warning threshold)
    attachments_size = 500 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return attachments_size
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        result = mod.check(_make_profile())

    assert result.has_issues
    attach_findings = [f for f in result.findings if f.data.get("type") == "mail_attachments"]
    assert len(attach_findings) == 1
    assert attach_findings[0].severity == Severity.INFO
    assert "500.0 MB" in attach_findings[0].title


def test_fix_mail_data_warning(tmp_path):
    """fix() provides informational actions for Mail data."""
    mod = _get_module()

    mail_data_size = 15 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return 0
        return mail_data_size

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert "archive" in fix.actions[0].description.lower()
    assert "delete" in fix.actions[0].description.lower()


def test_fix_mail_attachments_warning(tmp_path):
    """fix() provides informational actions for attachment cache."""
    mod = _get_module()

    attachments_size = 3 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return attachments_size
        return 0

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert "rm -rf" in fix.actions[0].description


def test_fix_is_always_successful(tmp_path):
    """All fix actions are marked as successful (informational only)."""
    mod = _get_module()

    mail_data_size = 15 * 1024 * 1024 * 1024
    attachments_size = 3 * 1024 * 1024 * 1024

    def mock_get_dir_size(path):
        if "Mail Downloads" in str(path):
            return attachments_size
        return mail_data_size

    with patch.object(mod, "_get_directory_size", side_effect=mock_get_dir_size):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    assert all(a.success for a in fix.actions)
    assert len(fix.actions) == 2
