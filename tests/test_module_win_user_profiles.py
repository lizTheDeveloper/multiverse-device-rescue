import json
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from rescue.models import Mode, Platform, SystemProfile, Severity
from modules.performance.win_user_profiles import Module


@pytest.fixture
def system_profile():
    """Create a basic SystemProfile for testing."""
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows",
        os_version="11",
        architecture="x86_64",
        cpu_model="Intel Core i7",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


@pytest.fixture
def module():
    """Create a Module instance."""
    return Module()


def test_module_metadata(module):
    """Test module metadata is correctly set."""
    assert module.name == "win_user_profiles"
    assert module.category == "performance"
    assert module.platforms == [Platform.WIN32]
    assert module.risk_level.value == "safe"


def test_check_with_no_profiles(module, system_profile):
    """Test check when no profiles are returned."""
    with patch.object(module, "_get_user_profiles", return_value=[]):
        result = module.check(system_profile)
        assert result.module_name == "win_user_profiles"
        assert len(result.findings) == 0


def test_check_with_normal_profiles(module, system_profile):
    """Test check with normal user profiles."""
    # Use recent dates to avoid triggering unused profile warning
    recent_date1 = datetime.now(timezone.utc) - timedelta(days=30)
    recent_date2 = datetime.now(timezone.utc) - timedelta(days=15)

    profiles = [
        {
            "LocalPath": "C:\\Users\\john",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "LastUseTime": recent_date1.isoformat().replace("+00:00", "Z"),
            "Special": False,
        },
        {
            "LocalPath": "C:\\Users\\jane",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-1002",
            "LastUseTime": recent_date2.isoformat().replace("+00:00", "Z"),
            "Special": False,
        },
    ]
    user_accounts = {
        "S-1-5-21-1234567890-1234567890-1234567890-1001",
        "S-1-5-21-1234567890-1234567890-1234567890-1002",
    }

    with patch.object(module, "_get_user_profiles", return_value=profiles):
        with patch.object(module, "_get_user_accounts", return_value=user_accounts):
            with patch.object(module, "_get_directory_size_powershell", return_value=2 * 1024**3):
                result = module.check(system_profile)
                assert result.module_name == "win_user_profiles"
                # Should have 1 INFO finding (profiles list)
                assert len(result.findings) == 1
                assert result.findings[0].severity == Severity.INFO
                assert "Found 2 user profile(s)" in result.findings[0].title


def test_check_with_orphaned_profiles(module, system_profile):
    """Test check identifies orphaned profiles."""
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)

    profiles = [
        {
            "LocalPath": "C:\\Users\\orphan",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-9999",
            "LastUseTime": recent_date.isoformat().replace("+00:00", "Z"),
            "Special": False,
        },
    ]
    user_accounts = set()  # No user accounts

    with patch.object(module, "_get_user_profiles", return_value=profiles):
        with patch.object(module, "_get_user_accounts", return_value=user_accounts):
            with patch.object(module, "_get_directory_size_powershell", return_value=1 * 1024**3):
                result = module.check(system_profile)
                # Should have 2 findings: profiles list + orphaned profiles warning
                assert len(result.findings) == 2
                warning_finding = [f for f in result.findings if f.severity == Severity.WARNING][0]
                assert "orphaned" in warning_finding.title.lower()
                assert warning_finding.data["type"] == "orphaned_profiles"


def test_check_with_temp_profiles(module, system_profile):
    """Test check identifies temporary profiles."""
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)

    profiles = [
        {
            "LocalPath": "C:\\Users\\TEMP123456",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-5000",
            "LastUseTime": recent_date.isoformat().replace("+00:00", "Z"),
            "Special": False,
        },
    ]
    user_accounts = {"S-1-5-21-1234567890-1234567890-1234567890-5000"}

    with patch.object(module, "_get_user_profiles", return_value=profiles):
        with patch.object(module, "_get_user_accounts", return_value=user_accounts):
            with patch.object(module, "_get_directory_size_powershell", return_value=500 * 1024**2):
                result = module.check(system_profile)
                # Should have 2 findings: profiles list + temp profiles warning
                assert len(result.findings) == 2
                warning_finding = [f for f in result.findings if f.severity == Severity.WARNING][0]
                assert "temporary" in warning_finding.title.lower()
                assert warning_finding.data["type"] == "temp_profiles"


def test_check_with_large_profiles(module, system_profile):
    """Test check identifies large profiles."""
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)

    profiles = [
        {
            "LocalPath": "C:\\Users\\biguser",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-2001",
            "LastUseTime": recent_date.isoformat().replace("+00:00", "Z"),
            "Special": False,
        },
    ]
    user_accounts = {"S-1-5-21-1234567890-1234567890-1234567890-2001"}

    with patch.object(module, "_get_user_profiles", return_value=profiles):
        with patch.object(module, "_get_user_accounts", return_value=user_accounts):
            # Profile is 15 GB (exceeds 10 GB threshold)
            with patch.object(module, "_get_directory_size_powershell", return_value=15 * 1024**3):
                result = module.check(system_profile)
                # Should have 2 findings: profiles list + large profiles warning
                assert len(result.findings) == 2
                warning_finding = [f for f in result.findings if f.severity == Severity.WARNING][0]
                assert "large" in warning_finding.title.lower()
                assert warning_finding.data["type"] == "large_profiles"


def test_check_with_unused_profiles(module, system_profile):
    """Test check identifies unused profiles."""
    # Profile last used 200 days ago (exceeds 180 day threshold)
    old_date = datetime.now(timezone.utc) - timedelta(days=200)
    old_date_str = old_date.isoformat().replace("+00:00", "Z")

    profiles = [
        {
            "LocalPath": "C:\\Users\\olduser",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-3001",
            "LastUseTime": old_date_str,
            "Special": False,
        },
    ]
    user_accounts = {"S-1-5-21-1234567890-1234567890-1234567890-3001"}

    with patch.object(module, "_get_user_profiles", return_value=profiles):
        with patch.object(module, "_get_user_accounts", return_value=user_accounts):
            with patch.object(module, "_get_directory_size_powershell", return_value=3 * 1024**3):
                result = module.check(system_profile)
                # Should have 2 findings: profiles list + unused profiles warning
                assert len(result.findings) == 2
                warning_finding = [f for f in result.findings if f.severity == Severity.WARNING][0]
                assert "unused" in warning_finding.title.lower()
                assert warning_finding.data["type"] == "unused_profiles"


def test_check_skips_special_profiles(module, system_profile):
    """Test check skips special profiles."""
    recent_date = datetime.now(timezone.utc) - timedelta(days=30)

    profiles = [
        {
            "LocalPath": "C:\\Windows\\System32\\config\\systemprofile",
            "SID": "S-1-5-18",
            "LastUseTime": recent_date.isoformat().replace("+00:00", "Z"),
            "Special": True,
        },
        {
            "LocalPath": "C:\\Users\\normaluser",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-1001",
            "LastUseTime": recent_date.isoformat().replace("+00:00", "Z"),
            "Special": False,
        },
    ]
    user_accounts = {"S-1-5-21-1234567890-1234567890-1234567890-1001"}

    with patch.object(module, "_get_user_profiles", return_value=profiles):
        with patch.object(module, "_get_user_accounts", return_value=user_accounts):
            with patch.object(module, "_get_directory_size_powershell", return_value=1 * 1024**3):
                result = module.check(system_profile)
                # Should only count the normal profile, not the special one
                info_finding = [f for f in result.findings if f.severity == Severity.INFO][0]
                assert "1 user profile" in info_finding.title


def test_fix_with_orphaned_profiles(module):
    """Test fix action for orphaned profiles."""
    check_result = module.check(
        SystemProfile(
            platform=Platform.WIN32,
            os_name="Windows",
            os_version="11",
            architecture="x86_64",
            cpu_model="Intel Core i7",
            cpu_cores=8,
            ram_bytes=16 * 1024**3,
        )
    )

    profiles = [
        {
            "LocalPath": "C:\\Users\\orphan",
            "SID": "S-1-5-21-1234567890-1234567890-1234567890-9999",
            "size": 1 * 1024**3,
            "is_orphaned": True,
            "is_temp": False,
            "is_large": False,
            "is_unused": False,
        },
    ]

    with patch.object(module, "_get_user_profiles", return_value=[]):
        with patch.object(module, "_get_user_accounts", return_value=set()):
            # Manually create a finding for testing
            from rescue.models import Finding
            check_result.findings = [
                Finding(
                    title="Found 1 orphaned profile(s)",
                    description="Test",
                    severity=Severity.WARNING,
                    category="performance",
                    data={
                        "type": "orphaned_profiles",
                        "count": 1,
                        "profiles": profiles,
                    },
                )
            ]

            fix_result = module.fix(check_result, Mode.MANUAL)
            assert len(fix_result.actions) == 1
            assert fix_result.actions[0].success is True
            assert "System Properties" in fix_result.actions[0].description


def test_fix_with_all_finding_types(module):
    """Test fix actions for all finding types."""
    from rescue.models import Finding

    check_result = Module().check(
        SystemProfile(
            platform=Platform.WIN32,
            os_name="Windows",
            os_version="11",
            architecture="x86_64",
            cpu_model="Intel Core i7",
            cpu_cores=8,
            ram_bytes=16 * 1024**3,
        )
    )

    findings = [
        Finding(
            title="Found 2 user profiles",
            description="Test",
            severity=Severity.INFO,
            category="performance",
            data={"type": "profiles_list", "count": 2, "total_size_formatted": "5.0 GB"},
        ),
        Finding(
            title="Found 1 orphaned profile",
            description="Test",
            severity=Severity.WARNING,
            category="performance",
            data={"type": "orphaned_profiles", "count": 1, "profiles": []},
        ),
        Finding(
            title="Found 1 temporary profile",
            description="Test",
            severity=Severity.WARNING,
            category="performance",
            data={"type": "temp_profiles", "count": 1, "profiles": []},
        ),
        Finding(
            title="Found 1 large profile",
            description="Test",
            severity=Severity.WARNING,
            category="performance",
            data={"type": "large_profiles", "count": 1, "profiles": []},
        ),
        Finding(
            title="Found 1 unused profile",
            description="Test",
            severity=Severity.WARNING,
            category="performance",
            data={"type": "unused_profiles", "count": 1, "profiles": []},
        ),
    ]
    check_result.findings = findings

    fix_result = module.fix(check_result, Mode.MANUAL)
    assert len(fix_result.actions) == 5
    assert all(a.success for a in fix_result.actions)
