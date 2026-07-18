from rescue.models import (
    Platform,
    RiskLevel,
    Severity,
    Mode,
    DiskInfo,
    ProcessInfo,
    SystemProfile,
    Finding,
    CheckResult,
    Action,
    FixResult,
)


def test_platform_values():
    assert Platform.DARWIN == "darwin"
    assert Platform.WIN32 == "win32"
    assert Platform.LINUX == "linux"


def test_risk_level_ordering():
    assert RiskLevel.SAFE == "safe"
    assert RiskLevel.MODERATE == "moderate"
    assert RiskLevel.DESTRUCTIVE == "destructive"


def test_system_profile_creation():
    profile = SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )
    assert profile.platform == Platform.DARWIN
    assert profile.disks == []
    assert profile.processes == []
    assert profile.hostname == ""


def test_check_result_has_issues():
    empty = CheckResult(module_name="test")
    assert not empty.has_issues

    with_finding = CheckResult(
        module_name="test",
        findings=[
            Finding(
                title="Test",
                description="A test finding",
                severity=Severity.WARNING,
                category="test",
            )
        ],
    )
    assert with_finding.has_issues


def test_fix_result_all_succeeded():
    result = FixResult(
        module_name="test",
        actions=[
            Action(
                title="Action 1",
                description="Did something",
                risk_level=RiskLevel.SAFE,
                success=True,
            ),
            Action(
                title="Action 2",
                description="Did another thing",
                risk_level=RiskLevel.SAFE,
                success=True,
            ),
        ],
    )
    assert result.all_succeeded

    result.actions[1].success = False
    assert not result.all_succeeded


def test_finding_default_data():
    finding = Finding(
        title="Test",
        description="Desc",
        severity=Severity.INFO,
        category="test",
    )
    assert finding.data == {}


def test_disk_info_ssd_default():
    disk = DiskInfo(
        device="/dev/disk1",
        mount_point="/",
        total_bytes=500 * 1024**3,
        used_bytes=400 * 1024**3,
        free_bytes=100 * 1024**3,
        filesystem="apfs",
    )
    assert disk.is_ssd is None


def test_finding_code_defaults_to_none():
    from rescue.models import Finding, Severity
    f = Finding(title="t", description="d", severity=Severity.WARNING, category="security")
    assert f.code is None


def test_finding_code_roundtrips():
    from rescue.models import Finding, Severity
    f = Finding(title="t", description="d", severity=Severity.CRITICAL,
                category="security", code="security.ssh_key_audit.world_readable_key")
    assert f.code == "security.ssh_key_audit.world_readable_key"
