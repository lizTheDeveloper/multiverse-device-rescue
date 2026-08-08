"""Tests for the redacted rescue-case export (roadmap P1#2).

The export is the artifact most likely to be pasted into a chat window or a
public issue, so the tests are weighted toward redaction and toward the export
never overstating what happened.
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.case import (
    RescueCase,
    case_to_dict,
    case_to_json,
    case_to_markdown,
    redact,
    write_case,
)
from rescue.models import (
    Action,
    ActionKind,
    CheckResult,
    Finding,
    FixResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.module_base import ModuleBase


class _Mod(ModuleBase):
    name = "demo_module"
    category = "security"
    platforms = [Platform.LINUX]
    estimated_duration = "1s"

    def check(self, profile: SystemProfile) -> CheckResult:
        return CheckResult(module_name=self.name)

    def fix(self, findings: CheckResult, mode: Mode) -> FixResult:
        return FixResult(module_name=self.name)


def _profile() -> SystemProfile:
    return SystemProfile(
        platform=Platform.LINUX,
        os_name="Ubuntu 24.04",
        os_version="6.8.0",
        architecture="x86_64",
        cpu_model="Test CPU",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
        hostname="jane-smiths-laptop",
    )


def _case_with_finding(**finding_kwargs) -> RescueCase:
    case = RescueCase(profile=_profile(), profile_name=None, started_at="2026-01-01T00:00:00+00:00")
    defaults = dict(
        title="Something to look at",
        description="Details here.",
        severity=Severity.WARNING,
        category="security",
    )
    defaults.update(finding_kwargs)
    check = CheckResult(module_name="demo_module", findings=[Finding(**defaults)])
    case.add(_Mod(), check)
    return case


def test_github_token_is_redacted():
    secret = "ghp_" + "a" * 36
    assert secret not in redact(f"found token {secret} in config")
    assert "github token" in redact(f"found token {secret} in config")


def test_private_key_block_is_redacted():
    blob = "-----BEGIN OPENSSH PRIVATE KEY-----\nMIIEow\n-----END OPENSSH PRIVATE KEY-----"
    assert "MIIEow" not in redact(blob)


def test_key_value_secrets_are_redacted():
    assert "hunter2" not in redact("password=hunter2")
    assert "s3cr3t" not in redact("api_key: s3cr3t")


def test_email_addresses_are_redacted():
    assert "jane@example.com" not in redact("signed in as jane@example.com")


def test_authorization_header_is_redacted():
    assert "abc123" not in redact("Authorization: Bearer abc123")


def test_redaction_reaches_nested_finding_data():
    """Finding.data is free-form; 280 modules put arbitrary strings in it."""
    secret = "sk-" + "b" * 32
    case = _case_with_finding(data={"evidence": {"lines": [f"key={secret}"]}})
    assert secret not in case_to_json(case)


def test_hostname_is_never_exported():
    case = _case_with_finding()
    assert "jane-smiths-laptop" not in case_to_json(case)


def test_home_directory_path_is_collapsed():
    home = str(Path.home())
    case = _case_with_finding(description=f"Found at {home}/Library/LaunchAgents/x.plist")
    exported = case_to_dict(case)
    described = exported["modules"][0]["findings"][0]["description"]
    assert home not in described
    assert "~/Library/LaunchAgents/x.plist" in described


def test_guidance_is_never_counted_as_a_system_change():
    """A module marking guidance successful must not read as a repair (P0#6)."""
    case = RescueCase(profile=_profile())
    check = CheckResult(module_name="demo_module", findings=[
        Finding(title="t", description="d", severity=Severity.INFO, category="security")
    ])
    fix = FixResult(
        module_name="demo_module",
        actions=[
            Action(
                title="Open System Settings and turn this on",
                description="Manual step.",
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.GUIDANCE,
                executed=True,
                success=True,
            )
        ],
    )
    case.add(_Mod(), check, fix)
    exported = case_to_dict(case)
    assert exported["summary"]["system_changes"] == 0
    assert exported["summary"]["manual_actions_required"] == 1
    assert exported["modules"][0]["actions"][0]["changed_the_system"] is False


def test_executed_mutation_is_counted_as_a_system_change():
    case = RescueCase(profile=_profile())
    fix = FixResult(
        module_name="demo_module",
        actions=[
            Action(
                title="Enabled the firewall",
                description="Changed a setting.",
                risk_level=RiskLevel.SAFE,
                kind=ActionKind.MUTATION,
                executed=True,
                success=True,
                data={"rollback": "Turn the firewall back off in Settings."},
            )
        ],
    )
    case.add(_Mod(), CheckResult(module_name="demo_module"), fix)
    exported = case_to_dict(case)
    assert exported["summary"]["system_changes"] == 1
    assert exported["modules"][0]["actions"][0]["rollback"]


def test_failed_and_unsupported_checks_are_reported_not_hidden():
    """An unsupported check must never read as a clean bill of health."""
    case = RescueCase(profile=_profile())
    case.add(_Mod(), CheckResult(module_name="demo_module", error="boom"))
    case.add(
        _Mod(),
        CheckResult(module_name="demo_module", supported=False, unsupported_reason="wrong platform"),
    )
    exported = case_to_dict(case)
    assert exported["summary"]["modules_failed"] == 1
    assert exported["summary"]["modules_unsupported"] == 1
    markdown = case_to_markdown(case)
    assert "did not produce a result" in markdown
    assert "wrong platform" in markdown


def test_export_is_valid_json_with_a_schema_version():
    exported = json.loads(case_to_json(_case_with_finding()))
    assert exported["schema_version"] >= 1
    assert exported["redaction"]["applied"] is True


def test_non_serializable_finding_data_does_not_break_the_export():
    case = _case_with_finding(data={"path": Path("/tmp/x"), "when": object()})
    json.loads(case_to_json(case))  # must not raise


def test_write_case_produces_both_files(tmp_path):
    json_path, md_path = write_case(_case_with_finding(), tmp_path, stem="case-test")
    assert json_path.exists() and md_path.exists()
    assert json.loads(json_path.read_text())["schema_version"] >= 1
    assert "# Rescue case report" in md_path.read_text()


def test_written_files_are_owner_only(tmp_path):
    if sys.platform.startswith("win"):
        return  # POSIX mode bits are not meaningful here
    json_path, _ = write_case(_case_with_finding(), tmp_path, stem="case-perm")
    assert json_path.stat().st_mode & 0o077 == 0
