import json
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    ActionKind,
    Finding,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.registry import discover_modules

MODULE_NAME = "evidence_bundle"


def _module_object(mod):
    return sys.modules[type(mod).__module__]


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    return next(m for m in discover_modules(modules_dir) if m.name == MODULE_NAME)


class _Result:
    def __init__(self, ok=True, stdout="output", truncated=False):
        self.ok = ok
        self.stdout = stdout
        self.stderr = ""
        self.timed_out = False
        self.error = None
        self.truncated = truncated


@pytest.fixture
def mod(tmp_path):
    m = _get_module()
    m.state_dir = tmp_path / "state"
    m._tmp = tmp_path
    return m


def _finding(result, check):
    return next((f for f in result.findings if f.data.get("check") == check), None)


def _indicator(severity=Severity.CRITICAL):
    return Finding(
        title="Something bad",
        description="an indicator",
        severity=severity,
        category="security",
    )


def test_discovered_with_expected_metadata():
    m = _get_module()
    assert m.name == MODULE_NAME
    assert m.category == "security"
    assert m.risk_level == RiskLevel.SAFE
    assert getattr(m, "auto_apply", False) is False
    # Runs early: evidence must be considered before remediation modules act.
    assert m.priority >= 85


def test_check_never_writes_a_bundle(mod):
    """check() observes; creating files needs an explicit human decision."""
    result = mod.check(_make_profile())
    readiness = _finding(result, "readiness")
    assert readiness.data["bundle_written"] is False
    assert readiness.data["existing_bundles"] == []
    bundles = list((mod.state_dir / "evidence").glob("evidence-*"))
    assert bundles == []


def test_check_reports_collectable_categories(mod):
    result = mod.check(_make_profile())
    readiness = _finding(result, "readiness")
    assert "process list" in readiness.data["collectable_categories"]
    assert "network connections" in readiness.data["collectable_categories"]


def test_check_lists_what_is_never_collected(mod):
    result = mod.check(_make_profile())
    readiness = _finding(result, "readiness")
    body = readiness.description.lower()
    for forbidden in ("password", "token", "cookie", "private key", "browser history"):
        assert forbidden in body


def test_unwritable_destination_is_reported(mod):
    blocked = mod._tmp / "blocked"
    blocked.write_text("")
    mod.state_dir = blocked / "nested"
    result = mod.check(_make_profile())
    finding = _finding(result, "destination_unwritable")
    assert finding is not None
    assert finding.severity == Severity.WARNING


def test_indicators_without_a_bundle_produce_a_warning(mod):
    result = mod.assess_with_context(_make_profile(), [_indicator()])
    finding = _finding(result, "no_bundle_captured")
    assert finding is not None
    assert finding.severity == Severity.WARNING
    assert finding.data["indicator_count"] == 1
    # The warning must lead the report, ahead of the readiness inventory.
    assert result.findings[0].data.get("check") == "no_bundle_captured"


def test_no_indicators_produces_no_warning(mod):
    result = mod.assess_with_context(_make_profile(), [_indicator(Severity.INFO)])
    assert _finding(result, "no_bundle_captured") is None


def test_existing_bundle_suppresses_the_warning(mod):
    with patch.object(_module_object(mod), "run", return_value=_Result()):
        mod.write_bundle(_make_profile())
    result = mod.assess_with_context(_make_profile(), [_indicator()])
    assert _finding(result, "no_bundle_captured") is None


def test_write_bundle_produces_a_hashed_manifest(mod):
    with patch.object(_module_object(mod), "run", return_value=_Result(stdout="PID CMD\n1 init\n")):
        bundle = mod.write_bundle(_make_profile())

    assert bundle is not None
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["manifest_version"] == 1
    assert manifest["items"]
    for item in manifest["items"]:
        assert len(item["sha256"]) == 64
        assert item["command"]
        assert item["collected_at"]
        assert (bundle / item["file"]).is_file()


def test_manifest_records_omissions_rather_than_hiding_them(mod):
    def only_ps_works(args, **kw):
        if args[0] == "ps":
            return _Result(stdout="PID CMD\n")
        return _Result(ok=False)

    with patch.object(_module_object(mod), "run", side_effect=only_ps_works):
        bundle = mod.write_bundle(_make_profile())

    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["omitted"], "a failed collection must be recorded, not dropped"
    assert all("reason" in o for o in manifest["omitted"])


def test_manifest_declares_what_is_never_collected(mod):
    with patch.object(_module_object(mod), "run", return_value=_Result()):
        bundle = mod.write_bundle(_make_profile())
    manifest = json.loads((bundle / "manifest.json").read_text())
    assert manifest["never_collected"]
    assert manifest["chain_of_custody"]
    assert "not transmitted" in manifest["chain_of_custody"].lower()


def test_bundle_is_written_outside_the_repository(mod):
    with patch.object(_module_object(mod), "run", return_value=_Result()):
        bundle = mod.write_bundle(_make_profile())
    repo_root = Path(__file__).parent.parent.resolve()
    assert repo_root not in bundle.resolve().parents


def test_collection_commands_never_touch_credential_stores(mod):
    """Structural guarantee: no collection command reads a secret store."""
    for platform in (Platform.DARWIN, Platform.WIN32, Platform.LINUX):
        for _category, command in mod._collection_commands(_make_profile(platform)):
            joined = " ".join(command).lower()
            for forbidden in ("security", "keychain", "cmdkey", "vaultcmd", "cookies"):
                assert forbidden not in joined, f"{joined} may read a credential store"


def test_bundle_item_size_is_bounded(mod):
    huge = "x" * (2 * 1024 * 1024)
    with patch.object(_module_object(mod), "run", return_value=_Result(stdout=huge)):
        bundle = mod.write_bundle(_make_profile())

    manifest = json.loads((bundle / "manifest.json").read_text())
    for item in manifest["items"]:
        assert item["bytes"] <= 512 * 1024
        assert item["truncated"] is True


def test_write_bundle_on_unwritable_destination_returns_none(mod):
    blocked = mod._tmp / "blocked"
    blocked.write_text("")
    mod.state_dir = blocked / "nested"
    with patch.object(_module_object(mod), "run", return_value=_Result()):
        assert mod.write_bundle(_make_profile()) is None


def test_fix_is_guidance_only(mod):
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False


def test_fix_leads_with_preserve_before_repair(mod):
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    first = fix.actions[0]
    assert first.data.get("check") == "order_of_operations"
    body = first.description.lower()
    assert body.index("capture evidence now") < body.index("work through remediation")


def test_fix_tells_work_machine_users_to_stop(mod):
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    combined = " ".join(a.description for a in fix.actions).lower()
    assert "work machine" in combined
    assert "domestic abuse advocate" in combined
