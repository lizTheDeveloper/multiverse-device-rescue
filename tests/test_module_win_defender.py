import json
import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


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
    return next(m for m in modules if m.name == "win_defender")


def _fake_run(status_dict, set_returncode=0):
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        if "Get-MpComputerStatus" in " ".join(cmd):
            result.stdout = json.dumps(status_dict)
        else:
            # Set-MpPreference / Update-MpSignature fix commands
            result.stdout = ""
            result.returncode = set_returncode
            if set_returncode != 0:
                result.stderr = "Access is denied."
        return result
    return fake_run


HEALTHY_STATUS = {
    "AMServiceEnabled": True,
    "AntispywareEnabled": True,
    "AntivirusEnabled": True,
    "RealTimeProtectionEnabled": True,
    "AntivirusSignatureAge": 1,
}


def test_win_defender_discovered():
    mod = _get_module()
    assert mod.name == "win_defender"
    assert mod.category == "security"
    assert Platform.WIN32 in mod.platforms
    assert mod.risk_level == RiskLevel.MODERATE


def test_win_defender_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_STATUS)):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_defender_antivirus_disabled():
    mod = _get_module()
    status = dict(HEALTHY_STATUS, AntivirusEnabled=False)
    with patch("subprocess.run", side_effect=_fake_run(status)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.data["check"] == "antivirus_enabled" for f in result.findings)


def test_win_defender_realtime_protection_disabled():
    mod = _get_module()
    status = dict(HEALTHY_STATUS, RealTimeProtectionEnabled=False)
    with patch("subprocess.run", side_effect=_fake_run(status)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].data["check"] == "realtime_protection"
    assert result.findings[0].severity == Severity.CRITICAL


def test_win_defender_stale_signatures_is_warning():
    mod = _get_module()
    status = dict(HEALTHY_STATUS, AntivirusSignatureAge=14)
    with patch("subprocess.run", side_effect=_fake_run(status)):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert result.findings[0].data["check"] == "signature_age"
    assert result.findings[0].severity == Severity.WARNING


def test_win_defender_handles_unparseable_output():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run(HEALTHY_STATUS)) as _:
        pass

    def bad_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = "Defender module not available on this system\n"
        result.stderr = ""
        return result

    with patch("subprocess.run", side_effect=bad_run):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_win_defender_fix_re_enables_realtime_protection():
    mod = _get_module()
    status = dict(HEALTHY_STATUS, RealTimeProtectionEnabled=False)
    with patch("subprocess.run", side_effect=_fake_run(status)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert fix.all_succeeded
    assert len(fix.actions) == 1


def test_win_defender_fix_handles_permission_failure():
    mod = _get_module()
    status = dict(HEALTHY_STATUS, AntivirusEnabled=False)
    with patch("subprocess.run", side_effect=_fake_run(status, set_returncode=1)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert not fix.all_succeeded
    assert "Access is denied" in fix.actions[0].error
