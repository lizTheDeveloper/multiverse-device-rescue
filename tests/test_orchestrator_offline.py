import os

import pytest
from rescue import orchestrator
from rescue.models import Platform
from rescue.orchestrator import OFFLINE_UNSUPPORTED_REASON, Orchestrator
from rescue.profiler.base import gather_target_profile

# Disk checks read Linux and macOS layouts (symlinks, FIFOs, POSIX modes) and
# only run from those hosts, so these tests do too.
pytestmark = pytest.mark.skipif(os.name != "posix", reason="offline disk checks run on POSIX hosts")

_TEMPLATE = '''
from rescue.models import CheckResult, Platform, RiskLevel
from rescue.module_base import ModuleBase


class Module(ModuleBase):
    name = "{name}"
    category = "test"
    platforms = [Platform.LINUX]
    risk_level = RiskLevel.SAFE
    depends_on = []
    offline_capable = {capable}

    def check(self, profile):
        {body}
        return CheckResult(module_name=self.name)

    def fix(self, findings, mode):
        raise NotImplementedError
'''


def _modules_dir(tmp_path):
    base = tmp_path / "mods" / "test"
    for name, capable, body in [
        ("disk_ok", True, "pass"),
        ("live_only", False, "raise AssertionError('must not run offline')"),
    ]:
        d = base / name
        d.mkdir(parents=True)
        (d / "__init__.py").write_text(
            _TEMPLATE.format(name=name, capable=capable, body=body)
        )
    return tmp_path / "mods"


def test_offline_skips_modules_not_marked_capable(linux_disk, tmp_path):
    profile = gather_target_profile(linux_disk, Platform.LINUX)
    results = {
        m.name: c
        for m, c in Orchestrator(
            modules_dir=_modules_dir(tmp_path), system_profile=profile
        ).run_checks()
    }
    assert results["live_only"].supported is False
    assert results["live_only"].unsupported_reason == OFFLINE_UNSUPPORTED_REASON
    assert results["disk_ok"].supported is True


def test_offline_never_touches_marks(linux_disk, tmp_path, monkeypatch):
    called = []
    monkeypatch.setattr(orchestrator, "_apply_item_marks", lambda *a, **k: called.append(a))
    profile = gather_target_profile(linux_disk, Platform.LINUX)
    Orchestrator(modules_dir=_modules_dir(tmp_path), system_profile=profile).run_checks()
    assert called == []


def test_offline_run_fixes_runs_nothing(linux_disk, tmp_path):
    from rescue.models import CheckResult, Finding, Mode, Severity

    fixed = []

    class _Mod:
        name = "m"
        risk_level = orchestrator.RiskLevel.SAFE
        auto_apply = True

        def fix(self, check, mode):
            fixed.append(mode)

    finding = Finding(title="t", description="d", severity=Severity.WARNING, category="c")
    checks = [(_Mod(), CheckResult(module_name="m", findings=[finding]))]
    profile = gather_target_profile(linux_disk, Platform.LINUX)
    orch = Orchestrator(modules_dir=_modules_dir(tmp_path), system_profile=profile)
    for mode in Mode:
        assert orch.run_fixes(checks, mode) == []
    assert fixed == []


def test_offline_run_auto_applies_nothing(linux_disk, tmp_path, monkeypatch):
    profile = gather_target_profile(linux_disk, Platform.LINUX)
    orch = Orchestrator(modules_dir=_modules_dir(tmp_path), system_profile=profile)
    monkeypatch.setattr(orch, "run_fixes", lambda *a: (_ for _ in ()).throw(AssertionError("no fixes")))
    out = orch.run_auto()
    assert out and all(fix is None for _, _, fix in out)
