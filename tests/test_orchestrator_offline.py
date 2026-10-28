from rescue import orchestrator
from rescue.models import Platform
from rescue.orchestrator import OFFLINE_UNSUPPORTED_REASON, Orchestrator
from rescue.profiler.base import gather_target_profile

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
