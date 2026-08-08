"""Tests for linux_memory_pressure.

The thing being protected: low *free* memory is normal on Linux and must never
produce a finding on its own. Only MemAvailable, swap ratios, and PSI do.
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, ProcessInfo, Severity, SystemProfile
from rescue.registry import discover_modules

GB = 1024**2  # /proc/meminfo is in kB, so 1 GB == 1024**2 kB


def _meminfo(total_gb=16, free_gb=0.2, available_gb=12, swap_total_gb=8, swap_free_gb=8):
    return (
        f"MemTotal:       {int(total_gb * GB)} kB\n"
        f"MemFree:        {int(free_gb * GB)} kB\n"
        f"MemAvailable:   {int(available_gb * GB)} kB\n"
        f"SwapTotal:      {int(swap_total_gb * GB)} kB\n"
        f"SwapFree:       {int(swap_free_gb * GB)} kB\n"
    )


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_memory_pressure")


def _profile(platform=Platform.LINUX, processes=None) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Ubuntu 24.04",
        os_version="6.8.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=16 * 1024**3,
        processes=processes or [],
    )


def _configure(mod, tmp_path, meminfo=None, psi=None):
    meminfo_path = tmp_path / "meminfo"
    meminfo_path.write_text(meminfo if meminfo is not None else _meminfo())
    mod.meminfo_path = str(meminfo_path)
    if psi is None:
        mod.psi_path = str(tmp_path / "absent-psi")
    else:
        psi_path = tmp_path / "psi"
        psi_path.write_text(psi)
        mod.psi_path = str(psi_path)
    return mod


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.WIN32)).supported is False


def test_low_free_memory_alone_is_not_a_finding(tmp_path):
    """0.2 GB free of 16 GB is a healthy Linux system, not a problem."""
    mod = _configure(_get_module(), tmp_path, meminfo=_meminfo(free_gb=0.2, available_gb=12))
    assert not mod.check(_profile()).has_issues


def test_low_available_memory_is_a_finding(tmp_path):
    mod = _configure(_get_module(), tmp_path, meminfo=_meminfo(available_gb=1))
    result = mod.check(_profile())
    finding = next(f for f in result.findings if f.code.endswith("low_available_memory"))
    assert finding.severity is Severity.WARNING


def test_very_low_available_memory_is_critical(tmp_path):
    mod = _configure(_get_module(), tmp_path, meminfo=_meminfo(available_gb=0.5))
    finding = next(
        f for f in mod.check(_profile()).findings if f.code.endswith("low_available_memory")
    )
    assert finding.severity is Severity.CRITICAL


def test_psi_stall_is_reported(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        psi="some avg10=30.00 avg60=28.50 avg300=10.00 total=123\n"
            "full avg10=5.00 avg60=4.00 avg300=1.00 total=45\n",
    )
    finding = next(f for f in mod.check(_profile()).findings if f.code.endswith("memory_stall"))
    assert finding.severity is Severity.CRITICAL
    assert finding.data["psi_some_avg60"] == 28.5


def test_low_psi_is_not_reported(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        psi="some avg10=0.10 avg60=0.05 avg300=0.00 total=1\n",
    )
    assert "performance.linux_memory_pressure.memory_stall" not in _codes(mod.check(_profile()))


def test_missing_psi_file_is_tolerated(tmp_path):
    """PSI needs kernel 4.20+; its absence must not break the check."""
    mod = _configure(_get_module(), tmp_path, psi=None)
    assert mod.check(_profile()).error is None


def test_heavy_swap_use_is_reported(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        meminfo=_meminfo(swap_total_gb=8, swap_free_gb=1),
    )
    finding = next(
        f for f in mod.check(_profile()).findings if f.code.endswith("heavy_swap_use")
    )
    assert finding.severity is Severity.CRITICAL


def test_light_swap_use_is_not_reported(tmp_path):
    mod = _configure(
        _get_module(), tmp_path,
        meminfo=_meminfo(swap_total_gb=8, swap_free_gb=7),
    )
    assert "performance.linux_memory_pressure.heavy_swap_use" not in _codes(mod.check(_profile()))


def test_no_swap_with_plenty_of_memory_is_not_a_finding(tmp_path):
    """Running without swap is a legitimate configuration on its own."""
    mod = _configure(
        _get_module(), tmp_path,
        meminfo=_meminfo(available_gb=12, swap_total_gb=0, swap_free_gb=0),
    )
    assert "performance.linux_memory_pressure.no_swap_configured" not in _codes(mod.check(_profile()))


def test_no_swap_with_tight_memory_is_a_finding(tmp_path):
    """With no swap and no headroom, the kernel's only option is to kill things."""
    mod = _configure(
        _get_module(), tmp_path,
        meminfo=_meminfo(available_gb=1, swap_total_gb=0, swap_free_gb=0),
    )
    assert "performance.linux_memory_pressure.no_swap_configured" in _codes(mod.check(_profile()))


def test_memory_hogs_are_named(tmp_path):
    mod = _configure(_get_module(), tmp_path)
    processes = [
        ProcessInfo(pid=1, name="firefox", cpu_percent=1.0, memory_bytes=4 * 1024**3, command="firefox"),
        ProcessInfo(pid=2, name="tiny", cpu_percent=0.1, memory_bytes=10 * 1024**2, command="tiny"),
    ]
    result = mod.check(_profile(processes=processes))
    hogs = [f for f in result.findings if f.code.endswith("memory_hog")]
    assert len(hogs) == 1
    assert hogs[0].data["name"] == "firefox"
    assert hogs[0].severity is Severity.INFO


def test_fix_does_not_kill_processes(tmp_path):
    mod = _configure(_get_module(), tmp_path, meminfo=_meminfo(available_gb=0.5))
    fix = mod.fix(mod.check(_profile()), Mode.CLI)
    assert fix.executed_mutations == []
    assert any("does not kill processes" in a.description for a in fix.actions)
