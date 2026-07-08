import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="14.5",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "memory_pressure_check")


def _make_run_result(
    pressure_level="normal",
    memsize="17179869184",
    pagesize="4096",
    vm_stat_output=None,
    swap_output="vm.swapusage: total = 4096.00M  used = 512.00M  free = 3584.00M  (encrypted)",
    compressor_mode="4",
):
    """Create a fake subprocess.run that returns appropriate results."""

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # memory_pressure command
        if "memory_pressure" in cmd_str:
            result.stdout = f"System memory pressure level: {pressure_level}\n"

        # sysctl hw.memsize
        elif "hw.memsize" in cmd_str:
            result.stdout = f"hw.memsize: {memsize}\n"

        # sysctl hw.pagesize
        elif "hw.pagesize" in cmd_str:
            result.stdout = f"hw.pagesize: {pagesize}\n"

        # vm_stat command
        elif cmd[0] == "vm_stat":
            if vm_stat_output is None:
                result.stdout = (
                    "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
                    "Pages free:                        4194304.\n"
                    "Pages active:                      2097152.\n"
                    "Pages inactive:                    1048576.\n"
                    "Pages speculative:                  524288.\n"
                    "Pages wired:                        262144.\n"
                    "Pages compressed:                   131072.\n"
                    "File-backed pages:                 1572864.\n"
                    "Anonymous pages:                   2621440.\n"
                    "Pages stored in swap:                49152.\n"
                    "Swap ins:                               10.\n"
                    "Swap outs:                             100.\n"
                    "Pages pageins:                        5000.\n"
                    "Pages pageouts:                       500.\n"
                    "Pages reactivated:                    8192.\n"
                )
            else:
                result.stdout = vm_stat_output

        # sysctl vm.swapusage
        elif "vm.swapusage" in cmd_str:
            result.stdout = swap_output

        # sysctl vm.compressor_mode
        elif "vm.compressor_mode" in cmd_str:
            result.stdout = f"vm.compressor_mode: {compressor_mode}\n"

        return result

    return fake_run


def test_memory_pressure_check_discovered():
    """Test that the module is discovered."""
    mod = _get_module()
    assert mod.name == "memory_pressure_check"
    assert mod.category == "performance"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_memory_pressure_check_healthy():
    """Test when system has healthy memory."""
    mod = _get_module()
    # Use low pageouts for healthy state
    vm_stat_output = (
        "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
        "Pages free:                        4194304.\n"
        "Pages active:                      2097152.\n"
        "Pages inactive:                    1048576.\n"
        "Pages speculative:                  524288.\n"
        "Pages wired down:                   262144.\n"
        "Pages compressed:                   131072.\n"
        "File-backed pages:                 1572864.\n"
        "Anonymous pages:                   2621440.\n"
        "Pages stored in swap:                49152.\n"
        "Swap ins:                               10.\n"
        "Swap outs:                             100.\n"
        "Pages pageins:                        5000.\n"
        "Pages pageouts:                        500.\n"
        "Pages reactivated:                    8192.\n"
    )
    with patch("subprocess.run", side_effect=_make_run_result(vm_stat_output=vm_stat_output)):
        result = mod.check(_make_profile())

    # Should have only INFO finding (memory breakdown)
    assert result.has_issues
    assert len(result.findings) == 1
    assert result.findings[0].severity == Severity.INFO
    assert "Memory Breakdown" in result.findings[0].title


def test_memory_pressure_check_critical_pressure():
    """Test when memory pressure is critical."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_run_result(pressure_level="critical")):
        result = mod.check(_make_profile())

    # Should have CRITICAL finding for critical pressure + INFO
    assert result.has_issues
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    assert len(critical_findings) >= 1
    assert "critical" in critical_findings[0].title.lower()


def test_memory_pressure_check_high_swap_usage():
    """Test when swap usage is high (>50%)."""
    mod = _get_module()
    # 2500M of 4096M = 61% usage
    swap_output = "vm.swapusage: total = 4096.00M  used = 2560.00M  free = 1536.00M  (encrypted)"
    with patch("subprocess.run", side_effect=_make_run_result(swap_output=swap_output)):
        result = mod.check(_make_profile())

    # Should have WARNING for high swap + INFO
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("swap" in f.title.lower() for f in warning_findings)


def test_memory_pressure_check_high_pageouts():
    """Test when pageout rate is high (>1000)."""
    mod = _get_module()
    vm_stat_output = (
        "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
        "Pages free:                        1048576.\n"
        "Pages active:                      4194304.\n"
        "Pages inactive:                    2097152.\n"
        "Pages speculative:                  262144.\n"
        "Pages wired:                        524288.\n"
        "Pages compressed:                   262144.\n"
        "File-backed pages:                 2097152.\n"
        "Anonymous pages:                   4194304.\n"
        "Pages stored in swap:                98304.\n"
        "Swap ins:                              100.\n"
        "Swap outs:                            500.\n"
        "Pages pageins:                       50000.\n"
        "Pages pageouts:                      5000.\n"
        "Pages reactivated:                   16384.\n"
    )
    with patch("subprocess.run", side_effect=_make_run_result(vm_stat_output=vm_stat_output)):
        result = mod.check(_make_profile())

    # Should have WARNING for high pageouts + INFO
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("page" in f.title.lower() for f in warning_findings)


def test_memory_pressure_check_high_wired_memory():
    """Test when wired memory is >60% of total RAM."""
    mod = _get_module()
    # With 16GB RAM, >60% = need wired to be > 9.6GB
    # wired_bytes > 10.3GB worth of pages
    total_gb = 16
    total_bytes = total_gb * 1024**3
    page_size = 4096
    # 65% of total RAM
    wired_pages = int((total_bytes * 0.65) / page_size)

    vm_stat_output = (
        "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
        "Pages free:                        1048576.\n"
        "Pages active:                      1048576.\n"
        "Pages inactive:                     524288.\n"
        "Pages speculative:                  262144.\n"
        f"Pages wired:                        {wired_pages}.\n"
        "Pages compressed:                    65536.\n"
        "File-backed pages:                  786432.\n"
        "Anonymous pages:                   2097152.\n"
        "Pages stored in swap:                24576.\n"
        "Swap ins:                               10.\n"
        "Swap outs:                             20.\n"
        "Pages pageins:                        2000.\n"
        "Pages pageouts:                        500.\n"
        "Pages reactivated:                    4096.\n"
    )
    with patch(
        "subprocess.run",
        side_effect=_make_run_result(
            memsize=str(total_bytes),
            vm_stat_output=vm_stat_output,
        ),
    ):
        result = mod.check(_make_profile())

    # Should have WARNING for high wired memory + INFO
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any("wired" in f.title.lower() or "kernel" in f.title.lower() for f in warning_findings)


def test_memory_pressure_check_fix_is_informational():
    """Test that fix() actions are informational and always succeed."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_run_result(pressure_level="critical")):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    # All actions should succeed (informational)
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    # All actions should be SAFE (informational)
    for action in fix.actions:
        assert action.risk_level == RiskLevel.SAFE
        assert action.success is True


def test_memory_pressure_check_fix_high_swap():
    """Test fix actions for high swap usage."""
    mod = _get_module()
    swap_output = "vm.swapusage: total = 4096.00M  used = 3000.00M  free = 1096.00M  (encrypted)"
    with patch("subprocess.run", side_effect=_make_run_result(swap_output=swap_output)):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    # Should have action about reducing swap
    assert any("Activity Monitor" in a.description for a in fix.actions)


def test_memory_pressure_check_fix_memory_breakdown():
    """Test that info finding gets appropriate action."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_run_result()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.AUTO)

    assert fix.all_succeeded
    # Should have action for memory monitoring
    assert any("Monitor" in a.title or "monitor" in a.title.lower() for a in fix.actions)


def test_memory_pressure_check_multiple_issues():
    """Test when multiple memory issues are present."""
    mod = _get_module()
    vm_stat_output = (
        "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
        "Pages free:                         262144.\n"
        "Pages active:                      8388608.\n"
        "Pages inactive:                     524288.\n"
        "Pages speculative:                   65536.\n"
        "Pages wired:                        3145728.\n"
        "Pages compressed:                   524288.\n"
        "File-backed pages:                 4194304.\n"
        "Anonymous pages:                   8388608.\n"
        "Pages stored in swap:               196608.\n"
        "Swap ins:                              200.\n"
        "Swap outs:                           1000.\n"
        "Pages pageins:                      100000.\n"
        "Pages pageouts:                     2500.\n"
        "Pages reactivated:                   32768.\n"
    )
    swap_output = "vm.swapusage: total = 4096.00M  used = 2560.00M  free = 1536.00M  (encrypted)"
    with patch(
        "subprocess.run",
        side_effect=_make_run_result(
            vm_stat_output=vm_stat_output,
            swap_output=swap_output,
        ),
    ):
        result = mod.check(_make_profile())

    # Should have multiple warning findings
    assert result.has_issues
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    # Should detect high swap and high pageouts
    assert len(warning_findings) >= 2


def test_memory_pressure_check_parse_pressure_normal():
    """Test parsing normal pressure level."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_run_result(pressure_level="normal")):
        result = mod.check(_make_profile())
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_memory_pressure_check_parse_pressure_warning():
    """Test parsing warning pressure level."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_make_run_result(pressure_level="warning")):
        result = mod.check(_make_profile())
    # Should not have critical, but should still have findings (INFO)
    assert not any(f.severity == Severity.CRITICAL for f in result.findings)


def test_memory_pressure_check_subprocess_timeout():
    """Test graceful handling of subprocess timeouts."""
    mod = _get_module()

    def fake_run_timeout(cmd, **kwargs):
        raise Exception("Timeout")

    with patch("subprocess.run", side_effect=fake_run_timeout):
        result = mod.check(_make_profile())

    # Should still report memory breakdown with default/empty values (graceful degradation)
    # but no critical/warning findings
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical_findings) == 0
    assert len(warning_findings) == 0
    # Should have INFO breakdown
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
