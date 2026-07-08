import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile(ram_bytes: int = 16 * 1024**3):
    return SystemProfile(
        platform=Platform.DARWIN,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=ram_bytes,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "swap_memory_check")


class TestSwapMemoryCheckDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "swap_memory_check"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 75
        assert mod.estimated_duration == "3s"
        assert mod.depends_on == []


class TestSwapMemoryCheckSwapUsage:
    def test_normal_swap_usage(self):
        """Test parsing of normal swap usage."""
        mod = _get_module()
        swap_output = "vm.swapusage: total = 4096.00M  used = 512.00M  free = 3584.00M  (encrypted)"
        info = {}
        mod._parse_swap_usage(swap_output, info)

        assert info["swap_total_bytes"] == 4096 * 1024 * 1024
        assert info["swap_used_bytes"] == 512 * 1024 * 1024

    def test_swap_usage_in_gigabytes(self):
        """Test parsing swap usage in gigabytes."""
        mod = _get_module()
        swap_output = "vm.swapusage: total = 4.0G  used = 1.5G  free = 2.5G  (encrypted)"
        info = {}
        mod._parse_swap_usage(swap_output, info)

        assert info["swap_total_bytes"] == int(4.0 * 1024 * 1024 * 1024)
        assert info["swap_used_bytes"] == int(1.5 * 1024 * 1024 * 1024)

    def test_critical_swap_exceeds_ram(self):
        """Test detection of swap usage exceeding physical RAM."""
        mod = _get_module()
        profile = _make_profile(ram_bytes=8 * 1024**3)  # 8GB RAM

        # Mock vm_stat and swap to have swap > RAM
        swap_output = "vm.swapusage: total = 16.0G  used = 10.0G  free = 6.0G  (encrypted)"
        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                       0.\n"
            "Pages pageins:                    100000.\n"
            "Pages pageouts:                   500000.\n"
        )

        with patch.object(mod, "_parse_swap_usage") as mock_swap:
            with patch.object(mod, "_parse_vm_stat") as mock_vm:
                # Manually set up the info dict for critical condition
                def setup_swap(output, info):
                    info["swap_total_bytes"] = int(16.0 * 1024 * 1024 * 1024)
                    info["swap_used_bytes"] = int(10.0 * 1024 * 1024 * 1024)

                def setup_vm(output, info):
                    info["page_size"] = 4096
                    info["free_pages"] = 1000000
                    info["active_pages"] = 500000
                    info["inactive_pages"] = 300000
                    info["wired_pages"] = 200000
                    info["compressed_pages"] = 0
                    info["page_ins"] = 100000
                    info["page_outs"] = 500000

                mock_swap.side_effect = setup_swap
                mock_vm.side_effect = setup_vm

                result = mod.check(profile)

        assert result.has_issues
        critical_finding = next(
            (f for f in result.findings if f.severity == Severity.CRITICAL), None
        )
        assert critical_finding is not None
        assert "exceeds physical ram" in critical_finding.title.lower()


class TestSwapMemoryCheckPageOuts:
    def test_high_page_outs_detected(self):
        """Test detection of high page-out activity (>1M pages)."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                       0.\n"
            "Pages pageins:                    500000.\n"
            "Pages pageouts:                 1500000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 100.00M  free = 3996.00M  (encrypted)"

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),  # sysctl vm.swapusage
                MagicMock(returncode=0, stdout=vm_stat_output),  # vm_stat
                MagicMock(returncode=0, stdout="kern.memorystatus_vm_pressure_level: 0"),  # memory pressure
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        assert result.has_issues
        warning_finding = next(
            (f for f in result.findings if f.data.get("check") == "high_page_outs"), None
        )
        assert warning_finding is not None
        assert warning_finding.severity == Severity.WARNING

    def test_normal_page_outs(self):
        """Test that normal page-out activity doesn't trigger warning."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                       0.\n"
            "Pages pageins:                     50000.\n"
            "Pages pageouts:                   100000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 50.00M  free = 4046.00M  (encrypted)"

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),  # sysctl vm.swapusage
                MagicMock(returncode=0, stdout=vm_stat_output),  # vm_stat
                MagicMock(returncode=0, stdout="kern.memorystatus_vm_pressure_level: 0"),  # memory pressure
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        # Should not have warning for high page outs
        warning_finding = next(
            (f for f in result.findings if f.data.get("check") == "high_page_outs"), None
        )
        assert warning_finding is None


class TestSwapMemoryCheckMemoryPressure:
    def test_critical_memory_pressure_detected(self):
        """Test detection of critical memory pressure level."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                        100000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                 100000.\n"
            "Pages pageins:                    500000.\n"
            "Pages pageouts:                   500000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 2048.00M  free = 2048.00M  (encrypted)"
        pressure_output = "kern.memorystatus_vm_pressure_level: 2"  # Critical

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),  # sysctl vm.swapusage
                MagicMock(returncode=0, stdout=vm_stat_output),  # vm_stat
                MagicMock(returncode=0, stdout=pressure_output),  # memory pressure
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        assert result.has_issues
        warning_finding = next(
            (f for f in result.findings if f.data.get("check") == "critical_memory_pressure"), None
        )
        assert warning_finding is not None
        assert warning_finding.severity == Severity.WARNING

    def test_normal_memory_pressure(self):
        """Test that normal memory pressure doesn't trigger warning."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       5000000.\n"
            "Pages active:                     3000000.\n"
            "Pages inactive:                   2000000.\n"
            "Pages wired down:                 1000000.\n"
            "Pages compressed:                       0.\n"
            "Pages pageins:                     50000.\n"
            "Pages pageouts:                    50000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 10.00M  free = 4086.00M  (encrypted)"
        pressure_output = "kern.memorystatus_vm_pressure_level: 0"  # Normal

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),
                MagicMock(returncode=0, stdout=vm_stat_output),
                MagicMock(returncode=0, stdout=pressure_output),
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        # Should not have critical warnings
        warning_finding = next(
            (f for f in result.findings if f.severity == Severity.CRITICAL), None
        )
        assert warning_finding is None


class TestSwapMemoryCheckInfoFindings:
    def test_swap_status_info_finding(self):
        """Test that swap status is reported as INFO."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                       0.\n"
            "Pages pageins:                     50000.\n"
            "Pages pageouts:                    50000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 512.00M  free = 3584.00M  (encrypted)"

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),
                MagicMock(returncode=0, stdout=vm_stat_output),
                MagicMock(returncode=0, stdout="kern.memorystatus_vm_pressure_level: 0"),
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        swap_finding = next(
            (f for f in result.findings if f.data.get("check") == "swap_status"), None
        )
        assert swap_finding is not None
        assert swap_finding.severity == Severity.INFO
        assert "512.0 MB" in swap_finding.description

    def test_memory_stats_info_finding(self):
        """Test that memory allocation stats are reported."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                     2000000.\n"
            "Pages inactive:                   1500000.\n"
            "Pages wired down:                  500000.\n"
            "Pages compressed:                  100000.\n"
            "Pages pageins:                    100000.\n"
            "Pages pageouts:                   100000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 100.00M  free = 3996.00M  (encrypted)"

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),
                MagicMock(returncode=0, stdout=vm_stat_output),
                MagicMock(returncode=0, stdout="kern.memorystatus_vm_pressure_level: 0"),
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        stats_finding = next(
            (f for f in result.findings if f.data.get("check") == "memory_stats"), None
        )
        assert stats_finding is not None
        assert stats_finding.severity == Severity.INFO
        assert "Active:" in stats_finding.description
        assert "Compressed:" in stats_finding.description

    def test_page_activity_info_finding(self):
        """Test that page activity metrics are reported."""
        mod = _get_module()
        profile = _make_profile()

        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                       0.\n"
            "Pages pageins:                    500000.\n"
            "Pages pageouts:                   200000.\n"
        )
        swap_output = "vm.swapusage: total = 4096.00M  used = 100.00M  free = 3996.00M  (encrypted)"

        with patch("subprocess.run") as mock_run:
            mock_results = [
                MagicMock(returncode=0, stdout=swap_output),
                MagicMock(returncode=0, stdout=vm_stat_output),
                MagicMock(returncode=0, stdout="kern.memorystatus_vm_pressure_level: 0"),
            ]
            mock_run.side_effect = mock_results

            result = mod.check(profile)

        activity_finding = next(
            (f for f in result.findings if f.data.get("check") == "page_activity"), None
        )
        assert activity_finding is not None
        assert activity_finding.severity == Severity.INFO
        assert "Page-ins: 500,000" in activity_finding.description
        assert "Page-outs: 200,000" in activity_finding.description


class TestSwapMemoryCheckFix:
    def test_fix_critical_swap_exceeds_ram(self):
        """Test fix actions for critical swap exceeds RAM."""
        mod = _get_module()
        from rescue.models import CheckResult, Finding

        finding = Finding(
            title="Critical: Swap usage exceeds physical RAM",
            description="Test",
            severity=Severity.CRITICAL,
            category="performance",
            data={"check": "critical_swap_exceeds_ram"},
        )
        check = CheckResult(module_name=mod.name, findings=[finding])
        fix = mod.fix(check, Mode.MANUAL)

        assert len(fix.actions) > 0
        assert fix.actions[0].success
        assert fix.actions[0].risk_level == RiskLevel.SAFE
        assert "Activity Monitor" in fix.actions[0].description

    def test_fix_high_page_outs(self):
        """Test fix actions for high page-out activity."""
        mod = _get_module()
        from rescue.models import CheckResult, Finding

        finding = Finding(
            title="Warning: High page-out activity detected",
            description="Test",
            severity=Severity.WARNING,
            category="performance",
            data={"check": "high_page_outs"},
        )
        check = CheckResult(module_name=mod.name, findings=[finding])
        fix = mod.fix(check, Mode.MANUAL)

        assert len(fix.actions) > 0
        assert fix.actions[0].success
        assert "thrashing" in fix.actions[0].title.lower()

    def test_fix_critical_memory_pressure(self):
        """Test fix actions for critical memory pressure."""
        mod = _get_module()
        from rescue.models import CheckResult, Finding

        finding = Finding(
            title="Warning: Critical memory pressure detected",
            description="Test",
            severity=Severity.WARNING,
            category="performance",
            data={"check": "critical_memory_pressure"},
        )
        check = CheckResult(module_name=mod.name, findings=[finding])
        fix = mod.fix(check, Mode.MANUAL)

        assert len(fix.actions) > 0
        assert fix.actions[0].success
        assert fix.actions[0].risk_level == RiskLevel.SAFE


class TestSwapMemoryCheckConversion:
    def test_convert_to_bytes_megabytes(self):
        """Test conversion from megabytes to bytes."""
        mod = _get_module()
        result = mod._convert_to_bytes(512.0, "M")
        assert result == 512 * 1024 * 1024

    def test_convert_to_bytes_gigabytes(self):
        """Test conversion from gigabytes to bytes."""
        mod = _get_module()
        result = mod._convert_to_bytes(2.0, "G")
        assert result == 2 * 1024 * 1024 * 1024

    def test_convert_to_bytes_no_unit(self):
        """Test conversion with no unit assumes bytes."""
        mod = _get_module()
        result = mod._convert_to_bytes(1024.0, "")
        assert result == 1024


class TestSwapMemoryCheckParseVmStat:
    def test_parse_vm_stat(self):
        """Test parsing of vm_stat output."""
        mod = _get_module()
        vm_stat_output = (
            "Mach Virtual Memory Statistics: (page size of 4096 bytes)\n"
            "Pages free:                       1000000.\n"
            "Pages active:                      500000.\n"
            "Pages inactive:                    300000.\n"
            "Pages wired down:                  200000.\n"
            "Pages compressed:                  100000.\n"
            "Pages pageins:                    150000.\n"
            "Pages pageouts:                   200000.\n"
        )
        info = {}
        mod._parse_vm_stat(vm_stat_output, info)

        assert info["page_size"] == 4096
        assert info["free_pages"] == 1000000
        assert info["active_pages"] == 500000
        assert info["inactive_pages"] == 300000
        assert info["wired_pages"] == 200000
        assert info["compressed_pages"] == 100000
        assert info["page_ins"] == 150000
        assert info["page_outs"] == 200000
