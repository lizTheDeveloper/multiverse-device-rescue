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
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "disk_fragmentation_check")


def _make_diskutil_result(is_ssd=True, filesystem="APFS"):
    """Create diskutil info output."""
    if is_ssd:
        return f"""   Device Identifier:        disk0
   Device Node:              /dev/disk0
   Whole Device:             Yes
   Part of Whole:            disk0
   Device / Media Name:       Apple SSD SM0512L

   Volume Name:              Macintosh HD
   Mounted:                  Yes
   Mount Point:              /

   Solid State:              Yes
   Type (Bundle):            {filesystem}
   File System Personality:  Case-insensitive Journaled APFS
   Type (Corner Cases):      -
   Name (Case-Insensitive):  APFS
   Character Encoding:       4354 (0x1106)
"""
    else:
        return f"""   Device Identifier:        disk1
   Device Node:              /dev/disk1
   Whole Device:             Yes

   Device / Media Name:       WDC WD10EZEX-08W

   Volume Name:              Backup
   Mounted:                  Yes
   Mount Point:              /

   Solid State:              No
   Type (Bundle):            {filesystem}
   File System Personality:  Case-insensitive Journaled {filesystem}
   Type (Corner Cases):      -
   Name (Case-Insensitive):  {filesystem}
   Character Encoding:       4354 (0x1106)
"""


def _make_df_result(total_bytes, used_bytes, free_bytes):
    """Create df -b output."""
    return f"""Filesystem                    Blocks       Used  Available Capacity  Mounted on
/dev/disk0s2           {total_bytes:11d} {used_bytes:10d} {free_bytes:10d}   {int((used_bytes/total_bytes)*100)}%  /
"""


class TestDiskFragmentationDiscovery:
    def test_module_discovered(self):
        mod = _get_module()
        assert mod.name == "disk_fragmentation_check"
        assert mod.category == "performance"
        assert mod.risk_level == RiskLevel.SAFE
        assert Platform.DARWIN in mod.platforms

    def test_module_properties(self):
        mod = _get_module()
        assert mod.priority == 60
        assert mod.estimated_duration == "5s"
        assert mod.depends_on == []


class TestDiskFragmentationSSDDetection:
    def test_ssd_detected(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=True, filesystem="APFS")
        df_output = _make_df_result(1000000000, 500000000, 500000000)

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        assert result.has_issues
        ssd_finding = next((f for f in result.findings if "SSD" in f.title), None)
        assert ssd_finding is not None
        assert ssd_finding.severity == Severity.INFO
        assert ssd_finding.data["disk_type"] == "SSD"
        assert ssd_finding.data["filesystem"] == "APFS"

    def test_ssd_no_warning(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=True, filesystem="APFS")
        df_output = _make_df_result(1000000000, 950000000, 50000000)  # 95% full

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        # SSD should not have warnings even at high usage
        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0


class TestDiskFragmentationHDDDetection:
    def test_hdd_detected(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 500000000, 500000000)

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        assert result.has_issues
        hdd_finding = next((f for f in result.findings if "HDD" in f.title), None)
        assert hdd_finding is not None
        assert hdd_finding.data["disk_type"] == "HDD"
        assert hdd_finding.data["filesystem"] == "HFS+"

    def test_hdd_warning_at_90_percent(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 900000000, 100000000)  # 90% full

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        # Should have warning for 90% full (HFS+ high usage triggers at >70%)
        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "high usage" in warnings[0].title.lower()
        assert warnings[0].data["usage_percent"] == 90

    def test_hdd_warning_above_90_percent(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 950000000, 50000000)  # 95% full

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert warnings[0].data["usage_percent"] == 95

    def test_hfs_plus_high_usage_warning(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 800000000, 200000000)  # 80% full

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 1
        assert "HFS+" in warnings[0].title
        assert "high usage" in warnings[0].title.lower()

    def test_apfs_hdd_no_extra_warning(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="APFS")
        df_output = _make_df_result(1000000000, 800000000, 200000000)  # 80% full on APFS

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        # APFS should not have the HFS+ specific warning
        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0

    def test_hdd_moderate_usage_no_warning(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 600000000, 400000000)  # 60% full

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        warnings = [f for f in result.findings if f.severity == Severity.WARNING]
        assert len(warnings) == 0


class TestDiskFragmentationError:
    def test_diskutil_failure(self):
        mod = _get_module()

        with patch("subprocess.run") as mock_run:
            mock_run.return_value.returncode = 1
            result = mod.check(_make_profile())

        # Should have an error finding but not crash
        assert isinstance(result.findings, list)
        # May be empty or have error finding
        assert result is not None

    def test_subprocess_timeout(self):
        mod = _get_module()

        with patch("subprocess.run") as mock_run:
            mock_run.side_effect = TimeoutError()
            result = mod.check(_make_profile())

        # Should handle timeout gracefully
        assert isinstance(result.findings, list)

    def test_general_exception(self):
        mod = _get_module()

        with patch.object(mod, "_get_disk_info") as mock_get_info:
            mock_get_info.side_effect = Exception("Test error")
            result = mod.check(_make_profile())

        # Should have error finding
        assert len(result.findings) == 1
        assert "Error" in result.findings[0].title


class TestDiskFragmentationFix:
    def test_fix_ssd(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=True, filesystem="APFS")
        df_output = _make_df_result(1000000000, 500000000, 500000000)

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

        assert fix.all_succeeded
        assert len(fix.actions) > 0
        assert all(a.success for a in fix.actions)
        assert all(a.risk_level == RiskLevel.SAFE for a in fix.actions)
        # SSD should recommend no defrag
        assert any("no action" in a.title.lower() or "SSD" in a.title for a in fix.actions)

    def test_fix_hdd_critical(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 950000000, 50000000)  # 95% full

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

        assert fix.all_succeeded
        # Should recommend freeing space
        assert any("free" in a.description.lower() for a in fix.actions)

    def test_fix_no_manual_defrag(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=False, filesystem="HFS+")
        df_output = _make_df_result(1000000000, 500000000, 500000000)

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            check = mod.check(_make_profile())
            fix = mod.fix(check, Mode.MANUAL)

        # Actions should not recommend manual defragmentation
        for action in fix.actions:
            description = action.description.lower()
            # Should NOT recommend running defrag utilities
            assert "defrag" not in description or "automatically" in description or "no" in description


class TestDiskFragmentationDataFormat:
    def test_bytes_formatting(self):
        from modules.performance.disk_fragmentation_check import _fmt_bytes

        assert _fmt_bytes(512) == "512.0 B"
        assert _fmt_bytes(1024) == "1.0 KB"
        assert _fmt_bytes(1024 * 1024) == "1.0 MB"
        assert _fmt_bytes(1024 * 1024 * 1024) == "1.0 GB"

    def test_finding_data_structure(self):
        mod = _get_module()
        diskutil_output = _make_diskutil_result(is_ssd=True, filesystem="APFS")
        df_output = _make_df_result(1000000000, 500000000, 500000000)

        with patch("subprocess.run") as mock_run:
            def run_side_effect(cmd, **kwargs):
                result = MagicMock()
                result.returncode = 0
                if "diskutil" in cmd:
                    result.stdout = diskutil_output
                elif "df" in cmd:
                    result.stdout = df_output
                return result

            mock_run.side_effect = run_side_effect
            result = mod.check(_make_profile())

        assert all("data" in dir(f) for f in result.findings)
        assert all(isinstance(f.data, dict) for f in result.findings)
