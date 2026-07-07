import sys
from pathlib import Path
from unittest.mock import patch, MagicMock
import tempfile

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
    return next(m for m in modules if m.name == "photos_library_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_library_missing():
    """Fake subprocess.run when library is missing"""
    def fake_run(cmd, **kwargs):
        # All defaults read calls fail if library is missing
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_library_exists_icloud_off():
    """Fake subprocess.run when library exists, iCloud Photos disabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "PQLCloudEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "CloudPhotoLibraryOptimizeStorageEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "CloudPhotoLibraryDownloadOriginalEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_library_exists_icloud_on_optimize():
    """Fake subprocess.run when library exists, iCloud on, Optimize Storage enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "PQLCloudEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "CloudPhotoLibraryOptimizeStorageEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "CloudPhotoLibraryDownloadOriginalEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        return _make_subprocess_result(returncode=1)
    return fake_run


def _fake_run_library_exists_icloud_on_download():
    """Fake subprocess.run when library exists, iCloud on, Download Originals enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "PQLCloudEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        elif "CloudPhotoLibraryOptimizeStorageEnabled" in cmd_str:
            return _make_subprocess_result(stdout="0")
        elif "CloudPhotoLibraryDownloadOriginalEnabled" in cmd_str:
            return _make_subprocess_result(stdout="1")
        return _make_subprocess_result(returncode=1)
    return fake_run


def test_photos_library_check_discovered():
    mod = _get_module()
    assert mod.name == "photos_library_check"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_photos_library_missing():
    """Test when Photos library doesn't exist"""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_library_missing()):
        with patch.object(Path, "home", return_value=Path(tempfile.mkdtemp())):
            result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "library_exists" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_photos_library_exists_icloud_off():
    """Test when library exists but iCloud Photos is disabled"""
    mod = _get_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        # Create mock library
        lib_path = tmp_path / "Pictures" / "Photos Library.photoslibrary"
        lib_path.mkdir(parents=True, exist_ok=True)
        # Create a small test file
        (lib_path / "test.db").write_text("test")

        with patch("subprocess.run", side_effect=_fake_run_library_exists_icloud_off()):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

    assert len(result.findings) > 0
    assert any(f.data.get("check") == "library_size" for f in result.findings)
    assert any(f.data.get("check") == "icloud_photos" for f in result.findings)


def test_photos_library_exists_icloud_on_optimize():
    """Test when library exists, iCloud on, Optimize Storage enabled"""
    mod = _get_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        lib_path = tmp_path / "Pictures" / "Photos Library.photoslibrary"
        lib_path.mkdir(parents=True, exist_ok=True)
        (lib_path / "test.db").write_text("test")

        with patch("subprocess.run", side_effect=_fake_run_library_exists_icloud_on_optimize()):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

    assert len(result.findings) > 0
    assert any(f.data.get("check") == "storage_optimization" for f in result.findings)
    # Should have optimize_storage set to True
    opt_findings = [f for f in result.findings if f.data.get("check") == "storage_optimization"]
    assert any(f.data.get("optimize_storage") for f in opt_findings)


def test_photos_library_exists_icloud_on_download():
    """Test when library exists, iCloud on, Download Originals enabled"""
    mod = _get_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        lib_path = tmp_path / "Pictures" / "Photos Library.photoslibrary"
        lib_path.mkdir(parents=True, exist_ok=True)
        (lib_path / "test.db").write_text("test")

        with patch("subprocess.run", side_effect=_fake_run_library_exists_icloud_on_download()):
            with patch.object(Path, "home", return_value=tmp_path):
                result = mod.check(_make_profile())

    assert len(result.findings) > 0
    opt_findings = [f for f in result.findings if f.data.get("check") == "storage_optimization"]
    assert any(f.data.get("download_originals") for f in opt_findings)


def test_photos_large_library_without_optimization():
    """Test warning when library is >100GB and Optimize Storage is off with iCloud on"""
    mod = _get_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        lib_path = tmp_path / "Pictures" / "Photos Library.photoslibrary"
        lib_path.mkdir(parents=True, exist_ok=True)

        # Mock large library size
        with patch("subprocess.run", side_effect=_fake_run_library_exists_icloud_on_download()):
            with patch.object(Path, "home", return_value=tmp_path):
                with patch.object(mod, "_get_dir_size", return_value=150 * 1024**3):  # 150 GB
                    result = mod.check(_make_profile())

    # Should have a warning about large library without optimization
    assert any(
        f.data.get("check") == "large_library_no_optimization" and f.severity == Severity.WARNING
        for f in result.findings
    )


def test_photos_large_library_with_optimization():
    """Test no warning when library is >100GB but Optimize Storage is on"""
    mod = _get_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        lib_path = tmp_path / "Pictures" / "Photos Library.photoslibrary"
        lib_path.mkdir(parents=True, exist_ok=True)

        with patch("subprocess.run", side_effect=_fake_run_library_exists_icloud_on_optimize()):
            with patch.object(Path, "home", return_value=tmp_path):
                with patch.object(mod, "_get_dir_size", return_value=150 * 1024**3):  # 150 GB
                    result = mod.check(_make_profile())

    # Should NOT have a warning about large library
    assert not any(
        f.data.get("check") == "large_library_no_optimization" for f in result.findings
    )


def test_photos_library_check_fix_is_informational():
    """Test that fix() is informational and always succeeds"""
    mod = _get_module()
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp_path = Path(tmpdir)
        lib_path = tmp_path / "Pictures" / "Photos Library.photoslibrary"
        lib_path.mkdir(parents=True, exist_ok=True)
        (lib_path / "test.db").write_text("test")

        with patch("subprocess.run", side_effect=_fake_run_library_exists_icloud_on_download()):
            with patch.object(Path, "home", return_value=tmp_path):
                check = mod.check(_make_profile())
                fix = mod.fix(check, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    assert len(fix.actions) > 0
