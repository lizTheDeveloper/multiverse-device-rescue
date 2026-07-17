import sys
import json
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
    return next(m for m in modules if m.name == "homebrew_health")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_not_installed():
    """Homebrew is not installed"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which brew" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_healthy():
    """Homebrew is healthy with no issues"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which brew" in cmd_str:
            return _make_subprocess_result("/usr/local/bin/brew\n")
        elif "brew doctor" in cmd_str:
            return _make_subprocess_result("Your system is ready to brew.\n")
        elif "brew outdated --json=v1" in cmd_str:
            return _make_subprocess_result('{"formulae": [], "casks": []}')
        elif "brew list --json=v1" in cmd_str:
            return _make_subprocess_result(
                '{"formulae": ["git", "python", "node"], "casks": ["chrome"]}'
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_brew_doctor_issues():
    """Brew doctor reports warnings"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which brew" in cmd_str:
            return _make_subprocess_result("/usr/local/bin/brew\n")
        elif "brew doctor" in cmd_str:
            return _make_subprocess_result(
                "Warning: Some installed formulae depend on unmet dependencies.\n"
                "Please run `brew missing` for details.\n"
                "Your system is ready to brew.\n"
            )
        elif "brew outdated --json=v1" in cmd_str:
            return _make_subprocess_result('{"formulae": [], "casks": []}')
        elif "brew list --json=v1" in cmd_str:
            return _make_subprocess_result(
                '{"formulae": ["git", "python"], "casks": []}'
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_many_outdated():
    """Many packages are outdated (>20)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which brew" in cmd_str:
            return _make_subprocess_result("/usr/local/bin/brew\n")
        elif "brew doctor" in cmd_str:
            return _make_subprocess_result("Your system is ready to brew.\n")
        elif "brew outdated --json=v1" in cmd_str:
            # Create 25 outdated packages
            outdated = [
                {"name": f"package{i}", "installed_versions": ["1.0"], "current_version": "2.0"}
                for i in range(25)
            ]
            return _make_subprocess_result(
                json.dumps({"formulae": outdated, "casks": []})
            )
        elif "brew list --json=v1" in cmd_str:
            packages = [f"package{i}" for i in range(30)]
            return _make_subprocess_result(
                json.dumps({"formulae": packages, "casks": []})
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_large_cache(monkeypatch=None):
    """Cache is large (>2GB)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which brew" in cmd_str:
            return _make_subprocess_result("/usr/local/bin/brew\n")
        elif "brew doctor" in cmd_str:
            return _make_subprocess_result("Your system is ready to brew.\n")
        elif "brew outdated --json=v1" in cmd_str:
            return _make_subprocess_result('{"formulae": [], "casks": []}')
        elif "brew list --json=v1" in cmd_str:
            return _make_subprocess_result(
                '{"formulae": ["git", "python"], "casks": []}'
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_multiple_issues():
    """Multiple issues: doctor warnings, outdated packages, large cache"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "which brew" in cmd_str:
            return _make_subprocess_result("/usr/local/bin/brew\n")
        elif "brew doctor" in cmd_str:
            return _make_subprocess_result(
                "Warning: Some installed formulae depend on unmet dependencies.\n"
                "Your system is ready to brew.\n"
            )
        elif "brew outdated --json=v1" in cmd_str:
            # Create 30 outdated packages
            outdated = [
                {"name": f"pkg{i}", "installed_versions": ["1.0"], "current_version": "2.0"}
                for i in range(30)
            ]
            return _make_subprocess_result(
                json.dumps({"formulae": outdated, "casks": []})
            )
        elif "brew list --json=v1" in cmd_str:
            packages = [f"pkg{i}" for i in range(40)]
            return _make_subprocess_result(
                json.dumps({"formulae": packages, "casks": []})
            )
        return _make_subprocess_result()
    return fake_run


def test_homebrew_health_discovered():
    mod = _get_module()
    assert mod.name == "homebrew_health"
    assert mod.category == "integrity"
    assert mod.risk_level == RiskLevel.SAFE


def test_homebrew_not_installed():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_not_installed()):
        result = mod.check(_make_profile())
    # No findings if Homebrew is not installed
    assert not result.has_issues


def test_homebrew_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    # Should have only INFO finding with summary
    assert result.has_issues
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) == 1
    assert info_findings[0].data.get("check") == "homebrew_summary"


def test_homebrew_doctor_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_brew_doctor_issues()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "brew_doctor_issues" for f in result.findings)
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) >= 1


def test_homebrew_many_outdated():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_many_outdated()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "outdated_packages" for f in result.findings)
    outdated_finding = next(f for f in result.findings if f.data.get("check") == "outdated_packages")
    assert outdated_finding.data.get("count") == 25
    assert outdated_finding.severity == Severity.WARNING


def test_homebrew_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_brew_doctor_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have actions for each finding
    assert len(fix.actions) > 0
    for action in fix.actions:
        assert action.success is True


def test_homebrew_fix_multiple_issues():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_multiple_issues()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # All actions should succeed with informational guidance
    assert fix.all_succeeded
    # Should have actions for doctor issues and outdated packages
    assert len(fix.actions) >= 2
    assert any("doctor" in a.title.lower() or "Doctor" in a.title for a in fix.actions)
    assert any("outdated" in a.title.lower() for a in fix.actions)


def test_homebrew_summary_includes_stats():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    summary_finding = next(f for f in result.findings if f.data.get("check") == "homebrew_summary")
    assert summary_finding.data.get("installed_count") == 4  # 3 formulae + 1 cask
    assert summary_finding.data.get("outdated_count") == 0
    assert summary_finding.data.get("doctor_issues_count") == 0
