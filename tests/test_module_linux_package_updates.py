"""Tests for linux_package_updates.

The security/ordinary split is what makes this check actionable, and the
end-of-life prompt is what stops "0 updates" from reading as good news on an
unsupported release.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules

APT_UPGRADABLE = """Listing... Done
libssl3/noble-security 3.0.13-0ubuntu3.4 amd64 [upgradable from: 3.0.13-0ubuntu3.3]
vim/noble-updates 2:9.1.0016-1ubuntu7.1 amd64 [upgradable from: 2:9.1.0016-1ubuntu7]
"""


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_package_updates")


def _profile(platform=Platform.LINUX) -> SystemProfile:
    return SystemProfile(
        platform=platform,
        os_name="Ubuntu 24.04",
        os_version="6.8.0",
        architecture="x86_64",
        cpu_model="Test",
        cpu_cores=4,
        ram_bytes=8 * 1024**3,
    )


def _result(args, stdout="", returncode=0, error=None) -> CommandResult:
    return CommandResult(
        args=list(args), returncode=returncode, stdout=stdout, stderr="",
        timed_out=False, error=error, duration_s=0.01, truncated=False,
    )


def _patched(mod, responses):
    def fake(args, **kwargs):
        key = args[0]
        if key not in responses:
            return _result(args, error="No such file or directory")
        return responses[key](args)

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def _configure(mod, tmp_path, os_release="ID=ubuntu\nVERSION_ID=\"24.04\"\nPRETTY_NAME=\"Ubuntu 24.04 LTS\"\n"):
    path = tmp_path / "os-release"
    path.write_text(os_release)
    mod.os_release_path = str(path)
    mod.reboot_required_path = str(tmp_path / "reboot-required")
    return mod


def _codes(result):
    return [f.code for f in result.findings]


def test_non_linux_is_unsupported():
    assert _get_module().check(_profile(Platform.WIN32)).supported is False


def test_no_package_manager_is_unsupported_not_healthy(tmp_path):
    """Nothing to ask is 'cannot answer', not 'you are up to date'."""
    mod = _configure(_get_module(), tmp_path)
    with _patched(mod, {}):
        result = mod.check(_profile())
    assert result.supported is False
    assert not result.has_issues


def test_apt_security_updates_are_critical_and_separated(tmp_path):
    mod = _configure(_get_module(), tmp_path)
    with _patched(mod, {"apt": lambda args: _result(args, APT_UPGRADABLE)}):
        result = mod.check(_profile())
    security = next(f for f in result.findings if f.code.endswith("security_updates_pending"))
    assert security.severity is Severity.CRITICAL
    assert security.data["packages"] == ["libssl3"]

    # Compared exactly: "security_updates_pending" also ends with
    # "updates_pending", so a suffix match here would test nothing.
    ordinary = next(
        f for f in result.findings
        if f.code == "integrity.linux_package_updates.updates_pending"
    )
    assert ordinary.data["packages"] == ["vim"]
    assert ordinary.severity is Severity.INFO


def test_reboot_required_marker_is_reported(tmp_path):
    mod = _configure(_get_module(), tmp_path)
    Path(mod.reboot_required_path).write_text("")
    with _patched(mod, {"apt": lambda args: _result(args, "Listing... Done\n")}):
        result = mod.check(_profile())
    assert "integrity.linux_package_updates.reboot_required" in _codes(result)


def test_end_of_life_prompt_appears_even_with_no_pending_updates(tmp_path):
    mod = _configure(_get_module(), tmp_path)
    with _patched(mod, {"apt": lambda args: _result(args, "Listing... Done\n")}):
        result = mod.check(_profile())
    eol = next(f for f in result.findings if f.code.endswith("release_end_of_life"))
    assert "ubuntu.com" in eol.data["support_url"]


def test_rolling_releases_get_no_end_of_life_prompt(tmp_path):
    """Arch has no release cycle to check; asking would be noise."""
    mod = _configure(_get_module(), tmp_path, os_release="ID=arch\nPRETTY_NAME=\"Arch Linux\"\n")
    with _patched(mod, {"pacman": lambda args: _result(args, "")}):
        result = mod.check(_profile())
    assert "integrity.linux_package_updates.release_end_of_life" not in _codes(result)


def test_dnf_exit_code_100_means_updates_available_not_failure(tmp_path):
    mod = _configure(_get_module(), tmp_path, os_release="ID=fedora\nPRETTY_NAME=\"Fedora 40\"\n")
    listing = "kernel.x86_64    6.9.4-200.fc40    updates\n"
    with _patched(mod, {"dnf": lambda args: _result(args, listing, returncode=100)}):
        result = mod.check(_profile())
    pending = [f for f in result.findings if "updates_pending" in (f.code or "")]
    assert pending and pending[0].data["packages"] == ["kernel.x86_64"]


def test_pacman_reports_updates_without_inventing_a_security_channel(tmp_path):
    mod = _configure(_get_module(), tmp_path, os_release="ID=arch\n")
    with _patched(mod, {"pacman": lambda args: _result(args, "linux 6.9.1-arch1 -> 6.9.2-arch1\n")}):
        result = mod.check(_profile())
    assert "integrity.linux_package_updates.security_updates_pending" not in _codes(result)
    assert "integrity.linux_package_updates.updates_pending" in _codes(result)


def test_fix_names_the_right_command_for_the_detected_manager(tmp_path):
    mod = _configure(_get_module(), tmp_path)
    with _patched(mod, {"apt": lambda args: _result(args, APT_UPGRADABLE)}):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.executed_mutations == []
    assert any("apt upgrade" in a.description for a in fix.actions)
