"""Tests for linux_firewall_check.

The behaviour worth protecting is the distinction between "no firewall" and
"could not read the firewall". Conflating them produces a confident wrong
answer, which is worse than no answer on a security check.
"""

import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.command import CommandResult
from rescue.models import Mode, Platform, Severity, SystemProfile
from rescue.registry import discover_modules


def _get_module():
    modules = discover_modules(Path(__file__).parent.parent / "modules")
    return next(m for m in modules if m.name == "linux_firewall_check")


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
        args=list(args),
        returncode=returncode,
        stdout=stdout,
        stderr="",
        timed_out=False,
        error=error,
        duration_s=0.01,
        truncated=False,
    )


def _patched(mod, responses):
    """Patch the module's own `run`, dispatching on the first argument.

    Rescue modules are loaded by path under a synthetic ``rescue_modules.*``
    name that is not an importable package, so ``patch("rescue_modules.x.run")``
    cannot resolve it. Patching the loaded module object directly does.
    """

    def fake(args, **kwargs):
        tool = args[0]
        if tool not in responses:
            return _result(args, error="No such file or directory")
        return responses[tool](args)

    return patch.object(sys.modules[type(mod).__module__], "run", side_effect=fake)


def test_module_metadata():
    mod = _get_module()
    assert mod.category == "security"
    assert mod.platforms == [Platform.LINUX]


def test_non_linux_is_unsupported_not_healthy():
    mod = _get_module()
    result = mod.check(_profile(Platform.DARWIN))
    assert result.supported is False
    assert result.unsupported_reason
    assert not result.has_issues


def test_no_firewall_installed_is_a_warning():
    mod = _get_module()
    with _patched(mod, {}):
        result = mod.check(_profile())
    codes = [f.code for f in result.findings]
    assert "security.linux_firewall_check.no_firewall" in codes


def test_active_ufw_produces_no_findings():
    mod = _get_module()
    responses = {
        "ufw": lambda args: _result(args, "Status: active\nDefault: deny (incoming)"),
    }
    with _patched(mod, responses):
        result = mod.check(_profile())
    assert not result.has_issues


def test_inactive_ufw_is_reported():
    mod = _get_module()
    responses = {"ufw": lambda args: _result(args, "Status: inactive")}
    with _patched(mod, responses):
        result = mod.check(_profile())
    assert any(f.code == "security.linux_firewall_check.firewall_inactive" for f in result.findings)


def test_active_but_default_allow_is_reported():
    mod = _get_module()
    responses = {
        "ufw": lambda args: _result(args, "Status: active\nDefault: allow (incoming)"),
    }
    with _patched(mod, responses):
        result = mod.check(_profile())
    assert any(
        f.code == "security.linux_firewall_check.default_allow_inbound" for f in result.findings
    )


def test_unreadable_ruleset_is_undetermined_not_absent():
    """The core promise: unreadable never renders as 'you have no firewall'."""
    mod = _get_module()
    responses = {
        "ufw": lambda args: _result(args, "", returncode=1),
        "nft": lambda args: _result(args, "", returncode=1),
    }
    with _patched(mod, responses):
        result = mod.check(_profile())
    codes = [f.code for f in result.findings]
    assert "security.linux_firewall_check.undetermined" in codes
    assert "security.linux_firewall_check.no_firewall" not in codes
    assert "security.linux_firewall_check.firewall_inactive" not in codes
    undetermined = next(f for f in result.findings if f.code.endswith("undetermined"))
    assert undetermined.severity is Severity.INFO


def test_iptables_with_accept_policy_and_no_rules_is_not_filtering():
    mod = _get_module()
    responses = {"iptables": lambda args: _result(args, "-P INPUT ACCEPT\n")}
    with _patched(mod, responses):
        result = mod.check(_profile())
    assert any(
        f.code == "security.linux_firewall_check.firewall_inactive" for f in result.findings
    )


def test_iptables_with_rules_counts_as_active():
    mod = _get_module()
    responses = {
        "iptables": lambda args: _result(
            args, "-P INPUT DROP\n-A INPUT -p tcp --dport 22 -j ACCEPT\n"
        )
    }
    with _patched(mod, responses):
        result = mod.check(_profile())
    assert not result.has_issues


def test_fix_only_ever_offers_guidance():
    mod = _get_module()
    with _patched(mod, {}):
        check = mod.check(_profile())
    fix = mod.fix(check, Mode.CLI)
    assert fix.actions
    assert fix.executed_mutations == []
    assert len(fix.guidance_actions) == len(fix.actions)
