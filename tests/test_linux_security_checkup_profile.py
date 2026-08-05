"""The Linux checkup profile has to select real, Linux-capable, read-only modules.

A profile is the one-command entry point most people will actually use, so the
ways it can be wrong are the ways the tool looks broken: naming a module that
does not exist (it silently runs fewer checks), naming a macOS-only module (it
reports "not supported here" rows for no reason), or including something that
changes the system in a profile documented as read-only.
"""

from pathlib import Path

from rescue.models import Platform, RiskLevel
from rescue.profiles import discover_profiles, filter_modules_by_profile
from rescue.registry import discover_modules

PROJECT_ROOT = Path(__file__).parent.parent

PROFILE = discover_profiles(PROJECT_ROOT / "profiles")["linux_security_checkup"]
MODULES = discover_modules(PROJECT_ROOT / "modules")
SELECTED = filter_modules_by_profile(MODULES, PROFILE)


def test_every_named_module_exists():
    available = {m.name for m in MODULES}
    missing = sorted(set(PROFILE.include_modules) - available)
    assert not missing, f"profile names modules that do not exist: {missing}"


def test_the_profile_actually_selects_modules():
    assert len(SELECTED) == len(PROFILE.include_modules)


def test_every_selected_module_supports_linux():
    """Otherwise the run is padded with rows that could never produce a result."""
    wrong_platform = sorted(m.name for m in SELECTED if Platform.LINUX not in m.platforms)
    assert not wrong_platform, f"not runnable on Linux: {wrong_platform}"


def test_no_selected_module_can_change_the_system_unattended():
    """The profile is documented as read-only; auto_apply is what would break that."""
    mutating = sorted(m.name for m in SELECTED if getattr(m, "auto_apply", False))
    assert not mutating, f"would run unattended mutations: {mutating}"


def test_selected_modules_are_all_safe_risk():
    risky = sorted(m.name for m in SELECTED if m.risk_level is not RiskLevel.SAFE)
    assert not risky, f"non-SAFE modules in a read-only checkup: {risky}"


def test_exposure_is_checked_before_persistence_and_health():
    """Order is deliberate: what can reach the machine, then what runs on it.

    Someone reading a long result list acts on the first few rows, so the rows
    that describe how a stranger reaches this machine come first.
    """
    order = PROFILE.include_modules
    assert order.index("linux_firewall_check") < order.index("linux_persistence_audit")
    assert order.index("linux_ssh_hardening") < order.index("linux_journal_errors")
