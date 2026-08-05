import plistlib
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    ActionKind,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.registry import discover_modules

MODULE_NAME = "twofa_audit"


def _module_object(mod):
    """The module object the registry actually loaded this class from.

    discover_modules imports these under a synthetic "rescue_modules.<name>",
    which is not importable by that name, so patch the object rather than a
    dotted string.
    """
    return sys.modules[type(mod).__module__]


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
        os_name="macOS" if platform == Platform.DARWIN else "Windows 11",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    return next(m for m in discover_modules(modules_dir) if m.name == MODULE_NAME)


@pytest.fixture
def mod(tmp_path):
    m = _get_module()
    apps = tmp_path / "Applications"
    apps.mkdir()
    m.app_dirs = [str(apps)]
    # Default: no signed-in Apple ID, so platform state is unknown.
    m.mobileme_plist_path = tmp_path / "absent.plist"
    m._apps_dir = apps
    m._tmp = tmp_path
    return m


def _install_app(mod, bundle_name):
    (mod._apps_dir / f"{bundle_name}.app").mkdir()


def _write_apple_id(mod, accounts):
    path = mod._tmp / "MobileMeAccounts.plist"
    with open(path, "wb") as f:
        plistlib.dump({"Accounts": accounts}, f)
    mod.mobileme_plist_path = path
    return path


def _finding(result, check):
    return next((f for f in result.findings if f.data.get("check") == check), None)


def test_discovered_with_expected_metadata():
    m = _get_module()
    assert m.name == MODULE_NAME
    assert m.category == "security"
    assert m.risk_level == RiskLevel.SAFE
    assert getattr(m, "auto_apply", False) is False
    for code in (
        "security.twofa_audit.no_second_factor_capability",
        "security.twofa_audit.platform_2fa_unknown",
        "security.twofa_audit.inventory",
    ):
        assert code in m.emits_codes


def test_warns_when_no_authenticator_and_no_platform_signal(mod):
    result = mod.check(_make_profile())
    warning = _finding(result, "no_second_factor_capability")
    assert warning is not None
    assert warning.severity == Severity.WARNING


def test_no_warning_when_authenticator_installed(mod):
    _install_app(mod, "Authy")
    result = mod.check(_make_profile())
    assert _finding(result, "no_second_factor_capability") is None
    inventory = _finding(result, "inventory")
    assert inventory.data["authenticators"] == ["Authy"]


def test_detects_multiple_authenticators(mod):
    _install_app(mod, "Microsoft Authenticator")
    _install_app(mod, "KeePassXC")
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    assert set(inventory.data["authenticators"]) == {
        "Microsoft Authenticator",
        "KeePassXC",
    }


def test_unrelated_apps_are_not_counted(mod):
    _install_app(mod, "Calculator")
    _install_app(mod, "Safari")
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    assert inventory.data["authenticators"] == []


def test_apple_id_with_two_factor_flag_is_reported_true(mod):
    _write_apple_id(mod, [{"AccountID": "user@icloud.com", "SecureAccount": True}])
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    assert inventory.data["platform_2fa"] is True
    # A positive platform signal clears the "no capability" warning.
    assert _finding(result, "no_second_factor_capability") is None


def test_absent_apple_id_is_unknown_not_disabled(mod):
    """The critical honesty property: never claim 2FA is off without evidence."""
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    assert inventory.data["platform_2fa"] is None
    assert _finding(result, "platform_2fa_unknown") is not None


def test_apple_id_without_flag_is_unknown_not_disabled(mod):
    _write_apple_id(mod, [{"AccountID": "user@icloud.com"}])
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    # Apple does not reliably expose this offline, so absence of the flag must
    # not be reported as "two-factor is disabled".
    assert inventory.data["platform_2fa"] is None
    assert inventory.data["platform_2fa"] is not False


def test_unreadable_apple_id_plist_is_unknown(mod):
    bad = mod._tmp / "corrupt.plist"
    bad.write_bytes(b"this is not a plist")
    mod.mobileme_plist_path = bad
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    assert inventory.data["platform_2fa"] is None


def test_inventory_always_states_accounts_were_not_checked(mod):
    result = mod.check(_make_profile())
    inventory = _finding(result, "inventory")
    assert inventory.data["account_status_checked"] is False
    assert "NOT CHECKED" in inventory.description


def test_windows_hello_policy_detected(mod):
    class Ok:
        ok = True
        stdout = "HKEY_LOCAL_MACHINE\\SOFTWARE\\Policies\\Microsoft\\PassportForWork\n"

    with patch.object(_module_object(mod), "run", return_value=Ok()):
        result = mod.check(_make_profile(Platform.WIN32))

    inventory = _finding(result, "inventory")
    assert inventory.data["platform_2fa"] is True


def test_windows_query_failure_is_unknown_not_disabled(mod):
    class Failed:
        ok = False
        stdout = ""

    with patch.object(_module_object(mod), "run", return_value=Failed()):
        result = mod.check(_make_profile(Platform.WIN32))

    inventory = _finding(result, "inventory")
    assert inventory.data["platform_2fa"] is None


def test_unsupported_platform_says_so(mod):
    result = mod.check(_make_profile(Platform.LINUX))
    assert result.supported is False
    assert result.unsupported_reason
    assert result.findings == []


def test_fix_is_guidance_only_and_orders_email_first(mod):
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False

    setup = next(a for a in fix.actions if "two-factor" in a.title.lower())
    body = setup.description.lower()
    # Email must come before banking: everything else resets through it.
    assert body.index("email") < body.index("banking")
    assert "sim swap" in body


def test_fix_never_solicits_a_code(mod):
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    combined = " ".join(a.description for a in fix.actions).lower()
    assert "never type a one-time code or a recovery code into this tool" in combined
