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

MODULE_NAME = "password_manager_check"


def _module_object(mod):
    """The module object the registry actually loaded this class from.

    discover_modules imports these under a synthetic "rescue_modules.<name>"
    name, so patching the "modules.security.<name>" dotted path would patch a
    second, unrelated module object and silently do nothing -- and that name is
    not importable, so patch() by string fails outright. Patch the object.
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
    """Module pointed at an empty fixture tree, so nothing on the host leaks in."""
    m = _get_module()
    apps = tmp_path / "Applications"
    apps.mkdir()
    m.app_dirs = [str(apps)]
    m.browser_profiles = {}
    m._apps_dir = apps
    m._tmp = tmp_path
    return m


def _install_app(mod, bundle_name):
    (mod._apps_dir / f"{bundle_name}.app").mkdir()


def _add_browser(mod, name):
    path = mod._tmp / "browsers" / name
    path.mkdir(parents=True)
    mod.browser_profiles = {**mod.browser_profiles, name: str(path)}


def test_discovered_with_expected_metadata():
    m = _get_module()
    assert m.name == MODULE_NAME
    assert m.category == "security"
    assert m.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in m.platforms
    assert Platform.WIN32 in m.platforms
    # Read-only: auto mode must never apply anything from this module.
    assert getattr(m, "auto_apply", False) is False
    for code in (
        "security.password_manager_check.no_password_manager",
        "security.password_manager_check.browser_stored_passwords",
        "security.password_manager_check.inventory",
    ):
        assert code in m.emits_codes


def test_warns_when_no_manager_installed(mod):
    result = mod.check(_make_profile())
    warnings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert any(f.data.get("check") == "no_password_manager" for f in warnings)


def test_no_warning_when_manager_installed(mod):
    _install_app(mod, "Bitwarden")
    result = mod.check(_make_profile())
    assert not any(
        f.data.get("check") == "no_password_manager" for f in result.findings
    )
    inventory = next(f for f in result.findings if f.data.get("check") == "inventory")
    assert inventory.data["managers"] == ["Bitwarden"]


def test_detects_each_known_manager_by_bundle_name(mod):
    _install_app(mod, "1Password 8")
    _install_app(mod, "KeePassXC")
    result = mod.check(_make_profile())
    inventory = next(f for f in result.findings if f.data.get("check") == "inventory")
    assert set(inventory.data["managers"]) == {"1Password", "KeePassXC"}


def test_unrelated_apps_are_not_mistaken_for_managers(mod):
    for name in ("Calculator", "Notes", "Passwords Are Fun"):
        _install_app(mod, name)
    result = mod.check(_make_profile())
    inventory = next(f for f in result.findings if f.data.get("check") == "inventory")
    assert inventory.data["managers"] == []


def test_browser_passwords_flagged_only_without_a_manager(mod):
    _add_browser(mod, "Google Chrome")
    result = mod.check(_make_profile())
    assert any(
        f.data.get("check") == "browser_stored_passwords" for f in result.findings
    )

    _install_app(mod, "Bitwarden")
    result = mod.check(_make_profile())
    assert not any(
        f.data.get("check") == "browser_stored_passwords" for f in result.findings
    )


def test_inventory_is_always_reported(mod):
    result = mod.check(_make_profile())
    inventory = [f for f in result.findings if f.data.get("check") == "inventory"]
    assert len(inventory) == 1
    assert inventory[0].severity == Severity.INFO


def test_windows_uses_the_uninstall_registry(mod):
    class FakeResult:
        ok = True
        stdout = (
            "HKEY_LOCAL_MACHINE\\Software\\...\\{guid}\n"
            "    DisplayName    REG_SZ    1Password 8\n"
            "    DisplayName    REG_SZ    Some Unrelated Tool\n"
        )

    with patch.object(_module_object(mod), "run", return_value=FakeResult()):
        result = mod.check(_make_profile(Platform.WIN32))

    inventory = next(f for f in result.findings if f.data.get("check") == "inventory")
    assert inventory.data["managers"] == ["1Password"]


def test_windows_registry_failure_is_tolerated(mod):
    class FailedResult:
        ok = False
        stdout = ""

    with patch.object(_module_object(mod), "run", return_value=FailedResult()):
        result = mod.check(_make_profile(Platform.WIN32))

    # A failed reg query means "found nothing", not a crash.
    inventory = next(f for f in result.findings if f.data.get("check") == "inventory")
    assert inventory.data["managers"] == []


def test_unsupported_platform_says_so_rather_than_reporting_healthy(mod):
    result = mod.check(_make_profile(Platform.LINUX))
    assert result.supported is False
    assert result.unsupported_reason
    assert result.findings == []


def test_missing_application_directory_is_tolerated(mod):
    mod.app_dirs = [str(mod._tmp / "definitely_absent")]
    result = mod.check(_make_profile())
    inventory = next(f for f in result.findings if f.data.get("check") == "inventory")
    assert inventory.data["managers"] == []


def test_fix_is_guidance_only(mod):
    _add_browser(mod, "Google Chrome")
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        # Guidance must never be reported as a completed system change.
        assert action.executed is False
    assert any("password manager" in a.title.lower() for a in fix.actions)
    assert any("browser" in a.title.lower() for a in fix.actions)


def test_fix_never_asks_for_a_master_password(mod):
    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.AUTO)
    combined = " ".join(a.description for a in fix.actions).lower()
    # The guidance must actively warn against entering it, not solicit it.
    assert "never type your master password into this tool" in combined


# -- password managers installed only as a browser extension -----------------

LASTPASS_ID = "hdokiejnpimakedhajhdlcegeplioahd"
STORE = "https://clients2.google.com/service/update2/crx"


def _chrome_extension(root, ext_id, update_url, profile="Default", name="LastPass"):
    import json

    version = root / profile / "Extensions" / ext_id / "4.0.0_0"
    version.mkdir(parents=True)
    manifest = {"name": name}
    if update_url:
        manifest["update_url"] = update_url
    (version / "manifest.json").write_text(json.dumps(manifest))


def test_store_extension_counts_as_a_password_manager(mod):
    chrome = mod._tmp / "Chrome"
    _chrome_extension(chrome, LASTPASS_ID, STORE, profile="Profile 3")
    mod.browser_profiles = {"Google Chrome": str(chrome)}
    result = mod.check(_make_profile())
    codes = [f.code for f in result.findings]
    assert "security.password_manager_check.no_password_manager" not in codes
    inventory = next(f for f in result.findings if f.data["check"] == "inventory")
    assert inventory.data["managers"] == ["LastPass"]


def test_sideloaded_copy_with_a_store_id_does_not_count(mod):
    chrome = mod._tmp / "Chrome"
    _chrome_extension(chrome, LASTPASS_ID, None)
    mod.browser_profiles = {"Google Chrome": str(chrome)}
    result = mod.check(_make_profile())
    codes = [f.code for f in result.findings]
    assert "security.password_manager_check.no_password_manager" in codes


def test_an_extension_merely_named_like_a_manager_does_not_count(mod):
    chrome = mod._tmp / "Chrome"
    _chrome_extension(chrome, "a" * 32, STORE, name="LastPass")
    mod.browser_profiles = {"Google Chrome": str(chrome)}
    result = mod.check(_make_profile())
    codes = [f.code for f in result.findings]
    assert "security.password_manager_check.no_password_manager" in codes


def test_firefox_addon_counts(mod):
    ff = mod._tmp / "Profiles"
    (ff / "abc.default" / "extensions").mkdir(parents=True)
    (ff / "abc.default" / "extensions" / "support@lastpass.com.xpi").write_bytes(b"")
    mod.browser_profiles = {"Firefox": str(ff)}
    result = mod.check(_make_profile())
    inventory = next(f for f in result.findings if f.data["check"] == "inventory")
    assert inventory.data["managers"] == ["LastPass"]
