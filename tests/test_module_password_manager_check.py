import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import ActionKind, Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN, installed_software=None):
    return SystemProfile(
        platform=platform,
        os_name="macOS",
        os_version="15.2",
        architecture="arm64",
        cpu_model="Apple M2",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
        installed_software=installed_software or [],
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "password_manager_check")


def _isolate(monkeypatch, mod, tmp_path, *, apps=None, chromium=None, firefox=None):
    """Point every filesystem lookup at a fixture tree under tmp_path."""
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    app_root = tmp_path / "Applications"
    app_root.mkdir(exist_ok=True)
    for name in apps or []:
        (app_root / name).mkdir()
    monkeypatch.setattr(mod, "_application_roots", lambda platform: [app_root])

    chromium_roots = []
    for browser, profiles in (chromium or {}).items():
        user_data = tmp_path / browser
        for profile_name, contents in profiles.items():
            profile_dir = user_data / profile_name
            profile_dir.mkdir(parents=True)
            for extension_id in contents.get("extensions", []):
                (profile_dir / "Extensions" / extension_id).mkdir(parents=True)
            if contents.get("login_data"):
                (profile_dir / "Login Data").write_bytes(b"sqlite fixture")
        chromium_roots.append((browser, user_data))
    monkeypatch.setattr(mod, "_chromium_user_data_roots", lambda platform: chromium_roots)

    firefox_root = tmp_path / "firefox-profiles"
    firefox_root.mkdir(exist_ok=True)
    for profile_name in firefox or []:
        profile_dir = firefox_root / profile_name
        profile_dir.mkdir()
        (profile_dir / "logins.json").write_text("{}")
    monkeypatch.setattr(
        mod, "_firefox_profile_roots", lambda platform: [("Firefox", firefox_root)]
    )
    return home


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "password_manager_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms
    assert Platform.WIN32 in mod.platforms


def test_no_manager_and_no_browser_store(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)

    result = mod.check(_make_profile())

    checks = [f.data["check"] for f in result.findings]
    assert checks == ["no_password_manager"]
    assert result.findings[0].severity == Severity.WARNING


def test_manager_detected_from_application_bundle(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, apps=["1Password.app", "Safari.app"])

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "password_manager_detected")
    assert finding.severity == Severity.INFO
    assert [record["product"] for record in finding.data["managers"]] == ["1Password"]


def test_manager_detected_from_installed_software_inventory(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)

    profile = _make_profile(
        platform=Platform.WIN32, installed_software=["Bitwarden 2024.10.1", "7-Zip"]
    )
    result = mod.check(profile)

    finding = next(f for f in result.findings if f.data["check"] == "password_manager_detected")
    assert [record["product"] for record in finding.data["managers"]] == ["Bitwarden"]
    assert finding.data["managers"][0]["source"] == "installed software inventory"


def test_manager_detected_from_browser_extension(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        chromium={
            "Chrome": {
                "Default": {"extensions": ["nngceckbapebfimnlniiiahkandclblb"]},
            }
        },
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "password_manager_detected")
    assert finding.data["managers"][0]["product"] == "Bitwarden"
    assert finding.data["managers"][0]["source"] == "Chrome extension"


def test_browser_login_data_reported_without_being_opened(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        chromium={"Chrome": {"Default": {"login_data": True}}},
        firefox=["abc.default-release"],
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_password_store")
    assert finding.data["browsers"] == ["Chrome", "Firefox"]
    for store in finding.data["stores"]:
        assert store["path"].startswith(("~/", "/"))
        assert "size_bytes" in store and "modified" in store


def test_chromium_non_profile_directories_are_ignored(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path)
    user_data = tmp_path / "Chrome"
    for name in ("Default", "Profile 2", "Crashpad", "ShaderCache"):
        (user_data / name).mkdir(parents=True)
        (user_data / name / "Login Data").write_bytes(b"x")
    mod._chromium_user_data_roots = lambda platform: [("Chrome", user_data)]

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_password_store")
    assert len(finding.data["stores"]) == 2
    assert home.exists()


def test_browser_store_is_informational_when_a_manager_exists(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        apps=["KeePassXC.app"],
        chromium={"Chrome": {"Default": {"login_data": True}}},
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_password_store")
    assert finding.severity == Severity.INFO


def test_elevated_sensitivity_warns_even_with_a_manager(monkeypatch, tmp_path):
    mod = _get_module()
    mod.configure({"sensitivity": "elevated"})
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        apps=["KeePassXC.app"],
        chromium={"Chrome": {"Default": {"login_data": True}}},
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_password_store")
    assert finding.severity == Severity.WARNING
    assert finding.data["sensitivity"] == "elevated"


def test_configure_ignores_unknown_sensitivity():
    mod = _get_module()
    mod.configure({"sensitivity": "paranoid"})
    assert mod._sensitivity == "normal"


def test_display_path_hides_the_account_name(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        chromium={"Chrome": {"Default": {"login_data": True}}},
    )
    monkeypatch.setattr(mod, "_chromium_user_data_roots", lambda platform: [
        ("Chrome", Path.home() / "Chrome")
    ])
    (Path.home() / "Chrome" / "Default").mkdir(parents=True)
    (Path.home() / "Chrome" / "Default" / "Login Data").write_bytes(b"x")

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_password_store")
    assert finding.data["stores"][0]["path"] == "~/Chrome/Default/Login Data"


def test_fix_produces_guidance_only(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        chromium={"Chrome": {"Default": {"login_data": True}}},
    )

    check = mod.check(_make_profile())
    fix = mod.fix(check, Mode.MANUAL)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False
    titles = " ".join(action.title for action in fix.actions)
    assert "Set up a password manager" in titles
    assert "Move saved passwords out of" in titles


def test_fix_on_empty_check_produces_no_actions():
    mod = _get_module()
    from rescue.models import CheckResult

    fix = mod.fix(CheckResult(module_name=mod.name), Mode.AUTO)
    assert fix.actions == []


def test_unreadable_directories_do_not_raise(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)
    monkeypatch.setattr(mod, "_application_roots", lambda platform: [tmp_path / "nope"])

    result = mod.check(_make_profile())

    assert result.error is None
    assert result.findings
