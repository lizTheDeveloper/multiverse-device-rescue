import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import (
    ActionKind,
    CheckResult,
    Mode,
    Platform,
    RiskLevel,
    Severity,
    SystemProfile,
)
from rescue.registry import discover_modules


def _make_profile(platform=Platform.DARWIN):
    return SystemProfile(
        platform=platform,
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
    return next(m for m in modules if m.name == "session_revocation_scan")


def _isolate(monkeypatch, mod, tmp_path, *, chromium=None, firefox=None, safari=False):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    chromium_roots = []
    for browser, profiles in (chromium or {}).items():
        user_data = home / browser
        for profile_name, cookie_location in profiles.items():
            profile_dir = user_data / profile_name
            profile_dir.mkdir(parents=True)
            if cookie_location == "network":
                (profile_dir / "Network").mkdir()
                (profile_dir / "Network" / "Cookies").write_bytes(b"fixture")
            elif cookie_location == "legacy":
                (profile_dir / "Cookies").write_bytes(b"fixture")
        chromium_roots.append((browser, user_data))
    monkeypatch.setattr(mod, "_chromium_user_data_roots", lambda platform: chromium_roots)

    firefox_root = home / "firefox-profiles"
    firefox_root.mkdir(exist_ok=True)
    for profile_name in firefox or []:
        profile_dir = firefox_root / profile_name
        profile_dir.mkdir()
        (profile_dir / "cookies.sqlite").write_bytes(b"fixture")
    monkeypatch.setattr(mod, "_firefox_profile_roots", lambda platform: [firefox_root])

    safari_cookies = home / "Safari" / "Cookies.binarycookies"
    if safari:
        safari_cookies.parent.mkdir(parents=True)
        safari_cookies.write_bytes(b"fixture")
    monkeypatch.setattr(mod, "_safari_cookie_paths", lambda platform: [safari_cookies])
    return home


def _write_credential(home, relative, mode=0o600):
    path = home / relative
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("token fixture")
    os.chmod(path, mode)
    return path


def _checks(result):
    return [f.data["check"] for f in result.findings]


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "session_revocation_scan"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.WIN32, Platform.LINUX}


def test_clean_device_reports_only_the_provider_reminder(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)

    result = mod.check(_make_profile())

    assert _checks(result) == ["provider_side_sessions"]


def test_chromium_cookie_stores_are_found_in_both_locations(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        chromium={"Chrome": {"Default": "network", "Profile 1": "legacy"}},
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_sessions")
    assert finding.data["count"] == 2
    assert {s["profile"] for s in finding.data["sessions"]} == {"Default", "Profile 1"}


def test_firefox_and_safari_cookie_stores_are_found(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, firefox=["abc.default-release"], safari=True)

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_sessions")
    assert finding.data["browsers"] == ["Firefox", "Safari"]


def test_browser_sessions_are_informational_at_normal_sensitivity(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, chromium={"Chrome": {"Default": "network"}})

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_sessions")
    assert finding.severity == Severity.INFO


def test_browser_sessions_warn_at_elevated_sensitivity(monkeypatch, tmp_path):
    mod = _get_module()
    mod.configure({"sensitivity": "elevated"})
    _isolate(monkeypatch, mod, tmp_path, chromium={"Chrome": {"Default": "network"}})

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "browser_sessions")
    assert finding.severity == Severity.WARNING


def test_credential_files_are_listed_with_revocation_advice(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path)
    _write_credential(home, ".aws/credentials")
    _write_credential(home, ".npmrc")

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "credential_artifacts")
    assert finding.severity == Severity.WARNING
    assert finding.data["services"] == ["AWS", "npm registry"]
    for record in finding.data["credentials"]:
        assert record["revocation"]
        assert record["path"].startswith("~/")


def test_credential_contents_are_never_included_in_findings(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path)
    path = home / ".git-credentials"
    path.write_text("https://user:SUPERSECRETTOKEN@github.com\n")

    result = mod.check(_make_profile())

    serialised = repr([f.description for f in result.findings]) + repr(
        [f.data for f in result.findings]
    )
    assert "SUPERSECRETTOKEN" not in serialised


def test_group_readable_credentials_are_flagged(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path)
    _write_credential(home, ".pypirc", mode=0o644)

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "credential_permissions")
    assert finding.severity == Severity.WARNING
    assert finding.data["credentials"][0]["mode"] == "644"


def test_private_credentials_are_not_flagged_for_permissions(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path)
    _write_credential(home, ".pypirc", mode=0o600)

    result = mod.check(_make_profile())

    assert "credential_permissions" not in _checks(result)


def test_windows_mode_bits_are_not_treated_as_permissions(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path)
    _write_credential(home, ".npmrc", mode=0o644)

    result = mod.check(_make_profile(platform=Platform.WIN32))

    assert "credential_permissions" not in _checks(result)
    finding = next(f for f in result.findings if f.data["check"] == "credential_artifacts")
    assert finding.data["credentials"][0]["mode"] == "n/a"


def test_provider_reminder_is_always_present(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, chromium={"Chrome": {"Default": "network"}})

    result = mod.check(_make_profile())

    assert "provider_side_sessions" in _checks(result)


def test_configure_ignores_unknown_sensitivity():
    mod = _get_module()
    mod.configure({"sensitivity": "maximum"})
    assert mod._sensitivity == "normal"


def test_fix_produces_guidance_only(monkeypatch, tmp_path):
    mod = _get_module()
    home = _isolate(monkeypatch, mod, tmp_path, chromium={"Chrome": {"Default": "network"}})
    _write_credential(home, ".aws/credentials", mode=0o644)

    fix = mod.fix(mod.check(_make_profile()), Mode.MANUAL)

    assert len(fix.actions) == 4
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False


def test_fix_orders_password_change_before_session_sign_out(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, chromium={"Chrome": {"Default": "network"}})

    fix = mod.fix(mod.check(_make_profile()), Mode.MANUAL)

    sign_out = next(a for a in fix.actions if "Sign out everywhere" in a.title)
    body = sign_out.description
    assert body.index("Change the password first") < body.index("sign out of all devices")


def test_fix_on_empty_check_produces_no_actions():
    mod = _get_module()
    fix = mod.fix(CheckResult(module_name=mod.name), Mode.AUTO)
    assert fix.actions == []


def test_missing_home_directory_does_not_raise(monkeypatch, tmp_path):
    mod = _get_module()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: tmp_path / "absent"))

    result = mod.check(_make_profile())

    assert result.error is None
    assert _checks(result) == ["provider_side_sessions"]
