import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

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
    return next(m for m in modules if m.name == "twofa_audit")


def _isolate(monkeypatch, mod, tmp_path, *, apps=None, usb="", ssh_keys=None):
    home = tmp_path / "home"
    home.mkdir(exist_ok=True)
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))

    app_root = tmp_path / "Applications"
    app_root.mkdir(exist_ok=True)
    for name in apps or []:
        (app_root / name).mkdir()
    monkeypatch.setattr(mod, "_application_roots", lambda platform: [app_root])

    ssh_dir = home / ".ssh"
    ssh_dir.mkdir(exist_ok=True)
    for filename, contents in (ssh_keys or {}).items():
        (ssh_dir / filename).write_text(contents)
    monkeypatch.setattr(mod, "_ssh_directory", lambda: ssh_dir)

    monkeypatch.setattr(mod, "_enumerate_usb_devices", lambda platform: usb)
    return home


def _checks(result):
    return [f.data["check"] for f in result.findings]


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "twofa_audit"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms
    assert Platform.WIN32 in mod.platforms


def test_no_factors_found(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)

    result = mod.check(_make_profile())

    assert _checks(result) == ["no_second_factors", "recovery_codes"]
    assert result.findings[0].severity == Severity.WARNING


def test_authenticator_app_detected_from_applications(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, apps=["Raivo OTP.app", "Notes.app"])

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "second_factors_available")
    assert [r["product"] for r in finding.data["authenticator_apps"]] == ["Raivo OTP"]
    assert finding.data["count"] == 1


def test_authenticator_app_detected_from_installed_software(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)

    profile = _make_profile(
        platform=Platform.WIN32,
        installed_software=["Microsoft Authenticator", "Notepad++"],
    )
    result = mod.check(profile)

    finding = next(f for f in result.findings if f.data["check"] == "second_factors_available")
    assert [r["product"] for r in finding.data["authenticator_apps"]] == [
        "Microsoft Authenticator"
    ]


def test_security_key_detected_from_usb_listing(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        usb="USB 3.1 Bus\n  YubiKey OTP+FIDO+CCID:\n    Vendor: Yubico\n",
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "second_factors_available")
    assert [r["product"] for r in finding.data["security_keys"]] == ["YubiKey"]


def test_fido_backed_ssh_key_detected(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(
        monkeypatch,
        mod,
        tmp_path,
        ssh_keys={
            "id_ed25519_sk.pub": "sk-ssh-ed25519@openssh.com AAAAB3 comment\n",
            "id_rsa.pub": "ssh-rsa AAAAB3 comment\n",
            "id_ed25519_sk": "PRIVATE KEY MATERIAL MUST NOT BE READ",
        },
    )

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "second_factors_available")
    keys = finding.data["fido_ssh_keys"]
    assert len(keys) == 1
    assert keys[0]["path"] == "~/.ssh/id_ed25519_sk.pub"


def test_plain_ssh_keys_are_not_counted_as_second_factors(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, ssh_keys={"id_rsa.pub": "ssh-rsa AAAAB3 me\n"})

    result = mod.check(_make_profile())

    assert "no_second_factors" in _checks(result)


def test_elevated_sensitivity_flags_software_only_factors(monkeypatch, tmp_path):
    mod = _get_module()
    mod.configure({"sensitivity": "elevated"})
    _isolate(monkeypatch, mod, tmp_path, apps=["Authy.app"])

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "factors_on_one_device")
    assert finding.severity == Severity.WARNING


def test_elevated_sensitivity_accepts_a_hardware_key(monkeypatch, tmp_path):
    mod = _get_module()
    mod.configure({"sensitivity": "elevated"})
    _isolate(monkeypatch, mod, tmp_path, apps=["Authy.app"], usb="Nitrokey 3\n")

    result = mod.check(_make_profile())

    assert "factors_on_one_device" not in _checks(result)


def test_normal_sensitivity_does_not_flag_software_only_factors(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, apps=["Authy.app"])

    result = mod.check(_make_profile())

    assert "factors_on_one_device" not in _checks(result)


def test_recovery_code_reminder_is_always_present(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, apps=["1Password.app"])

    result = mod.check(_make_profile())

    finding = next(f for f in result.findings if f.data["check"] == "recovery_codes")
    assert finding.severity == Severity.INFO


def test_usb_enumeration_failure_is_not_an_error(monkeypatch, tmp_path):
    mod = _get_module()
    home = tmp_path / "home"
    home.mkdir()
    monkeypatch.setattr(Path, "home", classmethod(lambda cls: home))
    monkeypatch.setattr(mod, "_application_roots", lambda platform: [])
    monkeypatch.setattr(mod, "_ssh_directory", lambda: home / ".ssh")

    with patch("subprocess.run", side_effect=OSError("no such binary")):
        result = mod.check(_make_profile())

    assert result.error is None
    assert "no_second_factors" in _checks(result)


def test_usb_enumeration_uses_a_timeout(monkeypatch, tmp_path):
    mod = _get_module()
    completed = MagicMock(returncode=0, stdout="YubiKey\n", stderr="")

    with patch("subprocess.run", return_value=completed) as run:
        listing = mod._enumerate_usb_devices(Platform.DARWIN)

    assert "YubiKey" in listing
    assert run.call_args.kwargs["timeout"] > 0


def test_usb_enumeration_returns_empty_on_nonzero_exit():
    mod = _get_module()
    completed = MagicMock(returncode=1, stdout="partial", stderr="boom")

    with patch("subprocess.run", return_value=completed):
        assert mod._enumerate_usb_devices(Platform.WIN32) == ""


def test_fix_produces_guidance_only(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path)

    fix = mod.fix(mod.check(_make_profile()), Mode.MANUAL)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False
    titles = " ".join(action.title for action in fix.actions)
    assert "Set up a second factor" in titles
    assert "Store recovery codes" in titles


def test_fix_recommends_the_hardware_key_when_one_is_present(monkeypatch, tmp_path):
    mod = _get_module()
    _isolate(monkeypatch, mod, tmp_path, apps=["Authy.app"], usb="YubiKey 5C\n")

    fix = mod.fix(mod.check(_make_profile()), Mode.MANUAL)

    assert any("YubiKey" in action.title for action in fix.actions)
