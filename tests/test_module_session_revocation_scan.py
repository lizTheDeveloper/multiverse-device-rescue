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

MODULE_NAME = "session_revocation_scan"


def _module_object(mod):
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


class _NoOutput:
    ok = False
    stdout = ""


@pytest.fixture
def mod(tmp_path):
    m = _get_module()
    m.browser_profile_roots = {}
    m.authorized_keys_path = tmp_path / "absent_authorized_keys"
    m._tmp = tmp_path
    return m


def _add_chromium(mod, browser, profile_names):
    root = mod._tmp / browser.replace(" ", "_")
    root.mkdir(parents=True, exist_ok=True)
    for name in profile_names:
        (root / name).mkdir()
    mod.browser_profile_roots = {**mod.browser_profile_roots, browser: str(root)}
    return root


def _write_authorized_keys(mod, lines):
    path = mod._tmp / "authorized_keys"
    path.write_text("\n".join(lines) + "\n")
    mod.authorized_keys_path = path
    return path


def _finding(result, check):
    return next((f for f in result.findings if f.data.get("check") == check), None)


def _check(mod, platform=Platform.DARWIN):
    """Run check() with system-account lookup stubbed to "nothing found"."""
    with patch.object(_module_object(mod), "run", return_value=_NoOutput()):
        return mod.check(_make_profile(platform))


def test_discovered_with_expected_metadata():
    m = _get_module()
    assert m.name == MODULE_NAME
    assert m.category == "security"
    assert m.risk_level == RiskLevel.SAFE
    assert getattr(m, "auto_apply", False) is False
    for code in (
        "security.session_revocation_scan.browser_sessions",
        "security.session_revocation_scan.system_accounts",
        "security.session_revocation_scan.ssh_authorized_keys",
        "security.session_revocation_scan.inventory",
    ):
        assert code in m.emits_codes


def test_clean_machine_reports_inventory_only(mod):
    result = _check(mod)
    assert _finding(result, "browser_sessions") is None
    assert _finding(result, "ssh_authorized_keys") is None
    inventory = _finding(result, "inventory")
    assert inventory is not None
    assert inventory.severity == Severity.INFO
    assert inventory.data["browser_profile_count"] == 0
    assert inventory.data["ssh_key_count"] == 0


def test_counts_each_chromium_profile_separately(mod):
    _add_chromium(mod, "Google Chrome", ["Default", "Profile 1", "Profile 2"])
    result = _check(mod)
    finding = _finding(result, "browser_sessions")
    assert finding is not None
    assert finding.severity == Severity.WARNING
    assert finding.data["profile_count"] == 3


def test_counts_profiles_across_multiple_browsers(mod):
    _add_chromium(mod, "Google Chrome", ["Default", "Profile 1"])
    _add_chromium(mod, "Brave", ["Default"])
    result = _check(mod)
    finding = _finding(result, "browser_sessions")
    assert finding.data["profile_count"] == 3
    assert {b["browser"] for b in finding.data["browsers"]} == {
        "Google Chrome",
        "Brave",
    }


def test_absent_browser_root_is_ignored(mod):
    mod.browser_profile_roots = {"Google Chrome": str(mod._tmp / "nope")}
    result = _check(mod)
    assert _finding(result, "browser_sessions") is None


def test_counts_authorized_ssh_keys_without_reading_key_material(mod):
    _write_authorized_keys(
        mod,
        [
            "# a comment line",
            "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAISECRETKEYMATERIAL laptop@home",
            "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABgQOTHERSECRET desktop@work",
            "",
        ],
    )
    result = _check(mod)
    finding = _finding(result, "ssh_authorized_keys")
    assert finding is not None
    assert finding.data["key_count"] == 2

    # The key material must never appear in any finding text or data.
    blob = " ".join(f.title + f.description + str(f.data) for f in result.findings)
    assert "SECRETKEYMATERIAL" not in blob
    assert "OTHERSECRET" not in blob


def test_comments_and_blank_lines_are_not_counted_as_keys(mod):
    _write_authorized_keys(mod, ["# only a comment", "", "   "])
    result = _check(mod)
    assert _finding(result, "ssh_authorized_keys") is None


def test_authorized_keys_reading_is_bounded(mod):
    # Far more lines than the cap; the count must stop at the bound rather than
    # walking an arbitrarily large file.
    _write_authorized_keys(mod, [f"ssh-ed25519 KEY{i} host{i}" for i in range(2000)])
    result = _check(mod)
    finding = _finding(result, "ssh_authorized_keys")
    assert finding.data["key_count"] == 500


def test_unreadable_authorized_keys_is_tolerated(mod):
    mod.authorized_keys_path = mod._tmp  # a directory, not a file
    result = _check(mod)
    assert _finding(result, "ssh_authorized_keys") is None


def test_macos_system_accounts_are_listed_by_id(mod):
    class Accounts:
        ok = True
        stdout = (
            "(\n    {\n        AccountID = \"user@icloud.com\";\n"
            "        LoggedIn = 1;\n    },\n"
            "    {\n        AccountID = \"other@icloud.com\";\n    }\n)\n"
        )

    with patch.object(_module_object(mod), "run", return_value=Accounts()):
        result = mod.check(_make_profile())

    finding = _finding(result, "system_accounts")
    assert finding is not None
    assert set(finding.data["accounts"]) == {"user@icloud.com", "other@icloud.com"}


def test_windows_credential_targets_are_listed(mod):
    class CmdKey:
        ok = True
        stdout = (
            "Currently stored credentials:\n"
            "    Target: LegacyGeneric:target=git:https://github.com\n"
            "    Type: Generic\n"
            "    Target: MicrosoftAccount:user=someone@example.com\n"
        )

    with patch.object(_module_object(mod), "run", return_value=CmdKey()):
        result = mod.check(_make_profile(Platform.WIN32))

    finding = _finding(result, "system_accounts")
    assert finding is not None
    assert len(finding.data["accounts"]) == 2


def test_failed_account_lookup_is_tolerated(mod):
    result = _check(mod)
    assert _finding(result, "system_accounts") is None


def test_inventory_states_provider_sessions_were_not_checked(mod):
    result = _check(mod)
    inventory = _finding(result, "inventory")
    assert inventory.data["provider_sessions_checked"] is False
    assert "provider" in inventory.description.lower()


def test_unsupported_platform_says_so(mod):
    result = _check(mod, Platform.LINUX)
    assert result.supported is False
    assert result.unsupported_reason
    assert result.findings == []


def test_fix_is_guidance_only(mod):
    _add_chromium(mod, "Google Chrome", ["Default"])
    _write_authorized_keys(mod, ["ssh-ed25519 KEY laptop@home"])
    check = _check(mod)
    fix = mod.fix(check, Mode.AUTO)

    assert fix.actions
    for action in fix.actions:
        assert action.kind == ActionKind.GUIDANCE
        assert action.executed is False


def test_fix_puts_password_change_before_sign_out(mod):
    """The ordering is the whole point: revoking first lets them back in."""
    check = _check(mod)
    fix = mod.fix(check, Mode.AUTO)
    order = next(a for a in fix.actions if a.data.get("check") == "revocation_order")
    body = order.description.lower()
    assert body.index("change the password") < body.index("sign out of all other")
    assert "oauth" in body


def test_fix_always_includes_the_ordering_guidance(mod):
    """Even on a clean machine, the ordering advice is the useful part."""
    check = _check(mod)
    fix = mod.fix(check, Mode.AUTO)
    assert any(a.data.get("check") == "revocation_order" for a in fix.actions)
