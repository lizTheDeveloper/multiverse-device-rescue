import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules


def _make_profile(platform=Platform.LINUX):
    return SystemProfile(
        platform=platform,
        os_name="Ubuntu",
        os_version="24.04",
        architecture="x86_64",
        cpu_model="Intel",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "browser_cryptojacking_check")


def _namespace(mod):
    return sys.modules[type(mod).__module__]


def _make_extension(root: Path, extension_id: str, manifest: dict, files: dict):
    version_dir = root / "Default" / "Extensions" / extension_id / "1.0_0"
    version_dir.mkdir(parents=True)
    (version_dir / "manifest.json").write_text(json.dumps(manifest))
    for name, content in files.items():
        (version_dir / name).write_text(content)
    return version_dir


def _check(mod, chromium_root=None, hosts_file=None, platform=Platform.LINUX):
    namespace = _namespace(mod)
    chromium = {platform: [str(chromium_root)]} if chromium_root else {platform: []}
    hosts = {platform: str(hosts_file)} if hosts_file else {}
    with patch.object(namespace, "_CHROMIUM_PROFILE_ROOTS", chromium):
        with patch.object(namespace, "_FIREFOX_PROFILE_ROOTS", {platform: []}):
            with patch.object(namespace, "_HOSTS_FILES", hosts):
                return mod.check(_make_profile(platform))


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "browser_cryptojacking_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.WIN32, Platform.LINUX}


def test_ordinary_extension_is_not_flagged(tmp_path):
    mod = _get_module()
    _make_extension(
        tmp_path,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
        {"name": "Reading List", "version": "1.0"},
        {"background.js": "chrome.storage.local.get('items');"},
    )
    result = _check(mod, chromium_root=tmp_path)
    assert not result.has_issues


def test_extension_calling_a_mining_service_is_critical(tmp_path):
    mod = _get_module()
    _make_extension(
        tmp_path,
        "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb",
        {"name": "Tab Manager Plus", "version": "2.1"},
        {"background.js": "var s='https://coinhive.com/lib/coinhive.min.js';"},
    )

    result = _check(mod, chromium_root=tmp_path)

    findings = [f for f in result.findings if f.data["check"] == "mining_extension"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].data["extension_name"] == "Tab Manager Plus"
    assert findings[0].data["evidence"] == "coinhive.com"


def test_extension_named_after_a_known_miner_is_flagged(tmp_path):
    mod = _get_module()
    _make_extension(
        tmp_path,
        "cccccccccccccccccccccccccccccccc",
        {"name": "SafeBrowse", "version": "3.0"},
        {"background.js": "console.log('hello');"},
    )

    result = _check(mod, chromium_root=tmp_path)

    findings = [f for f in result.findings if f.data["check"] == "mining_extension"]
    assert len(findings) == 1
    assert findings[0].data["indicator"] == "known_mining_extension"


def test_localised_extension_name_falls_back_to_the_extension_id(tmp_path):
    mod = _get_module()
    _make_extension(
        tmp_path,
        "dddddddddddddddddddddddddddddddd",
        {"name": "__MSG_appName__", "version": "1.0"},
        {"worker.js": "CoinHive.Anonymous('key').start();"},
    )

    result = _check(mod, chromium_root=tmp_path)

    assert result.findings[0].data["extension_name"] == (
        "dddddddddddddddddddddddddddddddd"
    )


def test_startup_page_pointing_at_a_mining_site_is_flagged(tmp_path):
    mod = _get_module()
    profile_dir = tmp_path / "Default"
    profile_dir.mkdir(parents=True)
    (profile_dir / "Preferences").write_text(
        json.dumps(
            {
                "session": {"startup_urls": ["https://webminepool.com/start"]},
                "homepage": "https://example.com",
            }
        )
    )

    result = _check(mod, chromium_root=tmp_path)

    findings = [
        f for f in result.findings if f.data["check"] == "mining_startup_page"
    ]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_hosts_file_blocklist_entry_is_not_treated_as_an_attack(tmp_path):
    mod = _get_module()
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n0.0.0.0 coinhive.com\n")

    result = _check(mod, hosts_file=hosts)

    assert not any(
        f.data["check"] == "mining_hosts_entry" for f in result.findings
    )


def test_hosts_file_redirecting_a_mining_domain_elsewhere_is_flagged(tmp_path):
    mod = _get_module()
    hosts = tmp_path / "hosts"
    hosts.write_text("127.0.0.1 localhost\n45.9.148.99 pool.minexmr.com # keepalive\n")

    result = _check(mod, hosts_file=hosts)

    findings = [
        f for f in result.findings if f.data["check"] == "mining_hosts_entry"
    ]
    assert len(findings) == 1
    assert findings[0].data["address"] == "45.9.148.99"
    assert findings[0].data["hostname"] == "pool.minexmr.com"


def test_fix_is_guidance_only_and_names_the_extension(tmp_path):
    mod = _get_module()
    _make_extension(
        tmp_path,
        "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee",
        {"name": "Tab Manager Plus", "version": "2.1"},
        {"background.js": "CryptoLoot.Anonymous('key');"},
    )
    result = _check(mod, chromium_root=tmp_path)

    fix = mod.fix(result, Mode.CLI)

    assert all(action.kind.value == "guidance" for action in fix.actions)
    assert any("Tab Manager Plus" in action.title for action in fix.actions)
    assert any("content blocker" in action.title for action in fix.actions)


def test_fix_does_nothing_without_findings(tmp_path):
    mod = _get_module()
    result = _check(mod, chromium_root=tmp_path)
    assert mod.fix(result, Mode.CLI).actions == []


def test_missing_browser_directories_do_not_raise():
    mod = _get_module()
    result = _check(mod, chromium_root=Path("/does/not/exist"))
    assert result.error is None
    assert not result.has_issues
