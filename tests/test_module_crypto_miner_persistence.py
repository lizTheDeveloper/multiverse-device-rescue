import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

# A Monero address's shape: 95 base58 characters beginning with 4 or 8. Not a
# real wallet — the point is that the pattern is what gets recognised.
WALLET = (
    "4123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabc"
)

LAUNCH_AGENT = """\
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>com.apple.softwareupdate.helper</string>
  <key>ProgramArguments</key>
  <array>
    <string>/tmp/.x/kworker</string>
    <string>-o</string>
    <string>stratum+tcp://pool.supportxmr.com:3333</string>
  </array>
  <key>RunAtLoad</key><true/>
</dict>
</plist>
"""

BENIGN_LAUNCH_AGENT = """\
<?xml version="1.0" encoding="UTF-8"?>
<plist version="1.0">
<dict>
  <key>Label</key><string>com.example.backup</string>
  <key>ProgramArguments</key><array><string>/usr/local/bin/backup</string></array>
</dict>
</plist>
"""


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
    return next(m for m in modules if m.name == "crypto_miner_persistence")


def _namespace(mod):
    return sys.modules[type(mod).__module__]


def _no_commands(*args, **kwargs):
    return MagicMock(stdout="", returncode=0)


def _check_darwin(mod, persistence_dir=None, drop_dir=None, profiles=()):
    namespace = _namespace(mod)
    with patch("subprocess.run", side_effect=_no_commands):
        with patch.object(
            namespace,
            "_DARWIN_PERSISTENCE_DIRS",
            [str(persistence_dir)] if persistence_dir else [],
        ):
            with patch.object(
                namespace,
                "_DARWIN_DROP_DIRS",
                [str(drop_dir)] if drop_dir else [],
            ):
                with patch.object(namespace, "_SHELL_PROFILES", list(profiles)):
                    return mod.check(_make_profile())


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "crypto_miner_persistence"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.WIN32, Platform.LINUX}


def test_clean_system_has_no_findings(tmp_path):
    mod = _get_module()
    (tmp_path / "com.example.backup.plist").write_text(BENIGN_LAUNCH_AGENT)
    result = _check_darwin(mod, persistence_dir=tmp_path)
    assert not result.has_issues


def test_launch_agent_running_a_miner_is_critical(tmp_path):
    mod = _get_module()
    (tmp_path / "com.apple.softwareupdate.helper.plist").write_text(LAUNCH_AGENT)

    result = _check_darwin(mod, persistence_dir=tmp_path)

    findings = [f for f in result.findings if f.data["check"] == "miner_launch_item"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].data["indicator"] == "miner_arguments"
    assert findings[0].data["confidence"] == "high"


def test_wallet_address_outranks_every_other_indicator(tmp_path):
    mod = _get_module()
    (tmp_path / "com.user.helper.plist").write_text(
        f"<plist><string>--user {WALLET}</string></plist>"
    )

    result = _check_darwin(mod, persistence_dir=tmp_path)

    assert result.findings[0].data["indicator"] == "monero_wallet_address"
    assert result.findings[0].severity == Severity.CRITICAL
    # The address itself is kept as evidence, but truncated in the prose.
    assert result.findings[0].data["evidence"] == WALLET
    assert WALLET not in result.findings[0].description


def test_known_pool_domain_is_detected(tmp_path):
    mod = _get_module()
    (tmp_path / "com.user.helper.plist").write_text(
        "<plist><string>https://moneroocean.stream/setup.sh</string></plist>"
    )

    result = _check_darwin(mod, persistence_dir=tmp_path)

    assert result.findings[0].data["indicator"] == "mining_pool"
    assert result.findings[0].data["evidence"] == "moneroocean.stream"


def test_shell_profile_starting_a_miner_is_detected(tmp_path):
    mod = _get_module()
    profile_file = tmp_path / ".zshrc"
    profile_file.write_text("export PATH=$PATH:/usr/local/bin\nnohup xmrig &\n")

    result = _check_darwin(mod, profiles=[str(profile_file)])

    findings = [f for f in result.findings if f.data["check"] == "miner_shell_profile"]
    assert len(findings) == 1
    assert findings[0].data["indicator"] == "known_miner"


def test_dropped_config_needs_strong_evidence_not_just_a_product_name(tmp_path):
    mod = _get_module()
    # A name-only mention in an arbitrary JSON file is not enough...
    (tmp_path / "settings.json").write_text('{"note": "compare against nicehash"}')
    assert not _check_darwin(mod, drop_dir=tmp_path).has_issues

    # ...but a pool URL in the same place is.
    (tmp_path / "config.json").write_text(
        '{"pools": [{"url": "stratum+tcp://pool.minexmr.com:4444"}]}'
    )
    result = _check_darwin(mod, drop_dir=tmp_path)
    findings = [f for f in result.findings if f.data["check"] == "miner_config_file"]
    assert len(findings) == 1


def test_cron_job_starting_a_miner_is_detected():
    mod = _get_module()
    namespace = _namespace(mod)

    def run(command, *args, **kwargs):
        if command[:2] == ["crontab", "-l"]:
            return MagicMock(
                stdout="# comment\n*/5 * * * * /tmp/.x --donate-level 1\n",
                returncode=0,
            )
        return MagicMock(stdout="", returncode=0)

    with patch("subprocess.run", side_effect=run):
        with patch.object(namespace, "_DARWIN_PERSISTENCE_DIRS", []):
            with patch.object(namespace, "_DARWIN_DROP_DIRS", []):
                with patch.object(namespace, "_SHELL_PROFILES", []):
                    result = mod.check(_make_profile())

    findings = [f for f in result.findings if f.data["check"] == "miner_cron_job"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL


def test_windows_run_key_pointing_at_a_pool_is_detected():
    mod = _get_module()

    def run(command, *args, **kwargs):
        if command[:2] == ["reg", "query"]:
            return MagicMock(
                stdout=(
                    "HKEY_CURRENT_USER\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\n"
                    "    OneDriveUpdate    REG_SZ    "
                    "C:\\Users\\a\\AppData\\svc.exe -o stratum+tcp://c3pool.com:80\n"
                ),
                returncode=0,
            )
        return MagicMock(stdout="", returncode=0)

    with patch("subprocess.run", side_effect=run):
        result = mod.check(_make_profile(Platform.WIN32))

    findings = [f for f in result.findings if f.data["check"] == "miner_run_key"]
    assert findings
    assert findings[0].severity == Severity.CRITICAL


def test_fix_is_guidance_only_and_explains_the_removal_order(tmp_path):
    mod = _get_module()
    (tmp_path / "com.apple.softwareupdate.helper.plist").write_text(LAUNCH_AGENT)
    result = _check_darwin(mod, persistence_dir=tmp_path)

    fix = mod.fix(result, Mode.CLI)

    assert all(action.kind.value == "guidance" for action in fix.actions)
    assert all(not action.executed for action in fix.actions)
    assert any("how the miner got installed" in a.title for a in fix.actions)


def test_fix_does_nothing_without_findings(tmp_path):
    mod = _get_module()
    result = _check_darwin(mod, persistence_dir=tmp_path)
    assert mod.fix(result, Mode.CLI).actions == []


def test_unreadable_locations_do_not_raise(tmp_path):
    mod = _get_module()
    namespace = _namespace(mod)
    with patch("subprocess.run", side_effect=OSError("no crontab")):
        with patch.object(
            namespace, "_DARWIN_PERSISTENCE_DIRS", [str(tmp_path / "missing")]
        ):
            with patch.object(namespace, "_DARWIN_DROP_DIRS", ["/does/not/exist"]):
                result = mod.check(_make_profile())
    assert result.error is None
    assert not result.has_issues
