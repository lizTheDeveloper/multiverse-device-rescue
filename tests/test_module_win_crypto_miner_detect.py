import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

WALLET = (
    "4123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    "123456789ABCDEFGHJKLMNPQRSTUVWXYZabc"
)

CLEAN_PROCESSES = (
    '"ProcessId","Name","CommandLine"\n'
    '"4","System",""\n'
    '"1200","chrome.exe","C:\\Program Files\\Google\\Chrome\\chrome.exe"\n'
)

MINER_PROCESSES = (
    '"ProcessId","Name","CommandLine"\n'
    '"1200","chrome.exe","C:\\Program Files\\Google\\Chrome\\chrome.exe"\n'
    '"4310","svchost.exe","C:\\Users\\a\\AppData\\svchost.exe '
    f'-o stratum+tcp://pool.supportxmr.com:3333 -u {WALLET}"\n'
)

BUSY_COUNTERS = (
    '"Name","IDProcess","PercentProcessorTime"\n'
    '"chrome","1200","95"\n'
    '"svchost","900","88"\n'
    '"winlogen","4310","91"\n'
)


def _make_profile():
    return SystemProfile(
        platform=Platform.WIN32,
        os_name="Windows 11",
        os_version="10.0.26100",
        architecture="AMD64",
        cpu_model="Intel",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "win_crypto_miner_detect")


def _fake_commands(processes=CLEAN_PROCESSES, counters="", netstat=""):
    def run(command, *args, **kwargs):
        if command[0] == "powershell":
            script = command[-1]
            if "Win32_Process" in script:
                return MagicMock(stdout=processes, returncode=0)
            if "PerfFormattedData" in script:
                return MagicMock(stdout=counters, returncode=0)
        if command[0] == "netstat":
            return MagicMock(stdout=netstat, returncode=0)
        return MagicMock(stdout="", returncode=0)

    return run


def _check(**kwargs):
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_commands(**kwargs)):
        return mod, mod.check(_make_profile())


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "win_crypto_miner_detect"
    assert mod.platforms == [Platform.WIN32]
    assert mod.risk_level == RiskLevel.SAFE


def test_clean_machine_has_no_findings():
    _, result = _check()
    assert not result.has_issues


def test_miner_command_line_is_critical_and_high_confidence():
    _, result = _check(processes=MINER_PROCESSES)
    findings = [f for f in result.findings if f.data["check"] == "known_miner"]
    assert len(findings) == 1
    assert findings[0].severity == Severity.CRITICAL
    assert findings[0].data["confidence"] == "high"
    assert findings[0].data["pid"] == 4310


def test_wallet_address_is_kept_as_evidence_but_not_printed_in_full():
    _, result = _check(processes=MINER_PROCESSES)
    finding = result.findings[0]
    assert finding.data["indicator"] == "monero_wallet_address"
    assert finding.data["evidence"] == WALLET
    assert WALLET not in finding.description


def test_established_connection_to_a_pool_port_is_flagged():
    netstat = (
        "  Proto  Local Address          Foreign Address        State           PID\n"
        "  TCP    192.168.1.5:51000      51.15.65.4:3333        ESTABLISHED     4310\n"
        "  TCP    192.168.1.5:51001      142.250.0.1:443        ESTABLISHED     1200\n"
    )
    _, result = _check(processes=MINER_PROCESSES, netstat=netstat)
    pool = [f for f in result.findings if f.data["check"] == "mining_pool_connection"]
    assert len(pool) == 1
    assert pool[0].data["port"] == 3333
    assert pool[0].data["process"] == "svchost.exe"


def test_listening_sockets_are_not_treated_as_pool_connections():
    netstat = (
        "  TCP    0.0.0.0:3333           0.0.0.0:0              LISTENING       900\n"
    )
    _, result = _check(netstat=netstat)
    assert not any(
        f.data["check"] == "mining_pool_connection" for f in result.findings
    )


def test_high_cpu_is_a_low_confidence_warning_and_skips_known_processes():
    _, result = _check(counters=BUSY_COUNTERS)
    high_cpu = [f for f in result.findings if f.data["check"] == "high_cpu_process"]
    # chrome and svchost are expected to spike; the unrecognised one is not.
    assert [f.data["process"] for f in high_cpu] == ["winlogen"]
    assert high_cpu[0].severity == Severity.WARNING
    assert high_cpu[0].data["confidence"] == "low"


def test_fix_separates_confirmed_miners_from_high_cpu_leads():
    _, result = _check(processes=MINER_PROCESSES, counters=BUSY_COUNTERS)
    mod = _get_module()
    fix = mod.fix(result, Mode.CLI)

    titles = [action.title for action in fix.actions]
    assert any(title.startswith("Stop and remove the miner") for title in titles)
    assert any(title.startswith("Identify what") for title in titles)
    assert all(action.kind.value == "guidance" for action in fix.actions)


def test_command_failures_degrade_to_no_findings():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("powershell missing")):
        result = mod.check(_make_profile())
    assert result.error is None
    assert not result.has_issues
