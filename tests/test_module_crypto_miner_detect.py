import sys
from pathlib import Path
from unittest.mock import patch, MagicMock

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode
from rescue.registry import discover_modules


def _make_profile():
    return SystemProfile(
        platform=Platform.DARWIN,
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
    return next(m for m in modules if m.name == "crypto_miner_detect")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_healthy():
    """Normal case: no miners found"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ps aux" in cmd_str or cmd == ["ps", "aux"]:
            return _make_subprocess_result(
                "USER       PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED     TIME COMMAND\n"
                "root         1  0.0  0.2  12345  2000 ??  Ss   10:00AM   0:00 /sbin/launchd\n"
                "user      1234  0.5  1.0  50000 20000 ??  S    10:00AM   0:01 /Applications/Safari.app\n"
            )
        elif "ps -eo" in cmd_str or cmd == ["ps", "-eo", "pid,pcpu,comm"]:
            return _make_subprocess_result(
                "  PID %CPU COMM\n"
                "    1  0.0 launchd\n"
                " 1234  0.5 Safari\n"
                " 5678  0.2 Finder\n"
            )
        elif "lsof -i" in cmd_str or cmd == ["lsof", "-i", "-n", "-P"]:
            return _make_subprocess_result(
                "COMMAND   PID USER  FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
                "Safari   1234 user   45  IPv4      0      0  TCP 192.168.1.10:54321->1.1.1.1:443 (ESTABLISHED)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_known_miner():
    """Case: known miner process running"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ps aux" in cmd_str or cmd == ["ps", "aux"]:
            return _make_subprocess_result(
                "USER       PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED     TIME COMMAND\n"
                "root         1  0.0  0.2  12345  2000 ??  Ss   10:00AM   0:00 /sbin/launchd\n"
                "user      2000  95.0  5.0 100000 50000 ??  R    10:00AM   1:30 /usr/local/bin/xmrig -c config.json\n"
            )
        elif "ps -eo" in cmd_str or cmd == ["ps", "-eo", "pid,pcpu,comm"]:
            return _make_subprocess_result(
                "  PID %CPU COMM\n"
                " 2000  95.0 xmrig\n"
            )
        elif "lsof -i" in cmd_str or cmd == ["lsof", "-i", "-n", "-P"]:
            return _make_subprocess_result(
                "COMMAND   PID USER  FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_high_cpu_process():
    """Case: unknown process with very high CPU usage"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ps aux" in cmd_str or cmd == ["ps", "aux"]:
            return _make_subprocess_result(
                "USER       PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED     TIME COMMAND\n"
                "root         1  0.0  0.2  12345  2000 ??  Ss   10:00AM   0:00 /sbin/launchd\n"
                "user      3000  85.0  8.0 150000 80000 ??  R    10:00AM   5:30 /usr/local/bin/mystery_app\n"
            )
        elif "ps -eo" in cmd_str or cmd == ["ps", "-eo", "pid,pcpu,comm"]:
            return _make_subprocess_result(
                "  PID %CPU COMM\n"
                " 3000  85.0 mystery_app\n"
            )
        elif "lsof -i" in cmd_str or cmd == ["lsof", "-i", "-n", "-P"]:
            return _make_subprocess_result(
                "COMMAND   PID USER  FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_mining_pool_connection():
    """Case: connection to mining pool port"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ps aux" in cmd_str or cmd == ["ps", "aux"]:
            return _make_subprocess_result(
                "USER       PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED     TIME COMMAND\n"
                "root         1  0.0  0.2  12345  2000 ??  Ss   10:00AM   0:00 /sbin/launchd\n"
                "user      4000  50.0  3.0 80000 30000 ??  S    10:00AM   2:00 /Applications/helper.app\n"
            )
        elif "ps -eo" in cmd_str or cmd == ["ps", "-eo", "pid,pcpu,comm"]:
            return _make_subprocess_result(
                "  PID %CPU COMM\n"
                " 4000  50.0 helper\n"
            )
        elif "lsof -i" in cmd_str or cmd == ["lsof", "-i", "-n", "-P"]:
            return _make_subprocess_result(
                "COMMAND   PID USER  FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
                "helper   4000 user   20  IPv4      0      0  TCP 192.168.1.10:54321->203.0.113.50:3333 (ESTABLISHED)\n"
            )
        return _make_subprocess_result()
    return fake_run


def _fake_run_with_mining_domain():
    """Case: connection to mining pool domain"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "ps aux" in cmd_str or cmd == ["ps", "aux"]:
            return _make_subprocess_result(
                "USER       PID  %CPU %MEM    VSZ   RSS TT  STAT STARTED     TIME COMMAND\n"
                "user      5000  30.0  2.0 60000 20000 ??  S    10:00AM   1:00 /usr/local/bin/app\n"
            )
        elif "ps -eo" in cmd_str or cmd == ["ps", "-eo", "pid,pcpu,comm"]:
            return _make_subprocess_result(
                "  PID %CPU COMM\n"
                " 5000  30.0 app\n"
            )
        elif "lsof -i" in cmd_str or cmd == ["lsof", "-i", "-n", "-P"]:
            return _make_subprocess_result(
                "COMMAND   PID USER  FD   TYPE DEVICE SIZE/OFF NODE NAME\n"
                "app      5000 user   15  IPv4      0      0  TCP 192.168.1.10:55555->pool.example.com:8888 (ESTABLISHED)\n"
            )
        return _make_subprocess_result()
    return fake_run


def test_crypto_miner_detect_discovered():
    mod = _get_module()
    assert mod.name == "crypto_miner_detect"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_crypto_miner_detect_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_healthy()):
        result = mod.check(_make_profile())
    assert not result.has_issues


def test_crypto_miner_detect_known_miner():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_known_miner()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "known_miner" for f in result.findings)
    assert any(f.severity == Severity.CRITICAL for f in result.findings)


def test_crypto_miner_detect_high_cpu_process():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_high_cpu_process()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "high_cpu_process" for f in result.findings)
    assert any(f.severity == Severity.WARNING for f in result.findings)


def test_crypto_miner_detect_mining_pool_connection():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_mining_pool_connection()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "mining_pool_connection" for f in result.findings)


def test_crypto_miner_detect_mining_domain():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_mining_domain()):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "mining_pool_connection" for f in result.findings)


def test_crypto_miner_detect_fix_is_informational():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_with_known_miner()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0
