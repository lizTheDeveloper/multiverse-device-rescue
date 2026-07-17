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
    return next(m for m in modules if m.name == "suspicious_connections")


def _fake_lsof_output(lsof_text):
    """Create a mock subprocess.run that returns lsof output."""
    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stdout = lsof_text
        result.stderr = ""
        return result
    return fake_run


def test_suspicious_connections_discovered():
    mod = _get_module()
    assert mod.name == "suspicious_connections"
    assert mod.risk_level == RiskLevel.SAFE
    assert mod.category == "security"


def test_suspicious_connections_healthy_standard_ports():
    """No suspicious activity when only standard ports are used."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP *:443 (LISTEN)
Mail      12346     user   11u  IPv4 0x1234567890123457      0t0  TCP *:993 (LISTEN)
Chrome    12347     user   12u  IPv4 0x1234567890123458      0t0  TCP *:80 (LISTEN)"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert not result.has_issues


def test_suspicious_connections_unusual_listening_port():
    """Detect unusual listening ports."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP *:443 (LISTEN)
BadApp    12348     user   13u  IPv4 0x1234567890123459      0t0  TCP *:8888 (LISTEN)"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) == 1
    assert "unusual listening port" in result.findings[0].title.lower()
    assert result.findings[0].severity == Severity.WARNING
    assert result.findings[0].data["port"] == 8888


def test_suspicious_connections_unusual_outbound_connection():
    """Detect unusual outbound connections to non-standard ports."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP 192.168.1.1:50000 (ESTABLISHED)
BadApp    12348     user   13u  IPv4 0x1234567890123459      0t0  TCP 10.0.0.1:9999 (ESTABLISHED)"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    # Safari is known safe, so should not flag it
    # BadApp is not known safe and uses non-standard port, so should flag it
    assert result.has_issues
    findings_about_badapp = [f for f in result.findings if "BadApp" in f.data.get("process", "")]
    assert len(findings_about_badapp) >= 1
    assert findings_about_badapp[0].data["port"] == 9999


def test_suspicious_connections_known_safe_process():
    """Known safe processes shouldn't be flagged even with unusual ports."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP 192.168.1.1:9999 (ESTABLISHED)
Chrome    12346     user   11u  IPv4 0x1234567890123457      0t0  TCP 192.168.1.2:8888 (ESTABLISHED)"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    # Both Safari and Chrome are known safe processes, so should not flag
    assert not result.has_issues


def test_suspicious_connections_high_connection_count():
    """Detect processes with unusually high connection counts."""
    mod = _get_module()
    # Create a process with 12 connections (exceeds threshold of 10)
    connections = [
        "MalwareApp 12348     user   13u  IPv4 0x1234567890123459      0t0  TCP 192.168.1.1:5000 (ESTABLISHED)"
        for _ in range(12)
    ]
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
""" + "\n".join(connections)

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    # Should detect high connection count
    high_conn_findings = [
        f for f in result.findings
        if f.data.get("check") == "high_connection_count"
    ]
    assert len(high_conn_findings) >= 1
    assert high_conn_findings[0].severity == Severity.INFO


def test_suspicious_connections_multiple_issues():
    """Detect multiple issues in a single scan."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
Safari    12345     user   10u  IPv4 0x1234567890123456      0t0  TCP *:443 (LISTEN)
MalApp1   12348     user   13u  IPv4 0x1234567890123459      0t0  TCP *:7777 (LISTEN)
MalApp2   12349     user   14u  IPv4 0x1234567890123460      0t0  TCP 192.168.1.1:6666 (ESTABLISHED)
MalApp2   12349     user   15u  IPv4 0x1234567890123461      0t0  TCP 192.168.1.2:6666 (ESTABLISHED)
MalApp2   12349     user   16u  IPv4 0x1234567890123462      0t0  TCP 192.168.1.3:6666 (ESTABLISHED)"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert result.has_issues
    assert len(result.findings) >= 2


def test_suspicious_connections_fix_is_informational():
    """fix() should be informational only, never kill processes."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME
BadApp    12348     user   13u  IPv4 0x1234567890123459      0t0  TCP *:8888 (LISTEN)"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        check = mod.check(_make_profile())

    # Patch subprocess to verify no kill commands are issued
    with patch("subprocess.run") as mock_run:
        fix = mod.fix(check, Mode.MANUAL)

    # Verify no subprocess calls were made (fix is informational)
    mock_run.assert_not_called()

    # Verify fix succeeded with informational actions
    assert fix.all_succeeded
    assert len(fix.actions) == 1
    assert fix.actions[0].success is True
    assert fix.actions[0].error is None


def test_suspicious_connections_empty_lsof():
    """Handle empty lsof output gracefully."""
    mod = _get_module()
    lsof_output = """COMMAND     PID     USER   FD   TYPE             DEVICE SIZE/OFF NODE NAME"""

    with patch("subprocess.run", side_effect=_fake_lsof_output(lsof_output)):
        result = mod.check(_make_profile())

    assert not result.has_issues


def test_suspicious_connections_lsof_unavailable():
    """Handle lsof command unavailable gracefully."""
    mod = _get_module()

    def fake_run_error(cmd, **kwargs):
        raise OSError("lsof not found")

    with patch("subprocess.run", side_effect=fake_run_error):
        result = mod.check(_make_profile())

    # Should not crash, just return no findings
    assert not result.has_issues
