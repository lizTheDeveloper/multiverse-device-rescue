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
        os_version="13.5",
        architecture="arm64",
        cpu_model="Apple M1",
        cpu_cores=8,
        ram_bytes=16 * 1024**3,
    )


def _get_module():
    modules_dir = Path(__file__).parent.parent / "modules"
    modules = discover_modules(modules_dir)
    return next(m for m in modules if m.name == "network_connections_monitor")


def _make_run_result(connections=None, expect_clean=False):
    """Create a fake subprocess.run that returns lsof output.

    Args:
        connections: List of connection tuples (process, pid, remote_ip, port, state)
        expect_clean: If True, return empty connections by default
    """

    def fake_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        result.stdout = ""

        cmd_str = " ".join(cmd) if isinstance(cmd, list) else str(cmd)

        # lsof command
        if "lsof" in cmd_str and "-i" in cmd_str:
            lines = [
                "COMMAND  PID  USER  FD  TYPE             DEVICE SIZE/OFF NODE NAME"
            ]

            if connections:
                for proc, pid, remote_ip, port, state in connections:
                    # Format: process pid user fd type device size node remote_ip:remote_port (state)
                    line = f"{proc:<8} {pid:<5} user  42u IPv4 0x123456 0t0 TCP 127.0.0.1:12345->{remote_ip}:{port} ({state})"
                    lines.append(line)

            result.stdout = "\n".join(lines)

        return result

    return fake_run


def test_network_connections_monitor_discovered():
    mod = _get_module()
    assert mod.name == "network_connections_monitor"
    assert mod.category == "security"
    assert Platform.DARWIN in mod.platforms
    assert mod.risk_level == RiskLevel.SAFE


def test_network_connections_monitor_clean():
    """Test when no suspicious connections are found."""
    mod = _get_module()
    fake_run = _make_run_result(expect_clean=True)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should have no findings if clean
    assert not result.has_issues


def test_network_connections_monitor_legitimate_connections():
    """Test with normal legitimate connections."""
    mod = _get_module()
    connections = [
        ("Safari", 123, "93.184.216.34", 443, "ESTABLISHED"),  # HTTP (HTTPS)
        ("Chrome", 456, "8.8.8.8", 53, "ESTABLISHED"),  # DNS
        ("SSH", 789, "192.168.1.100", 22, "ESTABLISHED"),  # SSH
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # Should only have INFO for connection summary
    assert result.has_issues
    assert any(f.data.get("check") == "connection_summary" for f in result.findings)
    info_findings = [f for f in result.findings if f.severity == Severity.INFO]
    assert len(info_findings) > 0


def test_network_connections_monitor_backdoor_ports():
    """Test detection of connections on backdoor ports."""
    mod = _get_module()
    connections = [
        ("suspect.exe", 1234, "10.0.0.50", 4444, "ESTABLISHED"),  # Backdoor port
        ("malware", 5678, "172.16.0.1", 1337, "ESTABLISHED"),  # Backdoor port
        ("normal.app", 9999, "93.184.216.34", 443, "ESTABLISHED"),  # Legitimate
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "backdoor_ports" for f in result.findings)
    critical = [f for f in result.findings if f.data.get("check") == "backdoor_ports"]
    assert len(critical) == 1
    assert critical[0].severity == Severity.CRITICAL
    assert "suspect.exe" in critical[0].description


def test_network_connections_monitor_high_connection_count():
    """Test detection of processes with many connections."""
    mod = _get_module()
    connections = []
    # Create 25 connections from same process
    for i in range(25):
        connections.append(
            ("malware", 2000, f"10.0.0.{i+1}", 1000 + i, "ESTABLISHED")
        )
    # Add some normal connections
    connections.append(("Safari", 456, "93.184.216.34", 443, "ESTABLISHED"))

    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "high_connection_count" for f in result.findings)
    warning = [f for f in result.findings if f.data.get("check") == "high_connection_count"]
    assert len(warning) == 1
    assert warning[0].severity == Severity.WARNING
    assert "malware" in warning[0].description


def test_network_connections_monitor_unusual_ports():
    """Test detection of connections on unusual ports."""
    mod = _get_module()
    connections = [
        ("app", 1111, "93.184.216.34", 8888, "ESTABLISHED"),  # Unusual port (backdoor but not >20)
        ("process", 2222, "10.0.0.100", 5000, "ESTABLISHED"),  # Unusual port
        ("Chrome", 3333, "8.8.8.8", 53, "ESTABLISHED"),  # Legitimate (DNS)
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    # Should have unusual_ports warning (and backdoor_ports critical for 8888)
    assert any(f.data.get("check") == "backdoor_ports" for f in result.findings)


def test_network_connections_monitor_private_ips():
    """Test detection of connections to private IPs."""
    mod = _get_module()
    connections = [
        ("app", 111, "192.168.1.50", 3306, "ESTABLISHED"),  # Private IP
        ("service", 222, "10.0.0.100", 5432, "ESTABLISHED"),  # Private IP
        ("browser", 333, "93.184.216.34", 443, "ESTABLISHED"),  # Public IP
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    assert any(f.data.get("check") == "private_ip_connections" for f in result.findings)
    private = [f for f in result.findings if f.data.get("check") == "private_ip_connections"]
    assert len(private) == 1
    assert private[0].severity == Severity.INFO


def test_network_connections_monitor_multiple_issues():
    """Test when multiple issues are detected."""
    mod = _get_module()
    connections = [
        # Backdoor port connection
        ("suspect", 100, "172.16.0.5", 4444, "ESTABLISHED"),
        # High connection count
        ("malware", 200, "10.0.0.1", 2000, "ESTABLISHED"),
        ("malware", 200, "10.0.0.2", 2001, "ESTABLISHED"),
        ("malware", 200, "10.0.0.3", 2002, "ESTABLISHED"),
        ("malware", 200, "10.0.0.4", 2003, "ESTABLISHED"),
        ("malware", 200, "10.0.0.5", 2004, "ESTABLISHED"),
        ("malware", 200, "10.0.0.6", 2005, "ESTABLISHED"),
        ("malware", 200, "10.0.0.7", 2006, "ESTABLISHED"),
        ("malware", 200, "10.0.0.8", 2007, "ESTABLISHED"),
        ("malware", 200, "10.0.0.9", 2008, "ESTABLISHED"),
        ("malware", 200, "10.0.0.10", 2009, "ESTABLISHED"),
        ("malware", 200, "10.0.0.11", 2010, "ESTABLISHED"),
        ("malware", 200, "10.0.0.12", 2011, "ESTABLISHED"),
        ("malware", 200, "10.0.0.13", 2012, "ESTABLISHED"),
        ("malware", 200, "10.0.0.14", 2013, "ESTABLISHED"),
        ("malware", 200, "10.0.0.15", 2014, "ESTABLISHED"),
        ("malware", 200, "10.0.0.16", 2015, "ESTABLISHED"),
        ("malware", 200, "10.0.0.17", 2016, "ESTABLISHED"),
        ("malware", 200, "10.0.0.18", 2017, "ESTABLISHED"),
        ("malware", 200, "10.0.0.19", 2018, "ESTABLISHED"),
        ("malware", 200, "10.0.0.20", 2019, "ESTABLISHED"),
        ("malware", 200, "10.0.0.21", 2020, "ESTABLISHED"),
        # Unusual port
        ("app", 300, "93.184.216.34", 9999, "ESTABLISHED"),
        # Legitimate
        ("Safari", 400, "93.184.216.34", 443, "ESTABLISHED"),
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    assert result.has_issues
    checks = [f.data.get("check") for f in result.findings]
    assert "backdoor_ports" in checks
    assert "high_connection_count" in checks
    assert "unusual_ports" in checks
    assert "private_ip_connections" in checks
    assert "connection_summary" in checks


def test_network_connections_monitor_fix_backdoor():
    """Test fix recommendation for backdoor ports."""
    mod = _get_module()
    connections = [
        ("suspect", 123, "10.0.0.50", 4444, "ESTABLISHED"),
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    backdoor_actions = [a for a in fix.actions if "backdoor" in a.title.lower()]
    assert len(backdoor_actions) > 0


def test_network_connections_monitor_fix_high_connections():
    """Test fix recommendation for high connection count."""
    mod = _get_module()
    connections = []
    for i in range(25):
        connections.append(("malware", 200, f"10.0.0.{i+1}", 1000 + i, "ESTABLISHED"))

    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert len(fix.actions) > 0
    high_conn_actions = [a for a in fix.actions if "high" in a.title.lower()]
    assert len(high_conn_actions) > 0


def test_network_connections_monitor_subprocess_error():
    """Test graceful handling of subprocess errors."""
    mod = _get_module()

    def error_run(cmd, **kwargs):
        raise OSError("Command failed")

    with patch("subprocess.run", side_effect=error_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_network_connections_monitor_timeout():
    """Test graceful handling of subprocess timeout."""
    mod = _get_module()

    def timeout_run(cmd, **kwargs):
        raise Exception("Timeout")

    with patch("subprocess.run", side_effect=timeout_run):
        result = mod.check(_make_profile())
    # Should complete without crashing
    assert isinstance(result.findings, list)


def test_network_connections_monitor_ipv6_connections():
    """Test parsing of IPv6 connections."""
    mod = _get_module()

    def ipv6_run(cmd, **kwargs):
        result = MagicMock()
        result.returncode = 0
        result.stderr = ""
        # IPv6 format with brackets
        result.stdout = (
            "COMMAND  PID  USER  FD  TYPE             DEVICE SIZE/OFF NODE NAME\n"
            "Safari   123  user  42u IPv6 0x123456 0t0 TCP [::1]:54321->[2001:4860:4860::8888]:443 (ESTABLISHED)\n"
        )
        return result

    with patch("subprocess.run", side_effect=ipv6_run):
        result = mod.check(_make_profile())
    # Should parse without error
    assert isinstance(result.findings, list)


def test_network_connections_monitor_all_ports_and_states():
    """Test that the module detects all types correctly."""
    mod = _get_module()
    connections = [
        ("proc1", 100, "93.184.216.34", 443, "ESTABLISHED"),
        ("proc2", 200, "8.8.8.8", 53, "ESTABLISHED"),
        ("proc3", 300, "10.0.0.1", 22, "ESTABLISHED"),
        ("proc4", 400, "192.168.1.1", 80, "ESTABLISHED"),
    ]
    fake_run = _make_run_result(connections=connections)
    with patch("subprocess.run", side_effect=fake_run):
        result = mod.check(_make_profile())
    # All are legitimate ports, should only have connection_summary
    assert result.has_issues
    summary = [f for f in result.findings if f.data.get("check") == "connection_summary"]
    assert len(summary) > 0
    assert summary[0].data.get("total_count") == 4
