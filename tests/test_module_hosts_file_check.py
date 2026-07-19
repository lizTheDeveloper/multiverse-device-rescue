import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import SystemProfile, Platform, Severity, RiskLevel, Mode, Finding, CheckResult
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
    return next(m for m in modules if m.name == "hosts_file_check")


def test_hosts_file_check_discovered():
    """Test that the module is properly discovered."""
    mod = _get_module()
    assert mod.name == "hosts_file_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE


def test_parse_hosts_file_clean():
    """Test parsing clean hosts file with only default entries."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "255.255.255.255\tbroadcasthost\n"
        "::1\tlocalhost\n"
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 0, "Clean hosts file should have no custom entries"


def test_parse_hosts_file_with_adblock():
    """Test parsing hosts file with safe ad-blocker entries."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "255.255.255.255\tbroadcasthost\n"
        "::1\tlocalhost\n"
        "127.0.0.1\tad.doubleclick.net\n"
        "0.0.0.0\tads.example.com\n"
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 2, "Should find 2 custom entries"
    assert entries[0]["hostname"] == "ad.doubleclick.net"
    assert entries[0]["ip"] == "127.0.0.1"
    assert entries[1]["hostname"] == "ads.example.com"
    assert entries[1]["ip"] == "0.0.0.0"


def test_parse_hosts_file_suspicious():
    """Test parsing hosts file with suspicious IP redirects."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "192.168.1.100\tmalicious.com\n"
        "10.0.0.1\tphishing.com\n"
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 2
    assert entries[0]["ip"] == "192.168.1.100"
    assert entries[0]["hostname"] == "malicious.com"
    assert entries[1]["ip"] == "10.0.0.1"
    assert entries[1]["hostname"] == "phishing.com"


def test_parse_hosts_file_with_comments():
    """Test parsing correctly ignores comments and blank lines."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "# Comment line\n"
        "192.168.1.1\tmalicious.com # inline comment\n"
        "\n"
        "::1\tlocalhost\n"
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 1, "Should find 1 custom entry"
    assert entries[0]["hostname"] == "malicious.com"
    assert entries[0]["ip"] == "192.168.1.1"


def test_parse_hosts_file_multiple_hostnames():
    """Test parsing multiple hostnames on one line."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost localhost.localdomain\n"
        "192.168.1.1\tmalicious.com phishing.com other.bad.com\n"
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 3, "Should find 3 custom entries (localhost doesn't count)"
    hostnames = {e["hostname"] for e in entries}
    assert hostnames == {"malicious.com", "phishing.com", "other.bad.com"}


def test_parse_hosts_file_ipv6():
    """Test parsing IPv6 entries."""
    mod = _get_module()

    content = (
        "::1\tlocalhost\n"
        "fe80::1\tip6-localnet\n"
        "2001:db8::1\tcustom.site.com\n"
    )

    entries = mod._parse_hosts_file(content)
    # Only custom.site.com is a custom entry (ip6-localnet is default)
    custom = [e for e in entries if e["hostname"] == "custom.site.com"]
    assert len(custom) == 1
    assert custom[0]["ip"] == "2001:db8::1"


def test_parse_hosts_file_large_count():
    """Test parsing a hosts file with many entries."""
    mod = _get_module()

    lines = ["127.0.0.1\tlocalhost\n"]
    for i in range(30):
        lines.append(f"127.0.0.1\tcustom-{i}.local\n")

    entries = mod._parse_hosts_file("".join(lines))
    assert len(entries) == 30, "Should parse all 30 custom entries"


def test_parse_hosts_file_wellknown_domains():
    """Test parsing well-known domain entries."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "192.168.1.1\tgoogle.com\n"
        "10.0.0.1\tfacebook.com\n"
        "172.16.0.1\tmail.google.com\n"
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 3
    hostnames = {e["hostname"] for e in entries}
    assert "google.com" in hostnames
    assert "facebook.com" in hostnames
    assert "mail.google.com" in hostnames


def test_fix_is_informational():
    """Test that fix() is informational and always succeeds."""
    mod = _get_module()

    findings = [
        Finding(
            title="Test finding",
            description="Test",
            severity=Severity.WARNING,
            category="security",
            data={"check": "suspicious_ip_redirect", "count": 2, "entries": []},
        ),
    ]

    check_result = CheckResult(module_name=mod.name, findings=findings)
    fix = mod.fix(check_result, Mode.MANUAL)

    # fix() should always succeed with informational messages
    assert fix.all_succeeded, "All fix actions should succeed"
    assert len(fix.actions) > 0, "Should have at least one action"
    assert all(a.success for a in fix.actions), "All actions should be marked as success"


def test_fix_clean_hosts_no_action():
    """Test fix() doesn't create actions for clean hosts."""
    mod = _get_module()

    findings = [
        Finding(
            title="Hosts file is clean",
            description="Clean",
            severity=Severity.INFO,
            category="security",
            data={"check": "clean_hosts"},
        ),
    ]

    check_result = CheckResult(module_name=mod.name, findings=findings)
    fix = mod.fix(check_result, Mode.MANUAL)

    # Clean hosts should not have actions
    assert fix.all_succeeded
    assert len(fix.actions) == 0


def test_fix_large_count():
    """Test fix() action for large hosts file count."""
    mod = _get_module()

    findings = [
        Finding(
            title="Large hosts",
            description="Too many",
            severity=Severity.WARNING,
            category="security",
            data={"check": "large_hosts_count", "count": 30},
        ),
    ]

    check_result = CheckResult(module_name=mod.name, findings=findings)
    fix = mod.fix(check_result, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("hosts" in a.description.lower() for a in fix.actions)


def test_fix_suspicious_ip_redirect():
    """Test fix() action for suspicious IP redirects."""
    mod = _get_module()

    findings = [
        Finding(
            title="Suspicious redirects",
            description="Bad",
            severity=Severity.WARNING,
            category="security",
            data={
                "check": "suspicious_ip_redirect",
                "count": 2,
                "entries": [
                    {"hostname": "malicious.com", "ip": "192.168.1.1"},
                    {"hostname": "phishing.com", "ip": "10.0.0.1"},
                ],
            },
        ),
    ]

    check_result = CheckResult(module_name=mod.name, findings=findings)
    fix = mod.fix(check_result, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    action = fix.actions[0]
    assert "review" in action.description.lower()


def test_fix_wellknown_domain_redirect():
    """Test fix() action for well-known domain redirects."""
    mod = _get_module()

    findings = [
        Finding(
            title="Well-known domain redirect",
            description="Malicious",
            severity=Severity.WARNING,
            category="security",
            data={
                "check": "wellknown_domain_redirect",
                "count": 1,
                "entries": [{"hostname": "google.com", "ip": "192.168.1.1"}],
            },
        ),
    ]

    check_result = CheckResult(module_name=mod.name, findings=findings)
    fix = mod.fix(check_result, Mode.MANUAL)

    assert fix.all_succeeded
    assert len(fix.actions) > 0
    action = fix.actions[0]
    assert "remove" in action.description.lower()


def test_fix_bank_domain_redirect():
    """Test fix() action for banking domain redirects (CRITICAL)."""
    mod = _get_module()

    findings = [
        Finding(
            title="Banking redirect",
            description="Critical",
            severity=Severity.CRITICAL,
            category="security",
            data={
                "check": "bank_domain_redirect",
                "count": 2,
                "entries": [
                    {"hostname": "paypal.com", "ip": "192.168.1.1"},
                    {"hostname": "chase.com", "ip": "10.0.0.5"},
                ],
            },
        ),
    ]

    check_result = CheckResult(module_name=mod.name, findings=findings)
    fix = mod.fix(check_result, Mode.MANUAL)

    # Should have URGENT action for bank domain
    assert fix.all_succeeded
    assert len(fix.actions) > 0
    assert any("URGENT" in a.title for a in fix.actions), "Should have URGENT action"
    assert any("immediately" in a.description.lower() for a in fix.actions)


def test_parse_empty_lines_and_tabs():
    """Test parsing handles various whitespace correctly."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "\n"
        "   \n"
        "192.168.1.1  \tmalicious.com  \n"  # extra spaces
    )

    entries = mod._parse_hosts_file(content)
    assert len(entries) == 1
    assert entries[0]["hostname"] == "malicious.com"


def test_parse_malformed_lines():
    """Test parsing handles various line formats."""
    mod = _get_module()

    content = (
        "127.0.0.1\tlocalhost\n"
        "192.168.1.1\n"  # Missing hostname - skipped (only 1 part)
        "10.0.0.1 custom.com\n"  # Space-separated - valid
        "10.0.0.2\tmalicious.com\n"
    )

    entries = mod._parse_hosts_file(content)
    # Should have entries for custom.com and malicious.com
    assert len(entries) == 2
    hostnames = {e["hostname"] for e in entries}
    assert "custom.com" in hostnames
    assert "malicious.com" in hostnames


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.hosts_file_check.") for c in declared)
