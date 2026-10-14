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
    return next(m for m in modules if m.name == "dns_poisoning_check")


def _make_subprocess_result(stdout="", stderr="", returncode=0):
    result = MagicMock()
    result.stdout = stdout
    result.stderr = stderr
    result.returncode = returncode
    return result


def _fake_run_clean_dns():
    """Clean case: using known-good public DNS (Google)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "scutil" in cmd_str and "--dns" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "resolver #0\n"
                    "  search domain[0] : local\n"
                    "  nameserver[0] : 8.8.8.8\n"
                    "  nameserver[1] : 8.8.4.4\n"
                )
            )
        elif "dig" in cmd_str and "apple.com" in cmd_str:
            return _make_subprocess_result(stdout="17.142.160.1\n")
        elif "dig" in cmd_str and "google.com" in cmd_str:
            return _make_subprocess_result(stdout="142.251.41.14\n")
        elif "dig" in cmd_str and "microsoft.com" in cmd_str:
            return _make_subprocess_result(stdout="13.107.42.14\n")
        elif "defaults read" in cmd_str and "DNSSettings" in cmd_str:
            return _make_subprocess_result(returncode=1)  # No DoH
        return _make_subprocess_result()
    return fake_run


def _fake_run_malicious_dns():
    """Malicious case: sinkhole DNS (0.0.0.0)"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "scutil" in cmd_str and "--dns" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "resolver #0\n"
                    "  search domain[0] : local\n"
                    "  nameserver[0] : 0.0.0.0\n"
                )
            )
        elif "dig" in cmd_str:
            return _make_subprocess_result(stdout="")  # No resolution
        elif "defaults read" in cmd_str and "DNSSettings" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_suspicious_dns():
    """Suspicious case: unknown/non-standard DNS"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "scutil" in cmd_str and "--dns" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "resolver #0\n"
                    "  search domain[0] : local\n"
                    "  nameserver[0] : 203.0.113.5\n"
                )
            )
        elif "dig" in cmd_str and "apple.com" in cmd_str:
            return _make_subprocess_result(stdout="17.142.160.1\n")
        elif "dig" in cmd_str and "google.com" in cmd_str:
            return _make_subprocess_result(stdout="142.251.41.14\n")
        elif "dig" in cmd_str and "microsoft.com" in cmd_str:
            return _make_subprocess_result(stdout="13.107.42.14\n")
        elif "defaults read" in cmd_str and "DNSSettings" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_bad_resolution():
    """Bad resolution: domains resolve to wrong IPs"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "scutil" in cmd_str and "--dns" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "resolver #0\n"
                    "  search domain[0] : local\n"
                    "  nameserver[0] : 8.8.8.8\n"
                )
            )
        elif "dig" in cmd_str and "apple.com" in cmd_str:
            return _make_subprocess_result(stdout="192.168.1.1\n")  # Wrong IP
        elif "dig" in cmd_str and "google.com" in cmd_str:
            return _make_subprocess_result(stdout="10.0.0.1\n")  # Wrong IP
        elif "dig" in cmd_str and "microsoft.com" in cmd_str:
            return _make_subprocess_result(stdout="172.16.0.1\n")  # Wrong IP
        elif "defaults read" in cmd_str and "DNSSettings" in cmd_str:
            return _make_subprocess_result(returncode=1)
        return _make_subprocess_result()
    return fake_run


def _fake_run_doh_enabled():
    """DoH case: DNS-over-HTTPS is enabled"""
    def fake_run(cmd, **kwargs):
        if isinstance(cmd, list):
            cmd_str = " ".join(cmd)
        else:
            cmd_str = cmd

        if "scutil" in cmd_str and "--dns" in cmd_str:
            return _make_subprocess_result(
                stdout=(
                    "resolver #0\n"
                    "  search domain[0] : local\n"
                    "  nameserver[0] : 8.8.8.8\n"
                )
            )
        elif "dig" in cmd_str and "apple.com" in cmd_str:
            return _make_subprocess_result(stdout="17.142.160.1\n")
        elif "dig" in cmd_str and "google.com" in cmd_str:
            return _make_subprocess_result(stdout="142.251.41.14\n")
        elif "dig" in cmd_str and "microsoft.com" in cmd_str:
            return _make_subprocess_result(stdout="13.107.42.14\n")
        elif "defaults read" in cmd_str and "DNSSettings" in cmd_str:
            return _make_subprocess_result(stdout="{ DoH = 1; }")  # DoH enabled
        return _make_subprocess_result()
    return fake_run


def test_dns_poisoning_check_discovered():
    """Test that module is discovered and has correct metadata."""
    mod = _get_module()
    assert mod.name == "dns_poisoning_check"
    assert mod.category == "security"
    assert mod.risk_level == RiskLevel.SAFE
    assert Platform.DARWIN in mod.platforms


def test_dns_poisoning_check_clean():
    """Test clean case: legitimate Google DNS."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_clean_dns()):
        result = mod.check(_make_profile())
    # Should not have critical or warning findings
    critical_findings = [f for f in result.findings if f.severity == Severity.CRITICAL]
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(critical_findings) == 0
    assert len(warning_findings) == 0
    # Should have at least an INFO finding about DNS config
    assert any(f.severity == Severity.INFO for f in result.findings)


def test_dns_poisoning_check_malicious():
    """Test malicious case: sinkhole DNS (0.0.0.0)."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_malicious_dns()):
        result = mod.check(_make_profile())
    # Should have CRITICAL finding for malicious DNS
    assert any(f.severity == Severity.CRITICAL for f in result.findings)
    assert any(f.data.get("check") == "malicious_dns" for f in result.findings)


def test_dns_poisoning_check_suspicious():
    """Test suspicious case: non-standard DNS."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_suspicious_dns()):
        result = mod.check(_make_profile())
    # Should have WARNING finding for suspicious DNS
    warning_findings = [f for f in result.findings if f.severity == Severity.WARNING]
    assert len(warning_findings) > 0
    assert any(f.data.get("check") == "suspicious_dns" for f in result.findings)


def test_dns_poisoning_check_bad_resolution():
    """Test bad resolution: domains resolve to unexpected IPs."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_bad_resolution()):
        result = mod.check(_make_profile())
    # Should have WARNING findings for resolution issues
    assert any(f.data.get("check") == "dns_resolution_issue" for f in result.findings)


def test_dns_poisoning_check_doh():
    """Test DoH detection."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_doh_enabled()):
        result = mod.check(_make_profile())
    # Should have INFO finding about DoH
    assert any(f.data.get("check") == "dns_over_https" for f in result.findings)


def test_dns_poisoning_check_fix_is_informational():
    """Test that fix() provides informational guidance."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_malicious_dns()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    # fix() should always succeed with informational messages
    assert fix.all_succeeded
    # Should have at least one action
    assert len(fix.actions) > 0


def test_dns_poisoning_check_fix_malicious_dns():
    """Test fix actions for malicious DNS."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_malicious_dns()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert any("Reset DNS" in a.title or "reset" in a.description.lower() for a in fix.actions)


def test_dns_poisoning_check_fix_suspicious_dns():
    """Test fix actions for suspicious DNS."""
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_run_suspicious_dns()):
        check = mod.check(_make_profile())
        fix = mod.fix(check, Mode.MANUAL)
    assert any("suspicious" in a.description.lower() for a in fix.actions)


def test_emitted_codes_are_declared():
    mod = _get_module()
    declared = set(mod.emits_codes)
    assert declared, "emits_codes must be populated"
    assert all(c.startswith("security.dns_poisoning_check.") for c in declared)


# --- false-alarm regressions -------------------------------------------------

def _run_dns(servers, resolutions):
    def fake_run(cmd, **kwargs):
        cmd_str = " ".join(cmd)
        if "scutil" in cmd_str:
            lines = "".join(f"  nameserver[{i}] : {s}\n" for i, s in enumerate(servers))
            return _make_subprocess_result(stdout="resolver #0\n" + lines)
        if cmd[0] == "dig":
            return _make_subprocess_result(stdout=resolutions.get(cmd[-1], "") + "\n")
        return _make_subprocess_result(returncode=1)

    with patch("subprocess.run", side_effect=fake_run):
        return _get_module().check(_make_profile())


_GOOD = {"apple.com": "17.142.160.1", "google.com": "142.251.41.14", "microsoft.com": "150.171.109.152"}


def test_nextdns_and_other_known_providers_not_suspicious():
    for ip in ["45.90.28.163", "45.90.30.163", "194.242.2.2", "76.76.2.0", "76.76.10.5",
               "94.140.14.14", "94.140.15.15", "9.9.9.11", "208.67.222.123", "1.1.1.3",
               "192.168.1.1", "10.0.0.1", "fe80::1"]:
        result = _run_dns([ip], _GOOD)
        assert not [f for f in result.findings if f.data.get("check") == "suspicious_dns"], ip


def test_unknown_public_dns_still_suspicious():
    result = _run_dns(["203.0.113.77"], _GOOD)
    assert any(f.data.get("check") == "suspicious_dns" for f in result.findings)


def test_cdn_resolution_outside_old_hardcoded_ranges_is_fine():
    result = _run_dns(["8.8.8.8"], _GOOD)
    assert not [f for f in result.findings if f.data.get("check") == "dns_resolution_issue"]


def test_public_domain_resolving_to_bogon_is_flagged():
    for bad in ["127.0.0.1", "169.254.1.1", "10.1.2.3", "100.64.0.1", "0.0.0.0"]:
        res = dict(_GOOD, **{"google.com": bad})
        result = _run_dns(["8.8.8.8"], res)
        assert any(f.data.get("check") == "dns_resolution_issue" for f in result.findings), bad
