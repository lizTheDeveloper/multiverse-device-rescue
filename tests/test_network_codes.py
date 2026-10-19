"""Finding codes for the network checks, shared by every network module's tests.

Each task that gives a network module its codes adds that module's entry to
EXPECTED_CODES. Per-module test files import assert_codes_match_check.
"""

import re
from pathlib import Path

import pytest

from rescue.registry import discover_modules

EXPECTED_CODES: dict[str, set[str]] = {
    "ethernet_diagnostics": {
        "network.ethernet_diagnostics.no_ethernet",
        "network.ethernet_diagnostics.interface_inactive",
        "network.ethernet_diagnostics.self_assigned_ip",
        "network.ethernet_diagnostics.non_standard_mtu",
        "network.ethernet_diagnostics.link_speed_mismatch",
        "network.ethernet_diagnostics.high_packet_errors",
        "network.ethernet_diagnostics.ethernet_summary",
    },
    "arp_spoof_check": {
        "network.arp_spoof_check.gateway_impersonation",
        "network.arp_spoof_check.duplicate_mac",
        "network.arp_spoof_check.locally_administered_gateway",
        "network.arp_spoof_check.multiple_gateways",
    },
    "lan_device_inventory": {
        "network.lan_device_inventory.lan_inventory",
        "network.lan_device_inventory.unrecognised_device",
        "network.lan_device_inventory.device_count_exceeded",
    },
    "router_security_audit": {
        "network.router_security_audit.admin_service_open",
        "network.router_security_audit.upnp_enabled",
        "network.router_security_audit.router_manual_review",
    },
    "dns_over_https_check": {
        "network.dns_over_https_check.dns_configuration",
        "network.dns_over_https_check.unencrypted_dns",
        "network.dns_over_https_check.encrypted_dns_provider",
        "network.dns_over_https_check.no_dns_found",
        "network.dns_over_https_check.encrypted_dns_profile",
        "network.dns_over_https_check.local_dns_resolver",
        "network.dns_over_https_check.doh_tls_configured",
        "network.dns_over_https_check.no_encryption_configured",
    },
    "wifi_security_audit": {
        "network.wifi_security_audit.wep_connected",
        "network.wifi_security_audit.open_network_connected",
        "network.wifi_security_audit.wpa2_only",
        "network.wifi_security_audit.hidden_network",
        "network.wifi_security_audit.wep_saved",
        "network.wifi_security_audit.open_saved",
        "network.wifi_security_audit.wifi_summary",
        "network.wifi_security_audit.security_unknown",
    },
    "vpn_leak_check": {
        "network.vpn_leak_check.no_vpns_configured",
        "network.vpn_leak_check.vpn_config_summary",
        "network.vpn_leak_check.dns_leak",
        "network.vpn_leak_check.split_tunneling",
        "network.vpn_leak_check.vpn_not_connected",
    },
    "network_proxy_check": {
        "network.network_proxy_check.network_query_failed",
        "network.network_proxy_check.remote_pac_url",
        "network.network_proxy_check.pac_url_detected",
        "network.network_proxy_check.suspicious_localhost_proxy",
        "network.network_proxy_check.proxy_enabled",
        "network.network_proxy_check.proxy_bypass_domains",
        "network.network_proxy_check.proxy_config_summary",
        "network.network_proxy_check.no_proxies",
    },
}


def load_module(name):
    modules_dir = Path(__file__).parent.parent / "modules"
    return next(m for m in discover_modules(modules_dir) if m.name == name)


def assert_codes_match_check(findings, module_name):
    """Every finding's code is network.<module>.<its data["check"]>."""
    assert findings, "expected at least one finding to check"
    for f in findings:
        assert f.code == f"network.{module_name}.{f.data['check']}", f.title


@pytest.mark.parametrize("name", sorted(EXPECTED_CODES))
def test_declared_codes(name):
    mod = load_module(name)
    assert set(mod.emits_codes) == EXPECTED_CODES[name]


_WALKTHROUGHS = [
    "encrypt_dns_lookups",
    "review_unknown_lan_devices",
    "secure_home_router",
    "secure_wifi_connection",
    "fix_vpn_leaks",
    "remove_unwanted_proxy",
    "fix_ethernet_connection",
    "read_a_connection_watch",
    "review_open_ports",
    "review_network_connections",
    "triage_suspicious_connections",
]


@pytest.mark.parametrize("stem", _WALKTHROUGHS)
def test_step_references_stay_inside_each_codes_view(stem):
    import re

    from rescue.guides import load_guide

    guide = load_guide(
        Path(__file__).parent.parent / "guides" / "remediation" / f"{stem}.md"
    )
    for code in guide.remediates:
        shown = guide.steps_for_code(code)
        numbers = {s.number for s in shown}
        for step in shown:
            for ref in re.findall(r"\bSteps? (\d+)", step.body):
                assert int(ref) in numbers, (code, step.number, ref)
            for a, b in re.findall(r"\bSteps (\d+) and (\d+)", step.body):
                assert int(a) in numbers and int(b) in numbers, (code, step.number)


# Walkthroughs for the connection checks and the connection watch: none of
# them tells anyone to kill, end or terminate a program.
_CONNECTION_WALKTHROUGHS = [
    "read_a_connection_watch",
    "review_open_ports",
    "review_network_connections",
    "triage_suspicious_connections",
]


@pytest.mark.parametrize("stem", _CONNECTION_WALKTHROUGHS)
def test_connection_walkthroughs_never_say_kill(stem):
    import re

    text = (
        Path(__file__).parent.parent / "guides" / "remediation" / f"{stem}.md"
    ).read_text(encoding="utf-8")
    assert not re.search(r"\bkill|\bterminat|\bend (the|that|this) (process|program)|\bend task", text, re.I)


@pytest.mark.parametrize("stem", _CONNECTION_WALKTHROUGHS)
def test_connection_walkthroughs_give_every_code_its_own_steps(stem):
    import frontmatter

    from rescue.guides import load_guide

    path = Path(__file__).parent.parent / "guides" / "remediation" / f"{stem}.md"
    assert set(frontmatter.load(path).metadata["platforms"]) == {"macos", "windows", "linux"}
    guide = load_guide(path)
    for code in guide.remediates:
        assert guide.steps_for.get(code), code


def test_open_ports_stop_service_step_works_as_written():
    """The listening-ports view says sudo for systemctl and how to find the service name."""
    from rescue.guides import load_guide

    guide = load_guide(
        Path(__file__).parent.parent / "guides" / "remediation" / "review_open_ports.md"
    )
    body = " ".join(
        " ".join(s.body.split())
        for s in guide.steps_for_code("security.open_ports_scan.listening_ports")
    )
    assert "`sudo systemctl disable --now <service>`" in body
    assert "`systemctl status <pid>`" in body
    for path in (Path(__file__).parent.parent / "guides").rglob("*.md"):
        text = " ".join(path.read_text(encoding="utf-8").split())
        assert not re.search(r"(?<!sudo )`?systemctl (disable|stop|mask)", text), path.name
