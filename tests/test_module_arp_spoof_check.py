import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

HEALTHY_ARP = """\
192.168.1.1 dev wlan0 lladdr 00:1c:42:00:00:08 REACHABLE
192.168.1.20 dev wlan0 lladdr a4:83:e7:1b:2c:3d REACHABLE
192.168.1.31 dev wlan0 lladdr de:ad:be:ef:00:01 STALE
"""

# The attacker's address answering both for the router and for two other hosts.
SPOOFED_ARP = """\
192.168.1.1 dev wlan0 lladdr de:ad:be:ef:00:01 REACHABLE
192.168.1.20 dev wlan0 lladdr de:ad:be:ef:00:01 REACHABLE
192.168.1.31 dev wlan0 lladdr de:ad:be:ef:00:01 REACHABLE
"""

# No gateway involved, but one address claiming several hosts.
DUPLICATE_ARP = """\
192.168.1.1 dev wlan0 lladdr 00:1c:42:00:00:08 REACHABLE
192.168.1.20 dev wlan0 lladdr 52:54:00:12:34:56 REACHABLE
192.168.1.21 dev wlan0 lladdr 52:54:00:12:34:56 REACHABLE
192.168.1.22 dev wlan0 lladdr 52:54:00:12:34:56 REACHABLE
"""

# The gateway reporting a software-generated address (locally administered bit).
LOCAL_MAC_ARP = "192.168.1.1 dev wlan0 lladdr 02:1c:42:00:00:08 REACHABLE\n"

ONE_GATEWAY = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
TWO_GATEWAYS = (
    "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"
    "default via 192.168.1.99 dev eth0 proto static metric 100\n"
)


def _make_profile():
    return SystemProfile(
        platform=Platform.LINUX,
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
    return next(m for m in modules if m.name == "arp_spoof_check")


def _fake_commands(arp, route=ONE_GATEWAY):
    def run(command, *args, **kwargs):
        if command[:2] == ["ip", "neigh"]:
            return MagicMock(stdout=arp, returncode=0)
        if command[:2] == ["ip", "route"]:
            return MagicMock(stdout=route, returncode=0)
        return MagicMock(stdout="", returncode=0)

    return run


def _check(arp, route=ONE_GATEWAY):
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_commands(arp, route)):
        return mod, mod.check(_make_profile())


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "arp_spoof_check"
    assert mod.category == "network"
    assert mod.risk_level == RiskLevel.SAFE


def test_healthy_network_has_no_findings():
    _, result = _check(HEALTHY_ARP)
    assert result.error is None
    assert not result.has_issues


def test_gateway_impersonation_is_critical():
    _, result = _check(SPOOFED_ARP)
    impersonation = [
        f for f in result.findings if f.data["check"] == "gateway_impersonation"
    ]
    assert len(impersonation) == 1
    assert impersonation[0].severity == Severity.CRITICAL
    assert impersonation[0].data["mac"] == "de:ad:be:ef:00:01"
    assert sorted(impersonation[0].data["other_ips"]) == ["192.168.1.20", "192.168.1.31"]


def test_gateway_impersonation_is_not_double_reported_as_a_duplicate():
    _, result = _check(SPOOFED_ARP)
    assert not any(f.data["check"] == "duplicate_mac" for f in result.findings)


def test_duplicate_mac_without_the_gateway_is_a_low_confidence_warning():
    _, result = _check(DUPLICATE_ARP)
    duplicates = [f for f in result.findings if f.data["check"] == "duplicate_mac"]
    assert len(duplicates) == 1
    assert duplicates[0].severity == Severity.WARNING
    assert duplicates[0].data["confidence"] == "low"


def test_two_addresses_for_one_device_is_below_the_threshold():
    arp = (
        "192.168.1.20 dev wlan0 lladdr 52:54:00:12:34:56 REACHABLE\n"
        "192.168.1.21 dev wlan0 lladdr 52:54:00:12:34:56 REACHABLE\n"
    )
    _, result = _check(arp)
    assert not any(f.data["check"] == "duplicate_mac" for f in result.findings)


def test_locally_administered_gateway_address_is_flagged():
    _, result = _check(LOCAL_MAC_ARP)
    flagged = [
        f
        for f in result.findings
        if f.data["check"] == "locally_administered_gateway"
    ]
    assert len(flagged) == 1
    assert flagged[0].data["mac"] == "02:1c:42:00:00:08"


def test_multiple_default_gateways_are_flagged():
    _, result = _check(HEALTHY_ARP, route=TWO_GATEWAYS)
    flagged = [f for f in result.findings if f.data["check"] == "multiple_gateways"]
    assert len(flagged) == 1
    assert flagged[0].data["gateways"] == ["192.168.1.1", "192.168.1.99"]


def test_unreadable_neighbour_table_is_reported_as_unavailable():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("command not found")):
        result = mod.check(_make_profile())
    assert result.error is not None
    assert not result.findings


def test_fix_leads_with_containment_and_is_guidance_only():
    mod, result = _check(SPOOFED_ARP)
    fix = mod.fix(result, Mode.CLI)

    assert all(action.kind.value == "guidance" for action in fix.actions)
    assert "sensitive" in fix.actions[0].title.lower()


def test_fix_does_nothing_on_a_healthy_network():
    mod, result = _check(HEALTHY_ARP)
    assert mod.fix(result, Mode.CLI).actions == []
