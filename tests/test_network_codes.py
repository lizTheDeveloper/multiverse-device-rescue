"""Finding codes for the network checks, shared by every network module's tests.

Each task that gives a network module its codes adds that module's entry to
EXPECTED_CODES. Per-module test files import assert_codes_match_check.
"""

from pathlib import Path

import pytest

from rescue.registry import discover_modules

EXPECTED_CODES: dict[str, set[str]] = {
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
