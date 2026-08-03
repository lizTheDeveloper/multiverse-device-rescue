import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.models import Mode, Platform, RiskLevel, Severity, SystemProfile
from rescue.registry import discover_modules

ARP_OUTPUT = """\
192.168.1.1 dev wlan0 lladdr 00:1c:42:00:00:08 REACHABLE
192.168.1.20 dev wlan0 lladdr a4:83:e7:1b:2c:3d REACHABLE
192.168.1.31 dev wlan0 lladdr de:ad:be:ef:00:01 STALE
"""

ROUTE_OUTPUT = "default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n"


def _make_profile(platform=Platform.LINUX):
    return SystemProfile(
        platform=platform,
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
    return next(m for m in modules if m.name == "lan_device_inventory")


def _fake_commands(arp=ARP_OUTPUT, route=ROUTE_OUTPUT):
    def run(command, *args, **kwargs):
        if command[:2] == ["ip", "neigh"]:
            return MagicMock(stdout=arp, returncode=0)
        if command[:2] == ["ip", "route"]:
            return MagicMock(stdout=route, returncode=0)
        return MagicMock(stdout="", returncode=0)

    return run


def test_module_discovered():
    mod = _get_module()
    assert mod.name == "lan_device_inventory"
    assert mod.category == "network"
    assert mod.risk_level == RiskLevel.SAFE
    assert set(mod.platforms) == {Platform.DARWIN, Platform.WIN32, Platform.LINUX}


def test_inventory_lists_every_device():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_commands()):
        result = mod.check(_make_profile())

    assert result.error is None
    inventory = next(
        f for f in result.findings if f.data["check"] == "lan_inventory"
    )
    assert inventory.severity == Severity.INFO
    assert inventory.data["device_count"] == 3
    macs = {device["mac"] for device in inventory.data["devices"]}
    assert macs == {"00:1c:42:00:00:08", "a4:83:e7:1b:2c:3d", "de:ad:be:ef:00:01"}


def test_inventory_labels_the_gateway_and_known_vendors():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_commands()):
        result = mod.check(_make_profile())

    devices = {
        d["mac"]: d
        for d in result.findings[0].data["devices"]
    }
    assert devices["00:1c:42:00:00:08"]["is_gateway"] is True
    assert devices["a4:83:e7:1b:2c:3d"]["vendor"] == "Apple"
    assert devices["de:ad:be:ef:00:01"]["vendor"] is None


def test_unreadable_neighbour_table_is_reported_as_unavailable_not_healthy():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("command not found")):
        result = mod.check(_make_profile())

    assert result.error is not None
    assert not result.findings


def test_known_macs_configuration_flags_only_the_rest():
    mod = _get_module()
    mod.configure({"known_macs": ["00:1C:42:0:0:8", "a4:83:e7:1b:2c:3d"]})

    with patch("subprocess.run", side_effect=_fake_commands()):
        result = mod.check(_make_profile())

    unrecognised = [
        f for f in result.findings if f.data["check"] == "unrecognised_device"
    ]
    assert len(unrecognised) == 1
    assert unrecognised[0].data["mac"] == "de:ad:be:ef:00:01"
    assert unrecognised[0].severity == Severity.WARNING


def test_expected_device_count_warns_only_when_exceeded():
    mod = _get_module()
    mod.configure({"expected_device_count": 2})
    with patch("subprocess.run", side_effect=_fake_commands()):
        exceeded = mod.check(_make_profile())
    assert any(f.data["check"] == "device_count_exceeded" for f in exceeded.findings)

    mod = _get_module()
    mod.configure({"expected_device_count": 5})
    with patch("subprocess.run", side_effect=_fake_commands()):
        within = mod.check(_make_profile())
    assert not any(f.data["check"] == "device_count_exceeded" for f in within.findings)


def test_fix_is_guidance_only():
    mod = _get_module()
    with patch("subprocess.run", side_effect=_fake_commands()):
        result = mod.check(_make_profile())
    fix = mod.fix(result, Mode.CLI)

    assert fix.actions
    assert all(action.kind.value == "guidance" for action in fix.actions)
    assert all(not action.executed for action in fix.actions)


def test_fix_does_nothing_without_findings():
    mod = _get_module()
    with patch("subprocess.run", side_effect=OSError("command not found")):
        result = mod.check(_make_profile())
    assert mod.fix(result, Mode.CLI).actions == []
