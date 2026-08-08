import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.runtime import load_content_module

NEIGHBORS = load_content_module(
    "modules/network/lan_common/neighbors.py", "test_lan_common_neighbors"
)

DARWIN_ARP = """\
? (192.168.1.1) at 0:1c:42:0:0:8 on en0 ifscope [ethernet]
? (192.168.1.42) at a4:83:e7:1b:2c:3d on en0 ifscope [ethernet]
? (192.168.1.255) at ff:ff:ff:ff:ff:ff on en0 ifscope [ethernet]
? (224.0.0.251) at 1:0:5e:0:0:fb on en0 ifscope permanent [ethernet]
"""

LINUX_NEIGH = """\
192.168.1.1 dev wlan0 lladdr 00:1c:42:00:00:08 REACHABLE
192.168.1.42 dev wlan0 lladdr a4:83:e7:1b:2c:3d STALE
192.168.1.77 dev wlan0  FAILED
"""

WINDOWS_ARP = """\

Interface: 192.168.1.5 --- 0x5
  Internet Address      Physical Address      Type
  192.168.1.1           00-1C-42-00-00-08     dynamic
  192.168.1.42          A4-83-E7-1B-2C-3D     dynamic
  192.168.1.255         ff-ff-ff-ff-ff-ff     static
"""


def test_normalise_mac_pads_and_lowercases():
    assert NEIGHBORS.normalise_mac("0:1C:42:0:0:8") == "00:1c:42:00:00:08"
    assert NEIGHBORS.normalise_mac("A4-83-E7-1B-2C-3D") == "a4:83:e7:1b:2c:3d"


def test_normalise_mac_leaves_unparseable_values_alone():
    assert NEIGHBORS.normalise_mac("not-a-mac") == "not-a-mac"


def test_darwin_arp_parsing_skips_broadcast_and_multicast():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=DARWIN_ARP, returncode=0)
        neighbors = NEIGHBORS.read_neighbors("darwin")

    assert [n.ip for n in neighbors] == ["192.168.1.1", "192.168.1.42"]
    assert neighbors[0].mac == "00:1c:42:00:00:08"
    assert neighbors[0].interface == "en0"


def test_linux_neigh_parsing_skips_entries_without_a_hardware_address():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=LINUX_NEIGH, returncode=0)
        neighbors = NEIGHBORS.read_neighbors("linux")

    assert [n.ip for n in neighbors] == ["192.168.1.1", "192.168.1.42"]
    assert neighbors[1].interface == "wlan0"


def test_windows_arp_parsing_records_the_interface_address():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=WINDOWS_ARP, returncode=0)
        neighbors = NEIGHBORS.read_neighbors("win32")

    assert [n.ip for n in neighbors] == ["192.168.1.1", "192.168.1.42"]
    assert all(n.interface == "192.168.1.5" for n in neighbors)


def test_platform_without_support_returns_nothing():
    assert NEIGHBORS.read_neighbors("plan9") == []


def test_locally_administered_bit_detection():
    vendor_assigned = NEIGHBORS.Neighbor(
        ip="192.168.1.1", mac="00:1c:42:00:00:08", interface="en0"
    )
    software_generated = NEIGHBORS.Neighbor(
        ip="192.168.1.1", mac="02:1c:42:00:00:08", interface="en0"
    )
    assert not vendor_assigned.is_locally_administered
    assert software_generated.is_locally_administered


def test_linux_gateway_parsing():
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(
            stdout="default via 192.168.1.1 dev wlan0 proto dhcp metric 600\n",
            returncode=0,
        )
        gateways = NEIGHBORS.read_gateways("linux")

    assert len(gateways) == 1
    assert gateways[0].ip == "192.168.1.1"
    assert gateways[0].interface == "wlan0"


def test_darwin_gateway_parsing():
    output = "   route to: default\n  gateway: 192.168.1.1\ninterface: en0\n"
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=output, returncode=0)
        gateways = NEIGHBORS.read_gateways("darwin")

    assert gateways[0].ip == "192.168.1.1"
    assert gateways[0].interface == "en0"


def test_windows_gateway_parsing_deduplicates():
    output = (
        "IPv4 Route Table\n"
        "Network Destination        Netmask          Gateway       Interface  Metric\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.5     25\n"
        "          0.0.0.0          0.0.0.0      192.168.1.1     192.168.1.5     25\n"
        "      192.168.1.0    255.255.255.0         On-link      192.168.1.5    281\n"
    )
    with patch("subprocess.run") as mock_run:
        mock_run.return_value = MagicMock(stdout=output, returncode=0)
        gateways = NEIGHBORS.read_gateways("win32")

    assert [g.ip for g in gateways] == ["192.168.1.1"]


def test_command_failure_degrades_to_empty():
    with patch("subprocess.run", side_effect=OSError("no such command")):
        assert NEIGHBORS.read_neighbors("linux") == []
        assert NEIGHBORS.read_gateways("linux") == []


def test_vendor_lookup_uses_the_bundled_oui_table():
    vendors = NEIGHBORS.load_oui_vendors()
    assert vendors, "the bundled OUI table should not be empty"
    assert NEIGHBORS.vendor_for("a4:83:e7:1b:2c:3d", vendors) == "Apple"
    assert NEIGHBORS.vendor_for("de:ad:be:ef:00:01", vendors) is None
