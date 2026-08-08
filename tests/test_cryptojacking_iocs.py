import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.runtime import load_content_module

IOC_DIR = (
    Path(__file__).parent.parent / "modules" / "security" / "cryptojacking_iocs"
)
LOADER = load_content_module(
    "modules/security/cryptojacking_iocs/loader.py", "test_cryptojacking_iocs_loader"
)


def test_loader_is_importable_by_path():
    assert LOADER is not None


def test_database_loads_every_section():
    db = LOADER.load_cryptojacking_iocs(IOC_DIR)
    assert db.version != "unknown"
    assert db.miners
    assert db.pools
    assert db.pool_ports
    assert db.browser_script_domains
    assert db.browser_script_markers
    assert db.browser_extensions


def test_platform_filtering():
    db = LOADER.load_cryptojacking_iocs(IOC_DIR)
    linux_only = {m.pattern for m in db.miners_for("linux")}
    windows_only = {m.pattern for m in db.miners_for("win32")}

    assert "kdevtmpfsi" in linux_only
    assert "kdevtmpfsi" not in windows_only
    assert "xmrig" in linux_only and "xmrig" in windows_only


def test_missing_directory_degrades_to_an_empty_database():
    db = LOADER.load_cryptojacking_iocs(Path("/does/not/exist"))
    assert db.version == "unknown"
    assert db.miners == []
    assert db.pools == []


def test_data_files_are_well_formed():
    for name in ("known_miners.json", "known_pools.json", "browser_miners.json"):
        with open(IOC_DIR / name) as f:
            data = json.load(f)
        assert data["version"]

    with open(IOC_DIR / "known_miners.json") as f:
        for entry in json.load(f)["entries"]:
            assert entry["pattern"] and entry["description"]
            assert entry["severity"] in {"critical", "warning"}
            assert set(entry["platforms"]) <= {"darwin", "linux", "win32"}


def test_pool_ports_are_plausible_stratum_ports():
    db = LOADER.load_cryptojacking_iocs(IOC_DIR)
    assert 3333 in db.pool_ports
    assert all(0 < port < 65536 for port in db.pool_ports)
    # Ports shared with ordinary services would make every check noisy.
    assert not {80, 443, 22, 53} & set(db.pool_ports)
