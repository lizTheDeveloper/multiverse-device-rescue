import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def test_load_iocs_parses_all_files():
    """IOC loader parses all JSON files and returns populated IOCDatabase."""
    from modules.security.ai_worm_iocs.loader import load_iocs

    db = load_iocs()
    assert db is not None
    assert isinstance(db.domains, list)
    assert isinstance(db.ips, list)
    assert isinstance(db.hashes, dict)
    assert isinstance(db.paths, list)
    assert isinstance(db.git_patterns, list)
    assert isinstance(db.mcp_servers, list)


def test_load_iocs_caches_result():
    """Calling load_iocs() twice returns the same object (cached)."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db1 = load_iocs()
    db2 = load_iocs()
    assert db1 is db2
    _clear_cache()


def test_load_iocs_known_paths_have_required_fields():
    """Every path IOC entry has threat, severity, description, source."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    for entry in db.paths:
        assert entry.path, "path must not be empty"
        assert entry.threat, "threat must not be empty"
        assert entry.severity in ("critical", "warning", "info")
        assert entry.description, "description must not be empty"
        assert entry.source, "source must not be empty"
    _clear_cache()


def test_load_iocs_known_domains_have_required_fields():
    """Every domain IOC entry has value, severity, threat, description."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    for entry in db.domains:
        assert entry.value, "value must not be empty"
        assert entry.threat, "threat must not be empty"
        assert entry.severity in ("critical", "warning", "info")
        assert entry.description, "description must not be empty"
    _clear_cache()


def test_load_iocs_known_hashes_have_required_fields():
    """Every hash IOC entry has sha256, threat, severity, description, source."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    for sha256, entry in db.hashes.items():
        assert len(sha256) == 64, "hash must be SHA256 (64 hex chars)"
        assert entry.threat, "threat must not be empty"
        assert entry.source, "source must not be empty"
    _clear_cache()


def test_load_iocs_custom_data_dir(tmp_path):
    """IOC loader can load from a custom directory."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    # Create minimal IOC files
    manifest = {"version": "0.0.1", "last_updated": "2026-07-09"}
    (tmp_path / "manifest.json").write_text(json.dumps(manifest))
    for name in [
        "known_hashes",
        "known_domains",
        "known_ips",
        "known_paths",
        "known_git_patterns",
        "known_mcp_servers",
    ]:
        (tmp_path / f"{name}.json").write_text(
            json.dumps({"version": "0.0.1", "entries": []})
        )

    _clear_cache()
    db = load_iocs(data_dir=tmp_path)
    assert len(db.domains) == 0
    assert len(db.paths) == 0
    _clear_cache()


def test_load_iocs_manifest_version():
    """Manifest version is accessible on the IOCDatabase."""
    from modules.security.ai_worm_iocs.loader import load_iocs, _clear_cache

    _clear_cache()
    db = load_iocs()
    assert db.version, "version must be set from manifest"
    _clear_cache()
