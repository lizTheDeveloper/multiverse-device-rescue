import json

import pytest

from rescue.update.manifest import ManifestError, load_content_manifest, validate_content_paths


def test_load_content_manifest_parses_fields(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({
        "content_version": "2026.07.10-1",
        "updated_at": "2026-07-10T00:00:00Z",
        "modules": ["bloatware/known_bloatware.json"],
        "guides": ["six_roses/phase1.md"],
    }))

    manifest = load_content_manifest(tmp_path)

    assert manifest.content_version == "2026.07.10-1"
    assert manifest.modules == ["bloatware/known_bloatware.json"]
    assert manifest.guides == ["six_roses/phase1.md"]


def test_load_content_manifest_missing_file_raises(tmp_path):
    with pytest.raises(ManifestError, match="manifest.json"):
        load_content_manifest(tmp_path)


def test_load_content_manifest_malformed_json_raises(tmp_path):
    (tmp_path / "manifest.json").write_text("{not valid json")
    with pytest.raises(ManifestError):
        load_content_manifest(tmp_path)


def test_load_content_manifest_missing_required_key_raises(tmp_path):
    (tmp_path / "manifest.json").write_text(json.dumps({"content_version": "1.0"}))
    with pytest.raises(ManifestError, match="updated_at"):
        load_content_manifest(tmp_path)


@pytest.mark.parametrize("path", ["modules/unsafe.py", "../modules/list.json", "other/data.json"])
def test_validate_content_paths_rejects_unsafe_content(path):
    with pytest.raises(ManifestError):
        validate_content_paths([path])
