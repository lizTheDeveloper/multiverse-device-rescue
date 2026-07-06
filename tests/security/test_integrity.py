from rescue.security.integrity import (
    IntegrityManifest,
    compute_package_manifest,
    verify_package_integrity,
    write_integrity_manifest,
)


def _make_package(tmp_path):
    pkg = tmp_path / "rescue"
    pkg.mkdir()
    (pkg / "__init__.py").write_text("VERSION = 1\n")
    (pkg / "cli.py").write_text("def main(): pass\n")
    sub = pkg / "profiler"
    sub.mkdir()
    (sub / "__init__.py").write_text("")
    (sub / "base.py").write_text("def gather(): pass\n")
    return pkg


def test_compute_package_manifest_hashes_all_py_files(tmp_path):
    pkg = _make_package(tmp_path)

    manifest = compute_package_manifest(pkg)

    assert set(manifest.files.keys()) == {
        "__init__.py", "cli.py", "profiler/__init__.py", "profiler/base.py",
    }
    assert all(len(h) == 64 for h in manifest.files.values())


def test_verify_package_integrity_ok_when_unchanged(tmp_path):
    pkg = _make_package(tmp_path)
    manifest = compute_package_manifest(pkg)

    result = verify_package_integrity(pkg, manifest)

    assert result.ok
    assert result.tampered == []
    assert result.missing == []


def test_verify_package_integrity_detects_tampered_file(tmp_path):
    pkg = _make_package(tmp_path)
    manifest = compute_package_manifest(pkg)

    (pkg / "cli.py").write_text("def main(): print('malicious')\n")

    result = verify_package_integrity(pkg, manifest)

    assert not result.ok
    assert result.tampered == ["cli.py"]
    assert result.missing == []


def test_verify_package_integrity_detects_missing_file(tmp_path):
    pkg = _make_package(tmp_path)
    manifest = compute_package_manifest(pkg)

    (pkg / "profiler" / "base.py").unlink()

    result = verify_package_integrity(pkg, manifest)

    assert not result.ok
    assert result.missing == ["profiler/base.py"]


def test_verify_package_integrity_reports_added_files_without_failing(tmp_path):
    pkg = _make_package(tmp_path)
    manifest = compute_package_manifest(pkg)

    (pkg / "new_module.py").write_text("# unexpected new file\n")

    result = verify_package_integrity(pkg, manifest)

    assert result.ok  # added-only is not itself a failure, just reported
    assert result.added == ["new_module.py"]


def test_manifest_json_roundtrip(tmp_path):
    pkg = _make_package(tmp_path)
    manifest = compute_package_manifest(pkg)

    restored = IntegrityManifest.from_json_bytes(manifest.to_json_bytes())

    assert restored == manifest


def test_write_integrity_manifest_creates_loadable_file(tmp_path):
    pkg = _make_package(tmp_path)
    output = tmp_path / "integrity_manifest.json"

    write_integrity_manifest(pkg, output)

    loaded = IntegrityManifest.from_json_bytes(output.read_bytes())
    assert set(loaded.files.keys()) == {
        "__init__.py", "cli.py", "profiler/__init__.py", "profiler/base.py",
    }
