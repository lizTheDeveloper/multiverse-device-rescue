import sys

from rescue import runtime


def test_content_file_prefers_applied_content(monkeypatch, tmp_path):
    content_root = tmp_path / "content"
    (content_root / ".git").mkdir(parents=True)
    (content_root / ".git" / "rescue-applied-head").write_text("abc123")
    (content_root / "manifest.json").write_text("{}")
    data_file = content_root / "modules" / "example.json"
    data_file.parent.mkdir()
    data_file.write_text("updated")
    bundled_root = tmp_path / "bundled"
    (bundled_root / "modules").mkdir(parents=True)
    (bundled_root / "modules" / "example.json").write_text("bundled")

    monkeypatch.setenv("RESCUE_CONTENT_DIR", str(content_root))
    monkeypatch.setattr(runtime, "bundled_root", lambda: bundled_root)

    assert runtime.content_file("modules/example.json") == data_file


def test_content_file_uses_bundled_content_without_applied_marker(monkeypatch, tmp_path):
    content_root = tmp_path / "content"
    content_root.mkdir()
    bundled_root = tmp_path / "bundled"
    (bundled_root / "guides").mkdir(parents=True)
    bundled_file = bundled_root / "guides" / "phase.md"
    bundled_file.write_text("bundled")

    monkeypatch.setenv("RESCUE_CONTENT_DIR", str(content_root))
    monkeypatch.setattr(runtime, "bundled_root", lambda: bundled_root)

    assert runtime.content_file("guides/phase.md") == bundled_file


def test_load_content_module_imports_a_helper_by_path(monkeypatch, tmp_path):
    bundled_root = tmp_path / "bundled"
    helper = bundled_root / "modules" / "helper.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("VALUE = 7\n\n\ndef double(n):\n    return n * 2\n")

    monkeypatch.setattr(runtime, "bundled_root", lambda: bundled_root)

    module = runtime.load_content_module("modules/helper.py", "test_helper_module")
    try:
        assert module is not None
        assert module.VALUE == 7
        assert module.double(4) == 8
    finally:
        sys.modules.pop("test_helper_module", None)


def test_load_content_module_reuses_an_already_loaded_helper(monkeypatch, tmp_path):
    bundled_root = tmp_path / "bundled"
    helper = bundled_root / "modules" / "helper.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("VALUE = 1\n")

    monkeypatch.setattr(runtime, "bundled_root", lambda: bundled_root)

    first = runtime.load_content_module("modules/helper.py", "test_helper_cached")
    try:
        helper.write_text("VALUE = 2\n")
        second = runtime.load_content_module("modules/helper.py", "test_helper_cached")
        assert second is first
        assert second.VALUE == 1
    finally:
        sys.modules.pop("test_helper_cached", None)


def test_load_content_module_returns_none_for_a_missing_file(monkeypatch, tmp_path):
    monkeypatch.setattr(runtime, "bundled_root", lambda: tmp_path)
    assert runtime.load_content_module("modules/absent.py", "test_helper_absent") is None


def test_load_content_module_does_not_leave_a_broken_helper_registered(
    monkeypatch, tmp_path
):
    bundled_root = tmp_path / "bundled"
    helper = bundled_root / "modules" / "broken.py"
    helper.parent.mkdir(parents=True)
    helper.write_text("raise RuntimeError('boom')\n")

    monkeypatch.setattr(runtime, "bundled_root", lambda: bundled_root)

    assert runtime.load_content_module("modules/broken.py", "test_helper_broken") is None
    assert "test_helper_broken" not in sys.modules
