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
