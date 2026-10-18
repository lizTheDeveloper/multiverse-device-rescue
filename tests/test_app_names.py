"""Bundle id -> app name, read from Info.plist fixtures."""

import plistlib

from rescue import app_names
from rescue.app_names import app_rows, build_index, display_name
from rescue.known_items import item_markable
from rescue.models import Finding, Severity


def _app(folder, bundle, info):
    contents = folder / bundle / "Contents"
    contents.mkdir(parents=True)
    with open(contents / "Info.plist", "wb") as fh:
        plistlib.dump(info, fh)
    return folder / bundle


def _apps_dir(tmp_path):
    d = tmp_path / "Applications"
    d.mkdir()
    _app(d, "Caffeine.app", {"CFBundleIdentifier": "com.intelliscapesolutions.caffeine", "CFBundleName": "Caffeine"})
    _app(d, "OBS.app", {"CFBundleIdentifier": "com.obsproject.obs-studio", "CFBundleName": "OBS",
                        "CFBundleDisplayName": "OBS Studio"})
    _app(d, "zoom.us.app", {"CFBundleIdentifier": "us.zoom.xos"})  # no name: the folder's
    _app(d, "Broken.app", {"CFBundleName": "No id"})
    (d / "Junk.app" / "Contents").mkdir(parents=True)
    (d / "Junk.app" / "Contents" / "Info.plist").write_bytes(b"not a plist")
    (d / "readme.txt").write_text("x")
    return d


def test_index_prefers_display_name_then_name_then_folder(tmp_path):
    idx = build_index([str(_apps_dir(tmp_path)), str(tmp_path / "missing")])
    assert idx == {
        "com.intelliscapesolutions.caffeine": "Caffeine",
        "com.obsproject.obs-studio": "OBS Studio",
        "us.zoom.xos": "zoom.us",
    }


def test_unknown_bundle_id_keeps_its_id(tmp_path):
    idx = build_index([str(_apps_dir(tmp_path))])
    assert display_name("com.example.notinstalled", idx) == "com.example.notinstalled"


def test_path_entries_read_that_apps_plist(tmp_path):
    app = _app(tmp_path, "Tool.app", {"CFBundleIdentifier": "com.example.tool", "CFBundleName": "Tool"})
    assert display_name(str(app) + "/Contents/MacOS/tool", {}) == "Tool"
    assert display_name(str(app), {}) == "Tool"
    assert display_name("/usr/local/bin/thing", {}) == "/usr/local/bin/thing"


def test_rows_keep_every_id_sorted_by_name(tmp_path):
    idx = build_index([str(_apps_dir(tmp_path))])
    rows = app_rows(["us.zoom.xos", "com.intelliscapesolutions.caffeine", "com.x.unknown", "us.zoom.xos", 3], idx)
    assert rows == [
        {"id": "com.intelliscapesolutions.caffeine", "name": "Caffeine"},
        {"id": "com.x.unknown", "name": "com.x.unknown"},
        {"id": "us.zoom.xos", "name": "zoom.us"},
    ]


def test_markable_app_list_shows_names_and_keeps_ids(tmp_path, monkeypatch):
    monkeypatch.setattr(app_names, "_index_cache", build_index([str(_apps_dir(tmp_path))]))
    apps = ["com.intelliscapesolutions.caffeine", "com.obsproject.obs-studio", "com.x.unknown"]
    f = Finding(title="Apps with accessibility access", description="d", severity=Severity.WARNING,
                category="security", code="security.app_permissions.accessibility_access",
                data={"check": "accessibility_access", "apps": apps})
    m = item_markable(f, "app_permissions")
    assert m["shows"][0] == ["Apps", "Caffeine, com.x.unknown, OBS Studio"]
    assert m["shows"][1] == ["How many", "3"]
    assert {r["id"] for r in m["apps"]} == set(apps)
    assert m["will_change"].startswith("The checkup will stop warning you")
    assert "Device Rescue" not in m["will_change"] + " ".join(m["how_to_undo"])
    assert any(s.startswith("If you use the command line: rescue known remove") for s in m["how_to_undo"])
