"""The remote-access tool list (modules/security/remote_access_tools/data/tools.json)."""

import json
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.runtime import load_content_module

TOOLS = load_content_module(
    "modules/security/remote_access_tools/tools.py", "rescue_remote_access_tools_tools"
)

SPEC_IDS = {
    "teamviewer", "anydesk", "screenconnect", "rustdesk", "ultraviewer", "splashtop", "logmein",
    "zoho_assist", "supremo", "aeroadmin", "ammyy", "remote_utilities", "simplehelp", "hoptodesk",
    "beyondtrust", "atera", "ninjaone", "action1", "chrome_remote_desktop", "realvnc", "tightvnc",
    "ultravnc", "parsec", "quick_assist",
    # Listed by stalkerware_scan before; the spec's list missed them.
    "netsupport", "dwagent", "radmin",
}


def test_every_spec_tool_is_listed():
    ids = {t.id for t in TOOLS.load_tools()}
    assert SPEC_IDS <= ids


def test_ids_unique_and_names_nonempty():
    tools = TOOLS.load_tools()
    ids = [t.id for t in tools]
    assert len(ids) == len(set(ids))
    for t in tools:
        assert t.name.strip() and t.maker.strip()


def test_patterns_compile():
    for t in TOOLS.load_tools():
        for pattern in t.win_display_names:
            re.compile(pattern, re.I)


def test_every_tool_can_be_found_somewhere():
    for t in TOOLS.load_tools():
        assert (t.mac_bundle_ids or t.mac_app_names or t.mac_launchd or t.mac_processes
                or t.win_display_names or t.win_services or t.win_processes), t.id


def test_quick_assist_is_presence_only():
    tools = {t.id: t for t in TOOLS.load_tools()}
    assert tools["quick_assist"].presence_only is True
    assert tools["quick_assist"].win_processes
    assert not tools["quick_assist"].win_display_names
    assert [t.id for t in tools.values() if t.presence_only] == ["quick_assist"]


def test_only_teamviewer_and_anydesk_have_logs():
    tools = TOOLS.load_tools()
    with_logs = {t.id for t in tools if t.logs}
    assert with_logs == {"teamviewer", "anydesk"}
    for t in tools:
        for log in t.logs:
            assert log.platform in ("darwin", "win32")
            assert log.format in ("teamviewer_incoming", "anydesk_trace")
    by_id = {t.id: t for t in tools}
    assert {(log.platform, log.format) for log in by_id["teamviewer"].logs} == {
        ("darwin", "teamviewer_incoming"), ("win32", "teamviewer_incoming")}
    assert {(log.platform, log.format) for log in by_id["anydesk"].logs} == {
        ("darwin", "anydesk_trace"), ("win32", "anydesk_trace")}


def test_known_vendor_identifiers():
    by_id = {t.id: t for t in TOOLS.load_tools()}
    assert "com.teamviewer.TeamViewer" in by_id["teamviewer"].mac_bundle_ids
    assert "com.philandro.anydesk" in by_id["anydesk"].mac_bundle_ids
    assert any(p.startswith("com.philandro.anydesk.service") for p in by_id["anydesk"].mac_launchd)
    assert any(p.startswith("com.teamviewer.teamviewer_service") for p in by_id["teamviewer"].mac_launchd)
    assert "AnyDesk.app" in by_id["anydesk"].mac_app_names


def _write(tmp_path, tools):
    path = tmp_path / "tools.json"
    path.write_text(json.dumps({"version": "1", "last_updated": "2026-10-22", "note": "", "tools": tools}))
    return path


def test_bad_file_raises(tmp_path):
    path = _write(tmp_path, [{"id": "x", "maker": "Someone"}])
    with pytest.raises(ValueError, match="x"):
        TOOLS.load_tools(path)


def test_bad_pattern_raises(tmp_path):
    path = _write(tmp_path, [{"id": "x", "name": "X", "maker": "Someone", "win_display_names": ["("]}])
    with pytest.raises(ValueError, match="x"):
        TOOLS.load_tools(path)


def test_bad_log_format_raises(tmp_path):
    path = _write(tmp_path, [{"id": "x", "name": "X", "maker": "Someone",
                              "logs": [{"platform": "darwin", "path": "~/a", "format": "guess"}]}])
    with pytest.raises(ValueError, match="x"):
        TOOLS.load_tools(path)


def test_tool_is_frozen():
    t = TOOLS.load_tools()[0]
    with pytest.raises(Exception):
        t.name = "other"
