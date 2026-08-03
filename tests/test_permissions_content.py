import json
from pathlib import Path

DOC = Path(__file__).parent.parent / "shared" / "permissions-content.json"

def test_permissions_content_covers_each_os_with_required_fields():
    data = json.loads(DOC.read_text())
    for os_key in ("macos", "windows", "linux"):
        assert os_key in data and data[os_key], f"missing {os_key}"
        for step in data[os_key]:
            assert step["title"] and step["body"]

def test_macos_mentions_gatekeeper_and_full_disk_access():
    data = json.loads(DOC.read_text())
    blob = json.dumps(data["macos"]).lower()
    assert "open anyway" in blob
    assert "full disk access" in blob
