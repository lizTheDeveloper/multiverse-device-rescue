from pathlib import Path

from rescue.tui.app import RescueApp


def test_app_loads_remediation_index(tmp_path):
    rem = tmp_path / "remediation"; rem.mkdir()
    (rem / "w.md").write_text(
        "---\ntitle: t\nestimated_time: \"5 minutes\"\n"
        "remediates:\n  - security.x.y\n"
        "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: a\n\nb\n"
    )
    app = RescueApp(modules_dir=tmp_path / "modules", guides_dir=tmp_path)
    assert "security.x.y" in app.remediation_index


def test_app_missing_guides_dir_is_empty_index(tmp_path):
    app = RescueApp(modules_dir=tmp_path / "modules", guides_dir=None)
    assert app.remediation_index == {}
