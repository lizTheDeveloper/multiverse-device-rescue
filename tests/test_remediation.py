from pathlib import Path

from rescue.remediation import load_remediation_walkthroughs, walkthrough_for


def _write(dir: Path, name: str, codes: list[str]) -> None:
    body = (
        "---\ntitle: \"" + name + "\"\nestimated_time: \"5 minutes\"\n"
        "remediates:\n" + "".join(f"  - {c}\n" for c in codes) +
        "automatable_steps: []\nhuman_only_steps: []\n---\n## Step 1: x\n\nb\n"
    )
    (dir / (name + ".md")).write_text(body)


def test_missing_dir_returns_empty(tmp_path):
    assert load_remediation_walkthroughs(tmp_path / "nope") == {}


def test_index_maps_codes_to_walkthrough(tmp_path):
    rem = tmp_path / "remediation"; rem.mkdir()
    _write(rem, "reset_ssh", ["security.ssh_key_audit.world_readable_key"])
    index = load_remediation_walkthroughs(rem)
    g = walkthrough_for(index, "security.ssh_key_audit.world_readable_key")
    assert g is not None and g.title == "reset_ssh"
    assert walkthrough_for(index, None) is None
    assert walkthrough_for(index, "security.unknown.code") is None


def test_conflict_first_wins(tmp_path):
    rem = tmp_path / "remediation"; rem.mkdir()
    _write(rem, "a_first", ["security.x.dup"])
    _write(rem, "b_second", ["security.x.dup"])
    index = load_remediation_walkthroughs(rem)
    # sorted filenames: a_first wins
    assert walkthrough_for(index, "security.x.dup").title == "a_first"
