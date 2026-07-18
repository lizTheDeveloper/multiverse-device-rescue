from rescue.module_base import ModuleBase
from rescue.remediation import build_catalog, render_catalog_markdown


class _Mod(ModuleBase):
    name = "ssh_key_audit"; category = "security"; platforms = []
    emits_codes = ["security.ssh_key_audit.world_readable_key",
                   "security.ssh_key_audit.no_passphrase"]
    def check(self, profile): ...
    def fix(self, findings, mode): ...


def test_build_catalog_marks_covered_and_gaps():
    index = {"security.ssh_key_audit.world_readable_key":
             type("G", (), {"title": "Reset SSH keys"})()}
    rows = build_catalog([_Mod()], index)
    by_code = {r["code"]: r for r in rows}
    assert by_code["security.ssh_key_audit.world_readable_key"]["walkthrough_title"] == "Reset SSH keys"
    assert by_code["security.ssh_key_audit.no_passphrase"]["walkthrough_title"] is None


def test_render_markdown_has_table_and_summary():
    rows = [{"code": "security.m.a", "module": "m", "walkthrough_title": "W"},
            {"code": "security.m.b", "module": "m", "walkthrough_title": None}]
    md = render_catalog_markdown(rows)
    assert "| Code | Module | Walkthrough |" in md
    assert "**gap**" in md
    assert "1 with walkthroughs" in md
