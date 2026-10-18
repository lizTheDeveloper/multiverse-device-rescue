import importlib.util
from pathlib import Path

from rescue.module_base import ModuleBase
from rescue.remediation import (
    build_catalog,
    load_remediation_walkthroughs,
    render_catalog_markdown,
)


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


# --- Every serious finding must have a walkthrough --------------------------

# Codes that may be emitted at WARNING or CRITICAL but deliberately have no
# walkthrough. Each entry needs a reason. Keep this list short: the default
# answer to "this finding has no walkthrough" is to write one.
_NO_WALKTHROUGH_NEEDED: dict[str, str] = {
    # (none at present)
}


def _scan_script():
    repo = Path(__file__).resolve().parent.parent
    spec = importlib.util.spec_from_file_location(
        "uncovered_codes", repo / "scripts" / "uncovered_codes.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return repo, mod.scan()


def test_every_warning_or_critical_code_has_a_walkthrough():
    repo, found = _scan_script()
    index = load_remediation_walkthroughs(repo / "guides" / "remediation")
    # "?" means the severity is computed at runtime, so assume it can be serious.
    serious = {
        code for code, (sevs, _files) in found.items()
        if sevs & {"WARNING", "CRITICAL", "?"}
    }
    missing = sorted(
        c for c in serious if c not in index and c not in _NO_WALKTHROUGH_NEEDED)
    assert not missing, (
        "These WARNING/CRITICAL finding codes have no walkthrough in "
        "guides/remediation/ (add the code to a walkthrough's `remediates`, or "
        "list it in _NO_WALKTHROUGH_NEEDED with a reason):\n  " + "\n  ".join(missing)
    )


def test_allowlist_entries_are_still_needed():
    repo, found = _scan_script()
    index = load_remediation_walkthroughs(repo / "guides" / "remediation")
    for code in _NO_WALKTHROUGH_NEEDED:
        assert code in found, f"{code} is no longer emitted; remove it from the allowlist"
        assert code not in index, f"{code} now has a walkthrough; remove it from the allowlist"


def test_dns_walkthrough_lists_quad9_first():
    repo = Path(__file__).resolve().parent.parent
    body = (repo / "guides" / "remediation" / "encrypt_dns_lookups.md").read_text()
    assert "Quad9" in body and "Cloudflare" in body
    assert body.index("Quad9") < body.index("Cloudflare")


def test_proxy_codes_route_to_right_steps():
    repo = Path(__file__).resolve().parent.parent
    index = load_remediation_walkthroughs(repo / "guides" / "remediation")

    expect = {
        "remote_pac_url": 1,
        "pac_url_detected": 1,
        "suspicious_localhost_proxy": 2,
        "proxy_enabled": 2,
        "no_proxies": 3,
    }
    for check, step in expect.items():
        code = f"network.network_proxy_check.{check}"
        assert code in index, code
        assert [s.number for s in index[code].steps_for_code(code)] == [step], code
