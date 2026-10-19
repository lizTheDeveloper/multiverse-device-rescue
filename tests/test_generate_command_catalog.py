"""The generated command catalog follows helpers and reports sockets."""

from __future__ import annotations

import importlib.util
import re
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "generate_command_catalog", REPO_ROOT / "scripts" / "generate_command_catalog.py"
)
gen = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(gen)


def _section(text: str, name: str) -> str:
    match = re.search(rf"### `{name}`\n(.*?)(?=\n### |\n## |\Z)", text, re.S)
    assert match, name
    return match.group(1)


def test_lan_device_inventory_lists_neighbor_commands():
    section = _section(gen.render(), "lan_device_inventory")
    for command in ("arp -a -n", "ip neigh show", "route -n get default", "route print -4"):
        assert command in section
    assert "Runs no external commands" not in section


def test_helper_param_call_not_counted_dynamic():
    assert "built at runtime" not in _section(gen.render(), "lan_common")


def test_router_audit_mentions_sockets():
    section = _section(gen.render(), "router_security_audit")
    assert "Also opens network connections directly from Python (sockets), without an external command." in section


def test_catalog_is_fresh(monkeypatch):
    monkeypatch.setattr(sys, "argv", ["generate_command_catalog.py", "--check"])
    assert gen.main() == 0
