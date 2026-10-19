"""docs/commands.md must list every firewall and sharing command (no 'built at runtime')."""

import importlib.util
from pathlib import Path

ROOT = Path(__file__).parent.parent


def _gen():
    spec = importlib.util.spec_from_file_location(
        "generate_command_catalog", ROOT / "scripts" / "generate_command_catalog.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


FW = "/usr/libexec/ApplicationFirewall/socketfilterfw"


def test_firewall_rules_audit_commands_are_literal():
    commands, dynamic, _ = _gen().commands_for(ROOT / "modules/security/firewall_rules_audit")
    assert dynamic == 0
    for flag in ("--getglobalstate", "--getstealthmode", "--listapps",
                 "--getblockall", "--getallowsigned"):
        assert f"{FW} {flag}" in commands


def test_firewall_audit_commands_are_literal():
    commands, dynamic, _ = _gen().commands_for(ROOT / "modules/security/firewall_audit")
    assert dynamic == 0
    assert f"{FW} --getglobalstate" in commands
    assert f"{FW} --getstealthmode" in commands


def test_sharing_daemon_probes_are_listed():
    commands, _, _ = _gen().commands_for(ROOT / "modules/security/sharing_services")
    for label in ("com.apple.screensharing", "com.apple.smbd", "com.openssh.sshd"):
        assert f"launchctl print system/{label}" in commands
