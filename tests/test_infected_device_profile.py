"""infected_device: a clearly infected computer, kept off the internet, scanned
with the app installed from a USB Rescue Stick."""
import json
from pathlib import Path

from click.testing import CliRunner

from rescue.guides import discover_guides
from rescue.profiles import filter_modules_by_profile, load_profile, validate_profile_modules
from rescue.registry import discover_modules

PROJECT_ROOT = Path(__file__).parent.parent
PROFILE_PATH = PROJECT_ROOT / "profiles" / "infected_device.yaml"
GUIDES_DIR = PROJECT_ROOT / "guides"
MODULES_DIR = PROJECT_ROOT / "modules"

# Checks that only make sense with a network, or reach out to one.
NEEDS_A_NETWORK = {
    "router_security_audit", "lan_device_inventory", "arp_spoof_check", "wifi_security_audit",
    "network_diagnostics", "network_speed_test", "network_quality", "update_checker",
    "win_updates", "win_windows_update_status", "linux_package_updates", "vpn_leak_check",
    "dns_over_https_check", "airport_wifi_scan", "mvt_spyware_scan",
}


def _matched():
    profile = load_profile(PROFILE_PATH)
    return {m.name for m in filter_modules_by_profile(discover_modules(MODULES_DIR), profile)}


def test_profile_loads_and_names_its_guide():
    profile = load_profile(PROFILE_PATH)
    assert profile.name == "infected_device"
    assert profile.guides == ["infected_device"]
    validate_profile_modules(profile, discover_modules(MODULES_DIR))


def test_it_looks_where_malware_persists_on_every_platform():
    matched = _matched()
    assert {"launch_agent_audit", "launchd_persistence_audit", "scheduled_tasks_audit"} <= matched
    assert {"win_autoruns_audit", "win_scheduled_tasks_security"} <= matched
    assert "linux_persistence_audit" in matched
    assert {"stalkerware_scan", "keylogger_indicators", "win_remote_access_audit"} <= matched
    assert {"malware_scan_indicators", "win_malware_indicators"} <= matched


def test_it_leaves_out_checks_that_need_a_network():
    assert not (_matched() & NEEDS_A_NETWORK)


def test_the_ai_tools_check_never_downloads_here():
    profile = load_profile(PROFILE_PATH)
    assert "ai_agent_audit" in profile.include_modules
    assert profile.module_config["ai_agent_audit"] == {"downloads": False}


def test_scan_with_the_profile_never_fetches(tmp_path, monkeypatch):
    """End to end through the CLI: the profile's config reaches the module."""
    monkeypatch.setenv("RESCUE_CACHE_DIR", str(tmp_path / "cache"))
    monkeypatch.delenv("RESCUE_NO_DOWNLOADS", raising=False)
    from rescue import orchestrator

    real = orchestrator.discover_modules

    def only_ai(path):
        return [m for m in real(path) if m.name == "ai_agent_audit"]

    monkeypatch.setattr(orchestrator, "discover_modules", only_ai)
    # validate_profile_modules sees only the AI check too, so check it separately above.
    monkeypatch.setattr(orchestrator, "validate_profile_modules", lambda *a, **k: None)
    from rescue.cli import main

    out = CliRunner().invoke(main, ["scan", "--json", "--no-attribution", "--profile", "infected_device"])
    assert out.exit_code == 0, out.output
    doc = json.loads(out.stdout)
    [mod] = doc["modules"]
    reasons = [f["data"].get("reason") for f in mod["findings"]]
    # Elevated runs and leftover HackMyAgent settings refuse earlier; otherwise it's kept_offline.
    assert set(reasons) <= {"kept_offline", "elevated", "hackmyagent_settings", "manifest_missing"}, reasons


def test_guide_starts_by_isolating_and_ends_with_accounts_from_a_clean_device():
    guides = discover_guides(GUIDES_DIR, "infected_device")
    assert guides, "guides/infected_device has no phases"
    first = guides[0]
    assert first.automatable_steps == []
    assert "network" in first.steps[0].title.lower() or "internet" in first.steps[0].title.lower()
    last_text = "\n".join(s.title + s.body for s in guides[-1].steps).lower()
    assert "different" in last_text and "digital_security_reset" in last_text
