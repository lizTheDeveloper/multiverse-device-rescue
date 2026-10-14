"""Background jobs are where stalkerware and malware persist. The situations a
frightened person picks in the app must look at them, not only the full scan."""
from pathlib import Path

import yaml

PROFILES = Path(__file__).resolve().parent.parent / "profiles"
BACKGROUND_JOB_CHECKS = {"launch_agent_audit", "launchd_persistence_audit", "scheduled_tasks_audit"}


def _includes(name):
    return set(yaml.safe_load((PROFILES / f"{name}.yaml").read_text())["modules"]["include"])


def test_hacked_and_watched_check_background_jobs_and_spyware_signals():
    included = _includes("digital_security_reset")
    assert BACKGROUND_JOB_CHECKS <= included
    assert {"keylogger_indicators", "privacy_permissions_audit"} <= included


def test_sketchy_install_checks_background_jobs():
    assert BACKGROUND_JOB_CHECKS <= _includes("ai_worm_response")
