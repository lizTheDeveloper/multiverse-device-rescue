"""Every couldn't-check code from the false-report audit shares its parent's walkthrough."""

import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from rescue.remediation import load_remediation_walkthroughs

ROOT = Path(__file__).parent.parent

PAIRS = {
    "security.firewall_rules_audit.alf_unknown": "security.firewall_rules_audit.alf_disabled",
    "security.firewall_rules_audit.stealth_unknown": "security.firewall_rules_audit.stealth_disabled",
    "security.firewall_audit.global_state_unknown": "security.firewall_audit.global_state",
    "security.firewall_audit.stealth_mode_unknown": "security.firewall_audit.stealth_mode",
    "security.lock_screen_check.screensaver_password_unknown":
        "security.lock_screen_check.screensaver_password",
    "security.appleid_security_check.icloud_keychain_unknown":
        "security.appleid_security_check.icloud_keychain",
    "security.appleid_security_check.autoupdate_unknown":
        "security.appleid_security_check.autoupdate_disabled",
    "security.remote_login_check.remote_access_unknown": "security.remote_login_check.ssh_enabled",
    "security.sharing_services.sharing_unknown": "security.sharing_services.remote_login",
    "security.sharing_preferences_audit.sharing_unknown":
        "security.sharing_preferences_audit.remote_login",
}


@pytest.mark.parametrize("code, parent", sorted(PAIRS.items()))
def test_unknown_code_maps_to_parent_walkthrough(code, parent):
    index = load_remediation_walkthroughs(ROOT / "guides" / "remediation")
    assert code in index, f"{code} has no walkthrough"
    assert index[code].title == index[parent].title
