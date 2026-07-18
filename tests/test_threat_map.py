from rescue.threat_map import (
    RunTarget, Threat, expand_codes, modules_for_codes,
    run_target_modules, validate_threat_map,
)

ALL_CODES = {
    "security.ai_worm_persistence.deadman_switch_launchagent",
    "security.ai_worm_persistence.known_malicious_launchagent",
    "security.ssh_key_audit.world_readable_key",
    "security.firewall_audit.firewall_disabled",
}
ALL_MODULES = {"ai_worm_persistence", "ssh_key_audit", "firewall_audit", "remote_login_check"}
PROFILES = {"ai_worm_response": {"ai_worm_persistence"}, "hygiene": {"remote_login_check"}}


def test_expand_codes_exact_glob_and_nomatch():
    assert expand_codes(["security.ssh_key_audit.world_readable_key"], ALL_CODES) == {
        "security.ssh_key_audit.world_readable_key"}
    assert expand_codes(["security.ai_worm_persistence.*"], ALL_CODES) == {
        "security.ai_worm_persistence.deadman_switch_launchagent",
        "security.ai_worm_persistence.known_malicious_launchagent"}
    assert expand_codes(["security.nope.*"], ALL_CODES) == set()


def test_modules_for_codes():
    assert modules_for_codes({"security.ssh_key_audit.world_readable_key"}) == {"ssh_key_audit"}


def test_run_target_modules_variants():
    assert run_target_modules(RunTarget(profile="ai_worm_response"), PROFILES) == {"ai_worm_persistence"}
    assert run_target_modules(RunTarget(modules=["ssh_key_audit"]), PROFILES) == {"ssh_key_audit"}
    assert run_target_modules(RunTarget(full=True), PROFILES) is None


def _threat(**kw):
    base = dict(id="t", title="T", summary="S", run=RunTarget(full=True),
                codes=["security.ssh_key_audit.world_readable_key"],
                curriculum_url="https://x", curriculum_section="Sec")
    base.update(kw)
    return Threat(**base)


def test_valid_map_has_no_errors():
    t = _threat(run=RunTarget(modules=["ssh_key_audit"]))
    assert validate_threat_map([t], PROFILES, ALL_CODES, ALL_MODULES) == []


def test_two_run_targets_errors():
    t = _threat(run=RunTarget(profile="ai_worm_response", full=True))
    assert any("exactly one" in e for e in validate_threat_map([t], PROFILES, ALL_CODES, ALL_MODULES))


def test_unknown_profile_and_module_error():
    assert any("unknown profile" in e for e in validate_threat_map(
        [_threat(run=RunTarget(profile="ghost"))], PROFILES, ALL_CODES, ALL_MODULES))
    assert any("unknown module" in e for e in validate_threat_map(
        [_threat(run=RunTarget(modules=["ghost"]))], PROFILES, ALL_CODES, ALL_MODULES))


def test_zero_resolving_code_error():
    assert any("no real code" in e for e in validate_threat_map(
        [_threat(codes=["security.ghost.x"])], PROFILES, ALL_CODES, ALL_MODULES))


def test_coverage_violation_error():
    # run target is ai_worm_response (only scans ai_worm_persistence), but the
    # code is owned by ssh_key_audit -> coverage violation.
    t = _threat(run=RunTarget(profile="ai_worm_response"),
                codes=["security.ssh_key_audit.world_readable_key"])
    assert any("does not scan" in e for e in validate_threat_map([t], PROFILES, ALL_CODES, ALL_MODULES))


def test_missing_field_and_dup_id_errors():
    assert any("missing summary" in e for e in validate_threat_map(
        [_threat(summary="")], PROFILES, ALL_CODES, ALL_MODULES))
    errs = validate_threat_map([_threat(id="dup"), _threat(id="dup")], PROFILES, ALL_CODES, ALL_MODULES)
    assert any("duplicate id" in e for e in errs)
