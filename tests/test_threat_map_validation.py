from rescue.cli import _get_modules_dir, _get_profiles_dir, _project_root
from rescue.profiles import discover_profiles
from rescue.registry import discover_modules
from rescue.threat_map import load_threat_map, validate_threat_map


def _ctx():
    mods = discover_modules(_get_modules_dir())
    all_modules = {m.name for m in mods}
    all_codes = set()
    for m in mods:
        all_codes |= set(getattr(m, "emits_codes", []))
    profs = discover_profiles(_get_profiles_dir())
    profiles = {n: ((set(p.include_modules) or all_modules) - set(p.exclude_modules))
                for n, p in profs.items()}
    return profiles, all_codes, all_modules


def test_shipped_threat_map_is_valid():
    profiles, all_codes, all_modules = _ctx()
    threats = load_threat_map(_project_root() / "docs" / "threat_remediation_map.yaml")
    assert threats, "threat map is empty"
    errors = validate_threat_map(threats, profiles, all_codes, all_modules)
    assert errors == [], "threat map invalid:\n" + "\n".join(errors)
