from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from rescue.module_base import ModuleBase


@dataclass
class Profile:
    name: str
    display_name: str
    description: str
    include_modules: list[str] = field(default_factory=list)
    exclude_modules: list[str] = field(default_factory=list)
    module_config: dict[str, dict[str, Any]] = field(default_factory=dict)
    guides: list[str] = field(default_factory=list)


class ProfileValidationError(ValueError):
    pass


def load_profile(path: Path) -> Profile:
    with open(path, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f) or {}

    modules_section = data.get("modules", {}) or {}

    return Profile(
        name=data["name"],
        display_name=data.get("display_name", data["name"]),
        description=(data.get("description") or "").strip(),
        include_modules=modules_section.get("include", []) or [],
        exclude_modules=modules_section.get("exclude", []) or [],
        module_config=data.get("module_config", {}) or {},
        guides=data.get("guides", []) or [],
    )


def discover_profiles(profiles_dir: Path) -> dict[str, Profile]:
    profiles: dict[str, Profile] = {}
    if not profiles_dir.is_dir():
        return profiles

    for path in sorted(profiles_dir.glob("*.yaml")):
        profile = load_profile(path)
        profiles[profile.name] = profile
    return profiles


def filter_modules_by_profile(
    modules: list[ModuleBase], profile: Profile
) -> list[ModuleBase]:
    result = modules
    if profile.include_modules:
        result = [m for m in result if m.name in profile.include_modules]
    if profile.exclude_modules:
        result = [m for m in result if m.name not in profile.exclude_modules]
    return result


def validate_profile_modules(profile: Profile, modules: list[ModuleBase]) -> None:
    available = {module.name for module in modules}
    referenced = (
        set(profile.include_modules)
        | set(profile.exclude_modules)
        | set(profile.module_config)
    )
    missing = sorted(referenced - available)
    if missing:
        raise ProfileValidationError(
            f"Profile '{profile.name}' references unavailable module(s): {', '.join(missing)}"
        )


def _selected(profile: Profile, module_names: list[str]) -> list[str]:
    out = [n for n in module_names if not profile.include_modules or n in profile.include_modules]
    return [n for n in out if n not in profile.exclude_modules]


def merge_profiles(profiles: list[Profile], module_names: list[str]) -> Profile:
    """One profile that runs every module any of `profiles` selects (the
    union), in `module_names` order, with each profile's module settings.

    Two profiles giving the same module setting different values is refused
    rather than guessed: ProfileValidationError.
    """
    if not profiles:
        raise ProfileValidationError("No profiles to combine.")
    chosen: set[str] = set()
    config: dict[str, dict[str, Any]] = {}
    set_by: dict[tuple[str, str], str] = {}
    for profile in profiles:
        chosen.update(_selected(profile, module_names))
        for module, settings in (profile.module_config or {}).items():
            merged = config.setdefault(module, {})
            for key, value in (settings or {}).items():
                if key in merged and merged[key] != value:
                    raise ProfileValidationError(
                        f"Profiles '{set_by[(module, key)]}' and '{profile.name}' set {module} "
                        f"{key} differently, so they can't run together."
                    )
                merged[key] = value
                set_by.setdefault((module, key), profile.name)
    return Profile(
        name="+".join(p.name for p in profiles),
        display_name=" + ".join(p.display_name for p in profiles),
        description="Every check any of these selects: " + ", ".join(p.display_name for p in profiles) + ".",
        include_modules=[n for n in module_names if n in chosen],
        exclude_modules=[],
        module_config=config,
        guides=list(dict.fromkeys(g for p in profiles for g in p.guides)),
    )
