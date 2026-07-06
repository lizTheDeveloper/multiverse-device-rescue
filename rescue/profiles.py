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


def load_profile(path: Path) -> Profile:
    with open(path, "r") as f:
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
