"""No shipped copy calls the app Device Rescue any more: it is Reclaim City.

The `rescue` command line keeps its name, so its own help and banners keep
theirs. So does the folder saved data lives in (a real path, never shown as a
name; moving it would lose everyone's progress).
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent

SHIPPED = [
    "README.md", "AGENTS.md", "CONTRIBUTING.md", "mkdocs.yml",
    "site/**/*", "shared/**/*", "docs/*.md", "docs/scenarios/**/*.md",
    "desktop/*.js", "desktop/package.json", "desktop/renderer/**/*",
    ".github/workflows/release.yml",
    "modules/**/*.py", "modules/**/manifest.json", "rescue/**/*.py", "rescue/**/*.json",
    "scripts/build_rescue_stick.py", "scripts/build-guides-html.py",
    "scripts/build-standalone-landing.py", "scripts/generate_command_catalog.py",
]
# The command line is not renamed: its help text, banners and TUI title stay.
CLI_FILES = {"rescue/cli.py", "rescue/__init__.py"}
CLI_DIRS = ("rescue/tui/",)
ALLOWED = [
    "Application Support/Device Rescue",        # the saved-data folder, a real path
    '"Application Support" / "Device Rescue"',
    "DATA_DIR_NAME = 'Device Rescue'",
    "Multiverse Device Rescue — Auto Mode",     # `rescue --auto` output, quoted in the docs
    "Multiverse Device Rescue — system diagnostic and repair toolkit",  # `rescue --help` output
    "used to be called Device Rescue",          # one line for people upgrading
    '"appId": "school.themultiverse.devicerescue"',  # kept so updates and OS permissions carry over
    "replace(/(?<![/\\w])Device Rescue\\b(?!\\/)/g, 'Reclaim City')",  # renames the engine's own text
]
# Matched without regard to case, so DEVICE RESCUE in a heading counts too.
# Slugs that must stay never match: `device-rescue` (URLs, paths, the
# `device-rescue.game.v1` store, endpoints) has a hyphen, and the appId above
# is allow-listed.
OLD = re.compile(r"Device ?Rescue", re.I)
TEXT = {".md", ".html", ".json", ".js", ".mjs", ".py", ".css", ".sh", ".bat", ".yml", ".yaml", ".txt"}
CODE = {".js", ".mjs", ".py", ".css", ".sh", ".bat", ".yml", ".yaml"}
COMMENT = re.compile(r"^\s*(//|/\*|\*|#|<!--|REM\b)")
ARTIFACTS = ["ReclaimCity-mac-arm64.dmg", "ReclaimCity-mac-x64.dmg", "ReclaimCity-windows-x64.exe"]


def _without_allowed(text):
    for ok in ALLOWED:
        text = text.replace(ok, "")
    return text


def _shipped_files():
    seen = set()
    for pattern in SHIPPED:
        for p in sorted(ROOT.glob(pattern)):
            rel = p.relative_to(ROOT).as_posix()
            if (p.is_file() and p.suffix in TEXT and rel not in seen
                    and "/superpowers/" not in rel and "node_modules" not in rel):
                seen.add(rel)
                yield rel, p


def test_no_shipped_copy_says_device_rescue():
    bad = []
    for rel, p in _shipped_files():
        if rel in CLI_FILES or rel.startswith(CLI_DIRS):
            continue
        for n, line in enumerate(p.read_text(encoding="utf-8").splitlines(), 1):
            if not OLD.search(_without_allowed(line)):
                continue
            if p.suffix in CODE and COMMENT.match(line):
                continue  # a code comment is never shown
            bad.append(f"{rel}:{n}: {line.strip()}")
    assert bad == [], "still says Device Rescue:\n" + "\n".join(bad)


def test_the_check_ignores_case_but_not_the_kept_slugs():
    assert OLD.search("OPTIONAL: TELL DEVICE RESCUE TOO")
    assert OLD.search("devicerescue")
    for kept in ["https://themultiverse.school/x/device-rescue", "device-rescue.game.v1",
                 '"appId": "school.themultiverse.devicerescue"']:
        assert not OLD.search(_without_allowed(kept)), kept


def _strings(obj):
    if isinstance(obj, str):
        yield obj
    elif isinstance(obj, dict):
        for v in obj.values():
            yield from _strings(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            yield from _strings(v)


def test_engine_text_the_app_shows_uses_the_new_name():
    from rescue import known_items
    from rescue.actions import launch_agent

    texts = [known_items.MARK_WILL_CHANGE, *known_items.MARK_HOW_TO_UNDO, *launch_agent.UNDO_STEPS]
    texts += list(_strings(json.loads((ROOT / "rescue" / "app_fixes.json").read_text(encoding="utf-8"))))
    assert [t for t in texts if OLD.search(_without_allowed(t))] == []
    assert any("Reclaim City" in t for t in texts)
    # The real folder is still named where a path is printed.
    assert any("Application Support/Device Rescue/Quarantine" in t for t in launch_agent.UNDO_STEPS)


def test_download_links_use_the_new_artifact_names():
    for rel in ["README.md", "site/index.html", ".github/workflows/release.yml"]:
        text = (ROOT / rel).read_text(encoding="utf-8")
        for a in ARTIFACTS:
            assert f"releases/latest/download/{a}" in text, f"{rel}: {a}"
    stick = (ROOT / "scripts" / "build_rescue_stick.py").read_text(encoding="utf-8")
    for a in ARTIFACTS:
        assert f'"{a}"' in stick, a
    pkg = json.loads((ROOT / "desktop" / "package.json").read_text(encoding="utf-8"))
    assert pkg["build"]["mac"]["artifactName"].startswith("ReclaimCity-mac-")
    assert pkg["build"]["win"]["artifactName"].startswith("ReclaimCity-windows-")
