# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for Multiverse Device Rescue.

Produces a single-file `rescue` executable bundling:
  - all Python code (rescue.* package, discovered via hidden imports)
  - modules/**/* (module code + data, e.g. known_bloatware.json lists) as
    plain data, since rescue.registry.discover_modules loads these from
    disk at runtime rather than importing them as regular packages
  - profiles/*.yaml (threat-model profiles)
  - guides/**/*.md (guided-walkthrough content)
  - rescue/security/trusted_signers.json and integrity_manifest.json
  - rescue/tui/app.tcss (Textual stylesheet, loaded relative to app.py)

Build with:
    pyinstaller rescue.spec
or via the cross-platform wrapper:
    python scripts/build.py

At runtime, rescue/cli.py's _project_root() detects sys.frozen and points
modules_dir/profiles_dir/guides_dir at sys._MEIPASS instead of the source
checkout, so the data bundled below must keep the same relative layout as
the source tree (modules/, profiles/, guides/ at the bundle root).
"""

import os
from pathlib import Path

from PyInstaller.utils.hooks import collect_submodules

PROJECT_ROOT = Path(os.path.abspath(SPECPATH))  # noqa: F821 (SPECPATH is injected by PyInstaller)

EXCLUDED_DIR_NAMES = frozenset({"__pycache__"})


def collect_tree(src_dir: Path, dest_prefix: str):
    """Recursively collect every file under src_dir into (source, dest_dir)
    tuples for the Analysis `datas` list, preserving directory structure
    under dest_prefix. Skips __pycache__ (and any other excluded dirs)."""
    entries = []
    if not src_dir.is_dir():
        return entries
    for path in sorted(src_dir.rglob("*")):
        if path.is_dir():
            continue
        if any(part in EXCLUDED_DIR_NAMES for part in path.parts):
            continue
        rel_parent = path.relative_to(src_dir).parent
        dest_dir = dest_prefix if str(rel_parent) == "." else str(Path(dest_prefix) / rel_parent)
        entries.append((str(path), dest_dir))
    return entries


datas = []

# modules/**/* -- module code (loaded from disk via importlib, not import
# machinery) plus their data files (e.g. bloatware/*/data/known_bloatware.json)
datas += collect_tree(PROJECT_ROOT / "modules", "modules")

# guides/**/*.md -- guided walkthrough content
datas += collect_tree(PROJECT_ROOT / "guides", "guides")

# profiles/*.yaml -- threat-model profiles
profiles_dir = PROJECT_ROOT / "profiles"
datas += [
    (str(f), "profiles") for f in sorted(profiles_dir.glob("*.yaml"))
]

# security metadata + TUI stylesheet, placed to match rescue/<pkg>/__file__
# resolution (Path(__file__).parent / "trusted_signers.json" etc.)
datas += [
    (str(PROJECT_ROOT / "rescue" / "security" / "trusted_signers.json"), "rescue/security"),
    (str(PROJECT_ROOT / "rescue" / "security" / "integrity_manifest.json"), "rescue/security"),
    (str(PROJECT_ROOT / "rescue" / "tui" / "app.tcss"), "rescue/tui"),
    (str(PROJECT_ROOT / "rescue" / "attribution_names.json"), "rescue"),
    # plain-language "what it is" lines, keyed on verified signing identity
    (str(PROJECT_ROOT / "rescue" / "program_descriptions.json"), "rescue"),
    # allowlist of fixes the desktop app may offer (rescue fix / scan --json)
    (str(PROJECT_ROOT / "rescue" / "app_fixes.json"), "rescue"),
]

def stdlib_imports_of(src_dir: Path):
    """Standard-library modules imported anywhere under src_dir.

    Check modules ship as data files (above), so PyInstaller never analyses
    their imports: a check that imports something the engine itself doesn't
    (ctypes.util, say) fails to load in the frozen app while every source
    test passes. Listing them here bundles them.
    """
    import ast
    import sys

    found = set()
    for path in src_dir.rglob("*.py"):
        if EXCLUDED_DIR_NAMES.intersection(path.parts):
            continue
        try:
            tree = ast.parse(path.read_text(encoding="utf-8"))
        except (SyntaxError, UnicodeDecodeError):
            continue
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                names = [alias.name for alias in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module]
            else:
                continue
            for name in names:
                if name.split(".")[0] in sys.stdlib_module_names:
                    found.add(name)
    return sorted(found)


hiddenimports = collect_submodules("rescue") + stdlib_imports_of(PROJECT_ROOT / "modules")

a = Analysis(
    [str(PROJECT_ROOT / "rescue" / "cli.py")],
    pathex=[str(PROJECT_ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="rescue",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
