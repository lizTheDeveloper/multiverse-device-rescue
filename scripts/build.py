#!/usr/bin/env python3
"""Build a single-file `rescue` executable with PyInstaller.

Wraps `pyinstaller rescue.spec` so the build works the same way on macOS
and Windows (mainly: locating the produced binary, which PyInstaller names
`rescue` on macOS/Linux and `rescue.exe` on Windows).

Usage:
    python scripts/build.py
"""

import subprocess
import sys
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
SPEC_FILE = PROJECT_ROOT / "rescue.spec"
DIST_DIR = PROJECT_ROOT / "dist"


def _output_path() -> Path:
    if sys.platform == "win32":
        return DIST_DIR / "rescue.exe"
    return DIST_DIR / "rescue"


def main() -> int:
    if not SPEC_FILE.exists():
        print(f"Spec file not found: {SPEC_FILE}", file=sys.stderr)
        return 1

    cmd = [
        sys.executable,
        "-m",
        "PyInstaller",
        "--clean",
        "--noconfirm",
        str(SPEC_FILE),
    ]
    result = subprocess.run(cmd, cwd=PROJECT_ROOT)
    if result.returncode != 0:
        print("Build failed.", file=sys.stderr)
        return result.returncode

    output = _output_path()
    if not output.exists():
        print(f"Build reported success but expected output is missing: {output}", file=sys.stderr)
        return 1

    print(f"Build complete: {output}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
