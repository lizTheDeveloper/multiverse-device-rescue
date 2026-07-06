#!/usr/bin/env python3
"""Regenerate rescue/security/integrity_manifest.json from the current
state of the rescue/ package. Run this at release time, after any
intentional change to the tool's own source files, then commit the
updated manifest alongside the code change:

    python scripts/generate_integrity_manifest.py
"""

from pathlib import Path

from rescue.security.integrity import write_integrity_manifest

PACKAGE_ROOT = Path(__file__).parent.parent / "rescue"
OUTPUT_PATH = PACKAGE_ROOT / "security" / "integrity_manifest.json"


def main() -> None:
    write_integrity_manifest(PACKAGE_ROOT, OUTPUT_PATH)
    print(f"Wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
