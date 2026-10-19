#!/usr/bin/env python3
"""Write the scan's real TeamViewer finding, as `rescue scan --json` gives it.

The desktop app's tests check that the "removing it can alert them" warning
survives on a finding outside the three monitoring checks, in both display
modes. They need the engine's own text: the module's description and the
walkthrough's steps and safety note. This runs win_remote_access_audit with
its system lookups replaced (only TeamViewer "found"), serializes the result
with the walkthroughs the CLI loads, and keeps the TeamViewer finding.

Usage::

    python scripts/remote_access_fixture.py           # write the fixture
    python scripts/remote_access_fixture.py --check   # exit 1 if stale

``tests/test_remote_access_fixture.py`` runs the check.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
MODULE = REPO_ROOT / "modules" / "security" / "win_remote_access_audit" / "__init__.py"
OUTPUT_PATH = REPO_ROOT / "desktop" / "test" / "fixtures" / "remote-access-finding.json"
CODE = "security.win_remote_access_audit.teamviewer_installed"


def collect() -> dict:
    from rescue.remediation import load_remediation_walkthroughs
    from rescue.serialize import checks_to_json

    spec = importlib.util.spec_from_file_location("win_remote_access_audit_fixture", MODULE)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    m = mod.Module()
    m._check_teamviewer = lambda: True
    m._check_anydesk = lambda: False
    m._check_vnc = lambda: []
    m._check_logmein = lambda: False
    m._check_chrome_remote_desktop = lambda: False
    m._check_rdp_enabled = lambda: False
    result = m.check(None)
    walkthroughs = load_remediation_walkthroughs(REPO_ROOT / "guides" / "remediation")
    doc = json.loads(checks_to_json([(m, result)], "win32", walkthroughs))
    mod_out = doc["modules"][0]
    finding = next(f for f in mod_out["findings"] if f.get("code") == CODE)
    return {"name": mod_out["name"], "category": mod_out.get("category", "security"), "finding": finding}


def render() -> str:
    return json.dumps(collect(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the fixture is stale")
    args = parser.parse_args()
    text = render()
    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text(encoding="utf-8") != text:
            print(f"{OUTPUT_PATH.relative_to(REPO_ROOT)} is stale; run python scripts/remote_access_fixture.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(text, encoding="utf-8")
    return 0


if __name__ == "__main__":
    sys.exit(main())
