#!/usr/bin/env python3
"""Write the monitoring checks' own findings, as `rescue scan --json` gives them.

The desktop app's little missions must treat a monitoring check's own finding
as one that warns before anything is removed, even though the engine sets no
``removal_alert`` or safety note on it (rescue/safety_scope.py leaves these
checks out: their whole description is the warning). The tests need the real
serialized shape, not a sample with a made-up ``removal_alert``. This runs
stalkerware_scan's finding builder on one known product and keylogger_indicators
with its system lookups replaced (one unrecognized app with keyboard access),
serializes both with the walkthroughs the CLI loads, and keeps the warnings.

Usage::

    python scripts/monitoring_findings_fixture.py           # write the fixture
    python scripts/monitoring_findings_fixture.py --check   # exit 1 if stale

``tests/test_monitoring_findings_fixture.py`` runs the check.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT))
OUTPUT_PATH = REPO_ROOT / "desktop" / "test" / "fixtures" / "monitoring-findings.json"
PRODUCT = "FlexiSPY"
LOCATION = "/Applications/FlexiSPY.app"
KEY_APP = "com.example.keys"


def _load(name: str):
    path = REPO_ROOT / "modules" / "security" / name / "__init__.py"
    spec = importlib.util.spec_from_file_location(f"{name}_fixture", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def collect() -> dict:
    from rescue.models import CheckResult
    from rescue.remediation import load_remediation_walkthroughs
    from rescue.serialize import checks_to_json

    stalk = _load("stalkerware_scan")
    s = stalk.Module()
    entry = next(e for e in stalk._load_known_stalkerware() if e["name"] == PRODUCT)
    s_result = CheckResult(module_name=s.name, findings=s._to_findings([(entry, "installed application", LOCATION)]))

    keys = _load("keylogger_indicators")
    k = keys.Module()
    k._get_input_monitoring_grants = lambda: {KEY_APP: [{"client_type": 0, "signer": None}]}
    k._check_cgeventtap_usage = lambda: []
    k_result = k.check(None)

    walkthroughs = load_remediation_walkthroughs(REPO_ROOT / "guides" / "remediation")
    doc = json.loads(checks_to_json([(s, s_result), (k, k_result)], "darwin", walkthroughs))
    out = {}
    for m in doc["modules"]:
        m["findings"] = [f for f in m["findings"] if f.get("severity") in ("critical", "warning")]
        out[m["name"]] = m
    return out


def render() -> str:
    return json.dumps(collect(), indent=1, ensure_ascii=False) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--check", action="store_true", help="exit 1 if the fixture is stale")
    args = parser.parse_args()
    text = render()
    if args.check:
        if not OUTPUT_PATH.exists() or OUTPUT_PATH.read_text() != text:
            print(f"{OUTPUT_PATH.relative_to(REPO_ROOT)} is stale; run python scripts/monitoring_findings_fixture.py", file=sys.stderr)
            return 1
        return 0
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(text)
    return 0


if __name__ == "__main__":
    sys.exit(main())
