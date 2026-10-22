#!/usr/bin/env python3
"""Write vendor/hackmyagent/tree.sha256: the sha256 of every file a clean
``npm ci`` of the pinned lockfile puts in the install folder.

The ai_agent_audit check compares its saved copy of HackMyAgent against this
list before every run, and refuses to run a copy that differs. Regenerate it
whenever package.json or package-lock.json in vendor/hackmyagent/ changes:

    python scripts/generate_hackmyagent_manifest.py

Needs Node.js and npm, and downloads the pinned packages from the npm registry.
The hashing and the npm flags come from the module itself, so the manifest is
made exactly the way the check installs and verifies.
"""

from __future__ import annotations

import importlib.util
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
VENDOR = REPO_ROOT / "vendor" / "hackmyagent"
MODULE = REPO_ROOT / "modules" / "security" / "ai_agent_audit" / "__init__.py"


def load_module():
    sys.path.insert(0, str(REPO_ROOT))
    spec = importlib.util.spec_from_file_location("ai_agent_audit_for_manifest", MODULE)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def npm_ci(module, work: Path, scratch: Path) -> None:
    fill = {id(module._NPM_CACHE): str(scratch / "cache")}
    for sentinel, name in ((module._NPM_RC, "empty-user-npmrc"),
                           (module._NPM_GLOBAL_RC, "empty-global-npmrc")):
        (scratch / name).write_text("", encoding="utf-8")
        fill[id(sentinel)] = str(scratch / name)
    npm = shutil.which("npm")
    if npm is None:
        raise SystemExit("npm not found")
    argv = [npm if a == "npm" else fill.get(id(a), a) for a in module.NPM_CI_ARGS]
    subprocess.run([str(a) for a in argv], cwd=work, check=True)


def main() -> int:
    module = load_module()
    with tempfile.TemporaryDirectory() as tmp:
        work = Path(tmp) / "install"
        scratch = Path(tmp) / "scratch"
        work.mkdir()
        scratch.mkdir()
        for name in ("package.json", "package-lock.json"):
            shutil.copy2(VENDOR / name, work / name)
        shutil.copytree(VENDOR / "stub", work / "stub")
        npm_ci(module, work, scratch)
        files, links, odd = module.tree_hashes(work)
        if [link for link in links if link != module.STUB_LINK] or odd:
            raise SystemExit(f"unexpected links or entries: {links} {odd}")
        out = VENDOR / module.MANIFEST_NAME
        out.write_text(module.render_manifest(files), encoding="utf-8")
        print(f"Wrote {out} ({len(files)} files)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
