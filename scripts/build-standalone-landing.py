#!/usr/bin/env python3
"""Build a single self-contained copy of the landing page.

site/index.html is served from GitHub Pages next to its stylesheet, script and
JSON. The Multiverse School serves pages from a database row at
themultiverse.school/x/device-rescue, where there are no neighbouring files,
so this inlines all three and points relative links at the Pages site.

Usage:
    python scripts/build-standalone-landing.py [output.html]
    (default output: dist/device-rescue-landing.html)
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PAGES_URL = "https://lizthedeveloper.github.io/multiverse-device-rescue/"


def build() -> str:
    html = (SITE / "index.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    js = (SITE / "permissions.js").read_text(encoding="utf-8")
    content = json.loads((SITE / "permissions-content.json").read_text(encoding="utf-8"))

    fetch_call = 'fetch("permissions-content.json")'
    if fetch_call not in js:
        raise SystemExit("permissions.js no longer fetches permissions-content.json; update this script")
    # A Response-shaped stand-in keeps permissions.js unchanged.
    inline_data = json.dumps(content, ensure_ascii=False).replace("</", "<\\/")
    js = js.replace(
        fetch_call,
        "Promise.resolve({ ok: true, json: function () { return " + inline_data + "; } })",
    )

    replacements = {
        '<link rel="stylesheet" href="styles.css" />': f"<style>\n{css}\n</style>",
        '<script src="permissions.js"></script>': f"<script>\n{js}\n</script>",
        'href="./"': f'href="{PAGES_URL}"',
        'href="docs/': f'href="{PAGES_URL}docs/',
    }
    for old, new in replacements.items():
        if old not in html:
            raise SystemExit(f"site/index.html no longer contains {old!r}; update this script")
        html = html.replace(old, new)
    return html.replace("</head>", f'  <link rel="canonical" href="{PAGES_URL}" />\n</head>', 1)


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "dist" / "device-rescue-landing.html"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build(), encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
