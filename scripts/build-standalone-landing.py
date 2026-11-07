#!/usr/bin/env python3
"""Build a single self-contained copy of the landing page (or the class page).

site/index.html is served from GitHub Pages next to its stylesheet, script and
JSON. The Multiverse School serves pages from a database row at
themultiverse.school/x/device-rescue, where there are no neighbouring files,
so this inlines all three and points relative links at the Pages site.

`--class` builds site/class/index.html the same way: the page for people in a
class who have never downloaded the app.

Usage:
    python scripts/build-standalone-landing.py [output.html]
    python scripts/build-standalone-landing.py --class [output.html]
    (default output: dist/reclaim-city-landing.html, or dist/reclaim-city-class.html)
"""

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SITE = ROOT / "site"
PAGES_URL = "https://lizthedeveloper.github.io/multiverse-device-rescue/"


def _apply(html: str, page: str, replacements: dict) -> str:
    for old, new in replacements.items():
        if old not in html:
            raise SystemExit(f"{page} no longer contains {old!r}; update this script")
        html = html.replace(old, new)
    return html


def _script(js: str) -> str:
    return "<script>\n" + js.replace("</script", "<\\/script") + "\n</script>"


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

    html = _apply(html, "site/index.html", {
        '<link rel="stylesheet" href="styles.css" />': f"<style>\n{css}\n</style>",
        '<script src="permissions.js"></script>': _script(js),
        'href="./"': f'href="{PAGES_URL}"',
        'href="docs/': f'href="{PAGES_URL}docs/',
        'href="class/"': f'href="{PAGES_URL}class/"',
    })
    return html.replace("</head>", f'  <link rel="canonical" href="{PAGES_URL}" />\n</head>', 1)


def build_class() -> str:
    html = (SITE / "class" / "index.html").read_text(encoding="utf-8")
    css = (SITE / "styles.css").read_text(encoding="utf-8")
    js = (SITE / "class" / "class.js").read_text(encoding="utf-8")
    html = _apply(html, "site/class/index.html", {
        '<link rel="stylesheet" href="../styles.css" />': f"<style>\n{css}\n</style>",
        '<script src="class.js"></script>': _script(js),
        'href="../docs/': f'href="{PAGES_URL}docs/',
        'href="../"': f'href="{PAGES_URL}"',
    })
    if 'href="../' in html or "src=\"../" in html:
        raise SystemExit("site/class/index.html has a relative link this script doesn't rewrite")
    canonical = PAGES_URL + "class/"
    return html.replace("</head>", f'  <link rel="canonical" href="{canonical}" />\n</head>', 1)


def main() -> int:
    args = sys.argv[1:]
    is_class = "--class" in args
    args = [a for a in args if a != "--class"]
    default = "reclaim-city-class.html" if is_class else "reclaim-city-landing.html"
    out = Path(args[0]) if args else ROOT / "dist" / default
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(build_class() if is_class else build(), encoding="utf-8")
    print(f"Wrote {out} ({out.stat().st_size} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
