#!/usr/bin/env python3
"""Convert the in-repo Markdown guides into standalone HTML pages.

Reads guides/ (phase walkthroughs) and site/guides/ (database-exported
guides), converts Markdown to HTML, and writes standalone pages to
dist/rescue-stick/guides/.

The output works offline in any browser, with dark mode support and the
same visual style as the tools index.
"""
import re
import sys
from pathlib import Path

try:
    import markdown
except ImportError:
    print("pip install markdown  (needed for guide conversion)", file=sys.stderr)
    sys.exit(1)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
GUIDES_DIR = PROJECT_ROOT / "guides"
SITE_GUIDES_DIR = PROJECT_ROOT / "site" / "guides"
OUTPUT_DIR = PROJECT_ROOT / "dist" / "rescue-stick" / "guides"

TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — Reclaim City</title>
<style>
  :root {{ --bg: #f6f4ef; --text: #23271f; --muted: #565b4f; --accent: #2f6f4f;
          --border: #e0ddd2; --card-bg: #fff; --link: #2f6f4f; }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #171a15; --text: #ecebe3; --muted: #b5b8a9; --accent: #6fbf8c;
            --border: #33392b; --card-bg: #1f231b; --link: #86d1a3; }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.6; }}
  .wrap {{ max-width: 720px; margin: 0 auto; }}
  h1 {{ font-family: Georgia, serif; font-size: 1.8rem; margin: 0 0 0.5rem; }}
  h2 {{ font-family: Georgia, serif; font-size: 1.3rem; margin: 2rem 0 0.5rem;
       padding-top: 1rem; border-top: 1px solid var(--border); }}
  h3 {{ font-size: 1.1rem; margin: 1.5rem 0 0.4rem; }}
  a {{ color: var(--link); }}
  p {{ margin: 0.5rem 0; }}
  ul, ol {{ padding-left: 1.4rem; }}
  li {{ margin-bottom: 0.3rem; }}
  code {{ background: var(--card-bg); border: 1px solid var(--border); padding: 0.15em 0.35em;
         border-radius: 4px; font-size: 0.9em; }}
  pre {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 8px;
        padding: 1rem; overflow-x: auto; font-size: 0.88rem; }}
  pre code {{ background: none; border: none; padding: 0; }}
  blockquote {{ border-left: 3px solid var(--accent); margin: 1rem 0; padding: 0.5rem 1rem;
               color: var(--muted); }}
  hr {{ border: none; border-top: 1px solid var(--border); margin: 1.5rem 0; }}
  .safety {{ background: var(--card-bg); border: 1px solid var(--border); border-radius: 12px;
            padding: 1rem; margin: 1rem 0; font-size: 0.9rem; color: var(--muted); }}
  .safety strong {{ color: var(--text); }}
  .nav {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .nav a {{ color: var(--accent); }}
  .meta {{ color: var(--muted); font-size: 0.9rem; margin-bottom: 1.5rem; }}
</style>
</head>
<body>
<div class="wrap">
<div class="nav">
  <a href="index.html">← All Guides</a>
  <a href="../tools/index.html">Security Tools</a>
  <a href="../START-HERE.html">START HERE</a>
</div>
{body}
<div class="safety">
  <strong>Safety note:</strong> If someone you know may be monitoring your device,
  removing their software can alert them. Talk to an advocate first.
  US National Domestic Violence Hotline: 1-800-799-7233, or text START to 88788 ·
  <a href="https://stopstalkerware.org">stopstalkerware.org</a>
</div>
</div>
</body>
</html>
"""


def strip_frontmatter(text: str) -> tuple[dict, str]:
    """Remove YAML frontmatter and return parsed fields + remaining text."""
    meta = {}
    if text.startswith("---"):
        parts = text.split("---", 2)
        if len(parts) >= 3:
            for line in parts[1].strip().splitlines():
                if ":" in line:
                    k, v = line.split(":", 1)
                    meta[k.strip()] = v.strip().strip('"')
            text = parts[2]
    return meta, text


def md_to_html(md_text: str) -> str:
    return markdown.markdown(
        md_text,
        extensions=["tables", "fenced_code", "nl2br"],
    )


def build_profile_guides():
    """Convert the in-repo profile guides (multi-phase walkthroughs)."""
    pages = []
    for profile_dir in sorted(GUIDES_DIR.iterdir()):
        if not profile_dir.is_dir() or profile_dir.name == "remediation":
            continue
        profile_name = profile_dir.name
        phases = sorted(profile_dir.glob("phase_*.md"), key=lambda p: p.stem)
        if not phases:
            continue

        combined_md = ""
        title = profile_name.replace("_", " ").title()
        for phase_file in phases:
            meta, body = strip_frontmatter(phase_file.read_text(encoding="utf-8"))
            if meta.get("title"):
                phase_title = meta["title"]
            else:
                phase_title = f"Phase {phase_file.stem.split('_')[-1]}"
            if meta.get("title") and not combined_md:
                title = f"{profile_name.replace('_', ' ').title()}"
            time_note = f" ({meta['estimated_time']})" if meta.get("estimated_time") else ""
            combined_md += f"\n## Phase: {phase_title}{time_note}\n\n{body}\n"

        html_body = f"<h1>{title}</h1>\n"
        html_body += f'<p class="meta">Multi-phase walkthrough · {len(phases)} phases</p>\n'
        html_body += md_to_html(combined_md)

        filename = f"{profile_name}.html"
        pages.append((filename, title, f"{len(phases)}-phase walkthrough"))
        out = OUTPUT_DIR / filename
        out.write_text(TEMPLATE.format(title=title, body=html_body), encoding="utf-8")
        print(f"  {filename} ({len(phases)} phases)")

    return pages


def build_remediation_guides():
    """Convert remediation guides into a single reference page."""
    remediation_dir = GUIDES_DIR / "remediation"
    if not remediation_dir.exists():
        return []

    guides = sorted(remediation_dir.glob("*.md"))
    if not guides:
        return []

    combined_md = ""
    for guide in guides:
        _, body = strip_frontmatter(guide.read_text(encoding="utf-8"))
        guide_title = guide.stem.replace("_", " ").title()
        combined_md += f"\n## {guide_title}\n\n{body}\n\n---\n"

    html_body = "<h1>Remediation Reference</h1>\n"
    html_body += f'<p class="meta">{len(guides)} remediation walkthroughs</p>\n'
    html_body += md_to_html(combined_md)

    filename = "remediation-reference.html"
    out = OUTPUT_DIR / filename
    out.write_text(TEMPLATE.format(title="Remediation Reference", body=html_body), encoding="utf-8")
    print(f"  {filename} ({len(guides)} guides)")

    return [(filename, "Remediation Reference", f"{len(guides)} fix-it walkthroughs")]


def build_site_guides():
    """Convert database-exported guides from site/guides/."""
    if not SITE_GUIDES_DIR.exists():
        return []

    pages = []
    for f in sorted(SITE_GUIDES_DIR.iterdir()):
        if f.suffix == ".md":
            _, body = strip_frontmatter(f.read_text(encoding="utf-8"))
            title_match = re.match(r"^#\s+(.+)", body.strip())
            title = title_match.group(1) if title_match else f.stem.replace("-", " ").title()
            html_body = f"<h1>{title}</h1>\n" + md_to_html(body)
            filename = f"{f.stem}.html"
            out = OUTPUT_DIR / filename
            out.write_text(TEMPLATE.format(title=title, body=html_body), encoding="utf-8")
            pages.append((filename, title, "Guide"))
            print(f"  {filename}")
        elif f.suffix == ".html":
            # Already HTML — copy with navigation wrapper
            content = f.read_text(encoding="utf-8")
            if content.strip().startswith("<!DOCTYPE") or content.strip().startswith("<html"):
                # Full HTML document — copy as-is
                out = OUTPUT_DIR / f.name
                out.write_text(content, encoding="utf-8")
            else:
                # HTML fragment — wrap in template
                title_match = re.search(r"<h1[^>]*>([^<]+)</h1>", content)
                title = title_match.group(1) if title_match else f.stem.replace("-", " ").title()
                out = OUTPUT_DIR / f.name
                out.write_text(TEMPLATE.format(title=title, body=content), encoding="utf-8")
            title_for_index = f.stem.replace("-", " ").title()
            pages.append((f.name, title_for_index, "Interactive"))
            print(f"  {f.name}")

    return pages


def build_index(all_pages):
    """Generate the guides index page."""
    cards = ""

    profile_pages = [p for p in all_pages if "walkthrough" in p[2].lower() or "phase" in p[2].lower()]
    db_guides = [p for p in all_pages if p[2] == "Guide"]
    interactive = [p for p in all_pages if p[2] == "Interactive"]
    remediation = [p for p in all_pages if "remediation" in p[1].lower()]

    def section(title, items):
        if not items:
            return ""
        html = f'<h2>{title}</h2>\n'
        for filename, page_title, desc in items:
            html += f'<a class="guide" href="{filename}"><strong>{page_title}</strong><span>{desc}</span></a>\n'
        return html

    cards += section("Step-by-Step Walkthroughs", profile_pages)
    cards += section("Security Guides", db_guides)
    cards += section("Interactive Tools", interactive)
    cards += section("Fix-It Reference", remediation)

    index_html = f"""\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Guides — Reclaim City</title>
<style>
  :root {{ --bg: #f6f4ef; --text: #23271f; --muted: #565b4f; --accent: #2f6f4f;
          --border: #e0ddd2; --card-bg: #fff; --shadow: 0 1px 3px rgba(0,0,0,0.08); }}
  @media (prefers-color-scheme: dark) {{
    :root {{ --bg: #171a15; --text: #ecebe3; --muted: #b5b8a9; --accent: #6fbf8c;
            --border: #33392b; --card-bg: #1f231b; --shadow: 0 1px 3px rgba(0,0,0,0.3); }}
  }}
  * {{ box-sizing: border-box; }}
  body {{ font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.5; }}
  .wrap {{ max-width: 720px; margin: 0 auto; }}
  h1 {{ font-family: Georgia, serif; font-size: 1.8rem; margin: 0 0 0.5rem; }}
  h2 {{ font-size: 1.2rem; margin: 2rem 0 0.75rem; color: var(--muted); }}
  .intro {{ color: var(--muted); margin: 0 0 1.5rem; }}
  a.guide {{ display: flex; justify-content: space-between; align-items: center;
            background: var(--card-bg); border: 1px solid var(--border);
            border-radius: 12px; padding: 1rem 1.2rem; margin-bottom: 0.6rem;
            text-decoration: none; color: var(--text); box-shadow: var(--shadow);
            transition: border-color 0.12s; }}
  a.guide:hover {{ border-color: var(--accent); }}
  a.guide strong {{ color: var(--accent); font-size: 1rem; }}
  a.guide span {{ color: var(--muted); font-size: 0.85rem; white-space: nowrap; margin-left: 1rem; }}
  .nav {{ display: flex; gap: 1rem; margin-bottom: 1.5rem; font-size: 0.9rem; }}
  .nav a {{ color: var(--accent); }}
</style>
</head>
<body>
<div class="wrap">
<div class="nav">
  <a href="../tools/index.html">Security Tools</a>
  <a href="../START-HERE.html">START HERE</a>
</div>
<h1>Security Guides</h1>
<p class="intro">
  Step-by-step walkthroughs for common security situations.
  Open any guide in your browser — they work offline.
</p>
{cards}
</div>
</body>
</html>
"""
    out = OUTPUT_DIR / "index.html"
    out.write_text(index_html, encoding="utf-8")
    print(f"  index.html ({len(all_pages)} guides)")


def main():
    global OUTPUT_DIR
    # `--out DIR` writes somewhere other than dist/rescue-stick/guides/.
    if "--out" in sys.argv[1:]:
        OUTPUT_DIR = Path(sys.argv[sys.argv.index("--out") + 1]).resolve()
    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    print("Building profile walkthroughs...")
    profile_pages = build_profile_guides()

    print("Building remediation reference...")
    remediation_pages = build_remediation_guides()

    print("Building exported guides...")
    site_pages = build_site_guides()

    all_pages = profile_pages + site_pages + remediation_pages

    print("Building guides index...")
    build_index(all_pages)

    # Keep the quick-reference.txt if it exists
    qr = OUTPUT_DIR / "quick-reference.txt"
    if not qr.exists():
        print("  (quick-reference.txt will be added by build_rescue_stick.py)")

    print(f"\nDone: {len(all_pages)} guides in {OUTPUT_DIR}")


if __name__ == "__main__":
    main()
