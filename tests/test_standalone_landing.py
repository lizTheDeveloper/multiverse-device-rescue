"""scripts/build-standalone-landing.py: both single-file pages build, with no
relative link left that would break when served from a database row."""

import importlib.util
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("standalone", ROOT / "scripts" / "build-standalone-landing.py")
standalone = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(standalone)

# Attribute values only; `href="' + escapeHtml(...)` inside a script isn't a link.
REL = re.compile(r"""(?:href|src)="(?!https?:|#|tel:|sms:|mailto:|x-apple)([^"'\s]+)\"""")


def test_landing_builds_self_contained():
    html = standalone.build()
    assert REL.findall(html) == []
    assert f'href="{standalone.PAGES_URL}class/"' in html
    assert "<style>" in html and 'src="permissions.js"' not in html


def test_class_page_builds_self_contained():
    html = standalone.build_class()
    assert REL.findall(html) == []
    assert 'src="class.js"' not in html and "STORE_KEY" in html
    assert f'rel="canonical" href="{standalone.PAGES_URL}class/"' in html
    for a in ["ReclaimCity-mac-arm64.dmg", "ReclaimCity-mac-x64.dmg", "ReclaimCity-windows-x64.exe"]:
        assert f"releases/latest/download/{a}" in html
