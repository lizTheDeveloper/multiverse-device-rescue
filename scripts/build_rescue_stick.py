# /// script
# requires-python = ">=3.11"
# dependencies = ["markdown>=3.5"]
# ///
"""Build a Reclaim City USB stick from the released desktop installers.

    uv run scripts/build_rescue_stick.py                    # latest release
    uv run scripts/build_rescue_stick.py --version v0.3.4   # a specific release
    uv run scripts/build_rescue_stick.py --with-cli         # also the command-line tool for this OS
    uv run scripts/build_rescue_stick.py --write-to /Volumes/RESCUE

The installers come from GitHub Releases (`gh release download`), are checked
against the release's SHA256SUMS.txt, and are laid out in dist/rescue-stick/
with plain-language START-HERE files for the person who receives the stick.

`--write-to` only copies files onto a drive that is already mounted. It never
formats, erases or deletes anything, and it refuses anything that isn't an
external drive under /Volumes/.
"""

from __future__ import annotations

import argparse
import hashlib
import html
import json
import os
import platform
import plistlib
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent.parent
DIST_DIR = PROJECT_ROOT / "dist"
STICK_DIR = DIST_DIR / "rescue-stick"
PERMISSIONS_JSON = PROJECT_ROOT / "shared" / "permissions-content.json"
DEFAULT_REPO = "lizTheDeveloper/multiverse-device-rescue"
SUMS_NAME = "SHA256SUMS.txt"

# (release asset, folder on the stick). Folder names are what a
# non-technical person sees when they open the drive.
INSTALLERS = [
    ("ReclaimCity-mac-arm64.dmg", "For Mac with Apple chip"),
    ("ReclaimCity-mac-x64.dmg", "For Mac with Intel"),
    ("ReclaimCity-windows-x64.exe", "For Windows"),
]
HELPERS_DIR = "For helpers"

HOTLINE = "1-800-799-7233"

SCHOOL_TOOLS = [
    ("password_health", "password-health.html", "Password Health Check",
     "Assess your password practices: manager usage, breach exposure, 2FA audit, recovery keys."),
    ("threat_model", "threat-model.html", "Personal Threat Model",
     "Figure out who might target you, what they're after, and what to protect first."),
    ("pretext_anatomy", "pretext-anatomy.html", "Scam & Phishing Autopsy",
     "Got a suspicious email, text, or call? Pull it apart and build a household scam defense card."),
    ("ad_surface", "ad-surface.html", "Ad Tracking Audit",
     "See how much of your data is used for advertising, and reduce it."),
    ("device_rescue", "device-rescue.html", "Reclaim City (Web)",
     "The browser version of Reclaim City: walk through a device audit and check for stalkerware."),
    ("attack_surface_bench", "attack-surface.html", "Attack Surface Map",
     "Map your personal attack surface: devices, services, credentials. For the more technical."),
]


class StickError(Exception):
    """Something is wrong; stop and tell the person running the script."""


# --- checksums ----------------------------------------------------------


def sha256_of(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def parse_sha256sums(text: str) -> dict[str, str]:
    """Parse `sha256sum` output: '<64 hex>  <name>' (or ' *<name>' for binary mode)."""
    sums: dict[str, str] = {}
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith("#"):
            continue
        parts = line.split(None, 1)
        if len(parts) != 2:
            raise StickError(f"{SUMS_NAME} line {lineno} is not '<hash>  <file>': {raw!r}")
        digest, name = parts
        name = name.lstrip("*").strip()
        digest = digest.lower()
        if len(digest) != 64 or any(c not in "0123456789abcdef" for c in digest):
            raise StickError(f"{SUMS_NAME} line {lineno} has a malformed hash: {raw!r}")
        sums[Path(name).name] = digest
    return sums


def verify_files(folder: Path, sums: dict[str, str], names: list[str]) -> None:
    """Check every name in `names` exists in `folder` and matches `sums`. Raise on any problem."""
    problems = []
    for name in names:
        expected = sums.get(name)
        path = folder / name
        if expected is None:
            problems.append(f"{name}: not listed in {SUMS_NAME}")
        elif not path.is_file():
            problems.append(f"{name}: file is missing")
        else:
            actual = sha256_of(path)
            if actual != expected:
                problems.append(f"{name}: checksum MISMATCH (expected {expected}, got {actual})")
    if problems:
        raise StickError("Checksum verification failed:\n  " + "\n  ".join(problems))


# --- download -----------------------------------------------------------


def run(cmd: list[str], **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, check=True, **kw)


def resolve_tag(repo: str, version: str | None) -> str:
    cmd = ["gh", "release", "view"] + ([version] if version else []) + [
        "-R", repo, "--json", "tagName", "-q", ".tagName"]
    try:
        out = run(cmd, capture_output=True, text=True).stdout.strip()
    except FileNotFoundError:
        raise StickError("The GitHub CLI (`gh`) isn't installed. Install it, then `gh auth login`.")
    except subprocess.CalledProcessError as e:
        raise StickError(f"Couldn't find release {version or '(latest)'} in {repo}: {e.stderr.strip()}")
    if not out:
        raise StickError(f"No release found in {repo}.")
    return out


def download_release(repo: str, tag: str, dest: Path) -> None:
    names = [n for n, _ in INSTALLERS] + [SUMS_NAME]
    cmd = ["gh", "release", "download", tag, "-R", repo, "-D", str(dest)]
    for n in names:
        cmd += ["-p", n]
    print(f"Downloading {tag} from {repo} into {dest} ...")
    try:
        run(cmd)
    except subprocess.CalledProcessError:
        raise StickError(f"`gh release download {tag}` failed (see the message above).")


# --- stick contents -----------------------------------------------------


def install_steps() -> dict[str, str]:
    """The unsigned-app wording, taken from the app's own permissions content."""
    data = json.loads(PERMISSIONS_JSON.read_text(encoding="utf-8"))
    out = {}
    for os_name in ("macos", "windows"):
        entry = next((e for e in data.get(os_name, []) if e.get("stage") == "install"), None)
        if entry is None:
            raise StickError(f"No install-stage entry for {os_name} in {PERMISSIONS_JSON}")
        out[os_name] = entry["body"]
    return out


def ascii_text(text: str) -> str:
    """Plain .txt files stay ASCII so any text editor shows them correctly."""
    for a, b in (("\u2192", ">"), ("\u2014", "--"), ("\u2013", "-"), ("\u2018", "'"), ("\u2019", "'"),
                 ("\u201c", '"'), ("\u201d", '"'), ("\u2026", "...")):
        text = text.replace(a, b)
    return text


def start_here_txt(tag: str, steps: dict[str, str], with_cli: bool, has_tools: bool) -> str:
    mac_arm, mac_intel, win = (folder for _, folder in INSTALLERS)
    text = f"""\
RECLAIM CITY
============

This drive has a free program called Reclaim City on it. It looks over
your computer and tells you, in plain words, what it found and what to do
about it.

  * It only looks. It doesn't change or delete anything unless you say yes.
  * It never asks for your passwords.
  * Your results stay on your computer. Nothing is sent anywhere unless you
    choose "Ask about this" on an item, and it shows you exactly what it
    will send first.

(Version {tag}. If you'd rather read this with pictures and bigger text,
double-click START-HERE.html instead. It opens in your web browser.)


IF YOU'RE SCARED SOMEONE IS WATCHING YOU -- READ THIS FIRST
-----------------------------------------------------------

If you think a partner, ex, family member or someone you live with put
something on your phone or computer:

  * Removing monitoring software can ALERT THE PERSON WHO INSTALLED IT.
    Before you remove anything, talk to an advocate about whether it's safe.
  * If you can, use a device they've never had access to (a library
    computer, or a friend's phone) to read guides and make plans.
  * In the US, the National Domestic Violence Hotline is {HOTLINE},
    or text START to 88788. They help with tech safety as well.
  * Coalition Against Stalkerware: https://stopstalkerware.org

Reclaim City will never remove anything on its own. You decide.


ON A MAC
--------

1. Find out which kind of Mac you have. Click the Apple menu (the apple
   in the top-left corner of the screen), then "About This Mac".

     If it says  "Chip: Apple M1" (or M2, M3, M4 ...)
       -> open the folder "{mac_arm}"

     If it says  "Processor: ... Intel ..."
       -> open the folder "{mac_intel}"

2. Double-click the file in that folder (it ends in ".dmg").
   A window opens. Drag "Reclaim City" into "Applications".

3. Open "Reclaim City" from your Applications folder. A warning appears,
   because we haven't paid Apple for a signing certificate yet. Click
   "Done". Then:

   {_wrap(steps["macos"], 3)}


ON WINDOWS
----------

1. Open the folder "{win}".

2. Double-click "ReclaimCity-windows-x64.exe".

3. If a blue box says "Windows protected your PC":

   {_wrap(steps["windows"], 3)}


THEN
----

Click "Get started" and follow the screens. A checkup takes a few minutes.

When it's done, it lists what it found, starting with the most important.
"Couldn't check" means that check didn't run. It does NOT mean everything
is fine. A clean result makes a problem less likely, but can't rule one out.

Nothing is changed unless you click to fix something and say yes.


WHAT IT WILL NEVER ASK FOR
--------------------------

  * Your passwords
  * Two-step sign-in codes (2FA codes)
  * Recovery keys or recovery codes

If anything asks you for these while claiming to be Reclaim City, it is
not Reclaim City. Close it.


ALSO ON THIS DRIVE
------------------

  guides/       Step-by-step walkthroughs. Double-click guides/index.html.
                guides/quick-reference.txt is a one-page card you can print.
"""
    if has_tools:
        text += """\
  tools/        Interactive security guides that run in your web browser,
                no internet needed. Double-click tools/index.html.
"""
    if with_cli:
        text += """\
  command-line/ The command-line version, for helpers and tech people.
"""
    text += f"""\
  {HELPERS_DIR}/  Notes for whoever is helping you, including how to check
                that the files on this drive haven't been changed.
"""
    return text


def _wrap(text: str, indent: int, width: int = 72) -> str:
    import textwrap
    pad = " " * indent
    return textwrap.fill(text, width=width, initial_indent="", subsequent_indent=pad)


START_HERE_CSS = """
  :root { --bg: #f6f4ef; --text: #1f231b; --muted: #50564a; --accent: #2f6f4f;
          --border: #dcd8cc; --card: #ffffff; --warn-bg: #fff4e5; --warn-border: #e2a04a; }
  @media (prefers-color-scheme: dark) {
    :root:not([data-theme="light"]) { --bg: #171a15; --text: #ecebe3; --muted: #b5b8a9;
      --accent: #7fcf9c; --border: #353b2d; --card: #1f231b; --warn-bg: #2d2416; --warn-border: #b07a2c; }
  }
  :root[data-theme="dark"] { --bg: #171a15; --text: #ecebe3; --muted: #b5b8a9;
      --accent: #7fcf9c; --border: #353b2d; --card: #1f231b; --warn-bg: #2d2416; --warn-border: #b07a2c; }
  * { box-sizing: border-box; }
  body { margin: 0; background: var(--bg); color: var(--text);
         font: 19px/1.6 -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
  .wrap { max-width: 760px; margin: 0 auto; padding: 32px 16px 64px; }
  h1 { font-family: Georgia, serif; font-size: 2.1rem; margin: 0 0 4px; }
  h2 { font-family: Georgia, serif; font-size: 1.45rem; margin: 0 0 12px; }
  .lead { font-size: 1.1rem; margin: 0 0 16px; }
  .promises { list-style: none; padding: 0; margin: 0 0 28px; }
  .promises li { padding-left: 1.6em; position: relative; margin: 6px 0; }
  .promises li::before { content: "\\2713"; position: absolute; left: 0; color: var(--accent); font-weight: 700; }
  section { background: var(--card); border: 1px solid var(--border); border-radius: 14px;
            padding: 20px 22px; margin: 0 0 20px; }
  section.safety { background: var(--warn-bg); border: 2px solid var(--warn-border); }
  ol { padding-left: 1.4em; margin: 0; }
  ol > li { margin: 0 0 14px; }
  .choice { display: grid; grid-template-columns: 1fr 1fr; gap: 12px; margin: 10px 0 0; }
  .choice div { border: 1px solid var(--border); border-radius: 10px; padding: 10px 12px; }
  .choice b { display: block; }
  .folder { font-weight: 700; color: var(--accent); }
  .quote { font-style: italic; }
  .phone { font-size: 1.25rem; font-weight: 700; white-space: nowrap; }
  .small { color: var(--muted); font-size: 0.9rem; }
  code { font-size: 0.9em; }
  a { color: var(--accent); }
  @media (max-width: 560px) { .choice { grid-template-columns: 1fr; } body { font-size: 18px; } }
"""


def start_here_html(tag: str, steps: dict[str, str], with_cli: bool, has_tools: bool) -> str:
    e = html.escape
    mac_arm, mac_intel, win = (folder for _, folder in INSTALLERS)
    extras = ['<li><a href="guides/index.html">Step-by-step guides</a>. '
              'There is also a one-page card to print: <code>guides/quick-reference.txt</code>.</li>']
    if has_tools:
        extras.append('<li><a href="tools/index.html">Interactive security tools</a> that run in '
                      'your web browser, no internet needed.</li>')
    if with_cli:
        extras.append('<li>The <span class="folder">command-line</span> folder has the '
                      'command-line version, for helpers and tech people.</li>')
    extras.append(f'<li>The <span class="folder">{e(HELPERS_DIR)}</span> folder has notes for '
                  'whoever is helping you, including how to check the files on this drive '
                  "haven't been changed.</li>")
    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Start Here</title>
<style>{START_HERE_CSS}</style>
</head>
<body>
<div class="wrap">
<h1>Reclaim City</h1>
<p class="lead">This drive has a free program on it that looks over your computer and tells you,
in plain words, what it found and what to do about it.</p>
<ul class="promises">
  <li><b>It only looks.</b> It doesn't change or delete anything unless you say yes.</li>
  <li><b>It never asks for your passwords.</b></li>
  <li><b>Your results stay on your computer.</b> Nothing is sent anywhere unless you choose &ldquo;Ask about this&rdquo; on an item, and it shows you exactly what it will send first.</li>
</ul>

<section class="safety">
  <h2>If you're scared someone is watching you, read this first</h2>
  <p>If you think a partner, ex, family member or someone you live with put something on your
  phone or computer:</p>
  <ul>
    <li><b>Removing monitoring software can alert the person who installed it.</b>
      Before you remove anything, talk to an advocate about whether it's safe.</li>
    <li>If you can, use a device they've never had access to (a library computer, or a friend's
      phone) to read guides and make plans.</li>
    <li>In the US, the National Domestic Violence Hotline is
      <span class="phone">{HOTLINE}</span>, or text <b>START</b> to <b>88788</b>.
      They help with tech safety as well.</li>
  </ul>
  <p class="small">Reclaim City never removes anything on its own. You decide.
  More help: <a href="https://stopstalkerware.org">stopstalkerware.org</a></p>
</section>

<section>
  <h2>On a Mac</h2>
  <ol>
    <li>Find out which kind of Mac you have. Click the <b>Apple menu</b> (the apple in the
      top-left corner of the screen), then <b>About This Mac</b>.
      <div class="choice">
        <div><b>It says &ldquo;Chip: Apple M1&rdquo;</b> (or M2, M3, M4&hellip;)<br>
          Open the folder <span class="folder">{e(mac_arm)}</span></div>
        <div><b>It says &ldquo;Processor: &hellip; Intel&rdquo;</b><br>
          Open the folder <span class="folder">{e(mac_intel)}</span></div>
      </div>
    </li>
    <li>Double-click the file in that folder (it ends in <code>.dmg</code>). A window opens.
      Drag <b>Reclaim City</b> into <b>Applications</b>.</li>
    <li>Open <b>Reclaim City</b> from your Applications folder. A warning appears, because we
      haven't paid Apple for a signing certificate yet. Click <b>Done</b>. Then:
      <p>{e(steps["macos"])}</p></li>
  </ol>
</section>

<section>
  <h2>On Windows</h2>
  <ol>
    <li>Open the folder <span class="folder">{e(win)}</span>.</li>
    <li>Double-click <code>ReclaimCity-windows-x64.exe</code>.</li>
    <li>If a blue box says <span class="quote">&ldquo;Windows protected your PC&rdquo;</span>:
      <p>{e(steps["windows"])}</p></li>
  </ol>
</section>

<section>
  <h2>Then</h2>
  <p>Click <b>Get started</b> and follow the screens. A checkup takes a few minutes.</p>
  <p>When it's done, it lists what it found, starting with the most important.
  <b>&ldquo;Couldn't check&rdquo; means that check didn't run. It does not mean everything is
  fine.</b> A clean result makes a problem less likely, but can't rule one out.</p>
  <p>Nothing is changed unless you click to fix something and say yes.</p>
</section>

<section>
  <h2>What it will never ask for</h2>
  <p>Your passwords, two-step sign-in codes (2FA codes), or recovery keys. If anything asks
  for these while claiming to be Reclaim City, it is not Reclaim City. Close it.</p>
</section>

<section>
  <h2>Also on this drive</h2>
  <ul>{"".join(extras)}</ul>
</section>

<p class="small">Reclaim City {e(tag)}. Free and open source:
github.com/{e(DEFAULT_REPO)}</p>
</div>
</body>
</html>
"""


def checksums_note(tag: str, repo: str, with_cli: bool) -> str:
    mac_arm = INSTALLERS[0][1]
    win = INSTALLERS[2][1]
    note = f"""\
CHECKSUMS -- for helpers
========================

The installers on this drive are the official Reclaim City {tag} release
downloads from https://github.com/{repo}/releases/tag/{tag}

SHA256SUMS.txt (in this folder) is the checksum file published with that
release. When this drive was built, every installer was checked against it.
You can check again, for example if the drive has been out of your sight.

On a Mac (Terminal), with the drive called RESCUE:

    cd "/Volumes/RESCUE/{mac_arm}"
    shasum -a 256 ReclaimCity-mac-arm64.dmg

On Windows (PowerShell), with the drive at E:

    Get-FileHash "E:\\{win}\\ReclaimCity-windows-x64.exe" -Algorithm SHA256

Compare the result with the matching line in SHA256SUMS.txt (Windows prints
it in capitals; that's fine). For the strongest check, compare against the
SHA256SUMS.txt on the release page itself, from a different computer, so a
changed drive can't vouch for itself.

If anything doesn't match, don't run it. Download the installer again from
the release page.
"""
    if with_cli:
        note += """
The command-line/ folder was built on the helper's own machine, not taken
from the release, so it isn't in SHA256SUMS.txt. Its checksum is in
command-line/SHA256SUMS-cli.txt.
"""
    note += """
For AI assistants and tech helpers: the command-line tool is read-only
unless you pass --auto or --yes. Don't. See AGENTS.md in the repository.
"""
    return note


QUICK_REFERENCE = f"""\
RECLAIM CITY -- QUICK REFERENCE
===============================

WHAT IT IS
  A free program that checks your computer and tells you what it found.
  It does not change anything unless you say yes.

INSTALL IT (from the drive)
  Mac:     Apple menu > About This Mac.
           "Chip: Apple M..."     -> folder "{INSTALLERS[0][1]}"
           "Processor: ... Intel" -> folder "{INSTALLERS[1][1]}"
           Double-click the .dmg, drag Reclaim City into Applications.
           First open: click Done, then System Settings > Privacy &
           Security > scroll down > Open Anyway.
  Windows: folder "{INSTALLERS[2][1]}", double-click the .exe.
           "Windows protected your PC": More info > Run anyway.

READ THE RESULTS
  Most important first.
  "Couldn't check"  -- that check didn't run. NOT the same as "fine".
  A clean result lowers the odds of a problem; it can't rule one out.

IT WILL NEVER ASK FOR
  Passwords, 2FA codes, recovery keys or recovery codes.

SAFETY
  If someone you know may be monitoring you, removing their software can
  alert them. Talk to an advocate before removing anything.
  US National Domestic Violence Hotline: {HOTLINE}, or text START to 88788.
  Use a device they can't reach to make plans. https://stopstalkerware.org
"""


def build_guides(stick: Path) -> None:
    print("Building HTML guides...")
    run([sys.executable, str(PROJECT_ROOT / "scripts" / "build-guides-html.py"),
         "--out", str(stick / "guides")], cwd=PROJECT_ROOT)
    (stick / "guides" / "quick-reference.txt").write_text(QUICK_REFERENCE, encoding="utf-8")


def find_school_dir(explicit: str | None) -> Path | None:
    if explicit:
        p = Path(explicit).expanduser()
        if not (p / "tools" / "shared").is_dir():
            raise StickError(f"--school-dir {p} doesn't look like the school repo (no tools/shared).")
        return p
    for cand in (PROJECT_ROOT.parent / "themultiverse.school",
                 Path.home() / "src" / "themultiverse.school",
                 PROJECT_ROOT.parent / "the-multiverse-school"):
        if (cand / "tools" / "shared").is_dir():
            return cand
    return None


def build_school_tools(school: Path, stick: Path) -> int:
    """Build the school's offline tools in a scratch copy, so the school repo isn't modified."""
    print(f"Building security tools from {school} ...")
    out_dir = stick / "tools"
    out_dir.mkdir(parents=True, exist_ok=True)
    built = []
    with tempfile.TemporaryDirectory(prefix="rescue-stick-tools-") as tmp:
        work = Path(tmp)
        shutil.copytree(school / "tools" / "shared", work / "tools" / "shared")
        (work / "static" / "tools").mkdir(parents=True)
        for tool_dir, filename, title, desc in SCHOOL_TOOLS:
            src = school / "tools" / tool_dir
            if not (src / "build.py").is_file():
                print(f"  skip {tool_dir}: no build.py")
                continue
            shutil.copytree(src, work / "tools" / tool_dir)
            result = subprocess.run([sys.executable, "-I", str(work / "tools" / tool_dir / "build.py")],
                                    cwd=work, capture_output=True, text=True)
            produced = work / "static" / "tools" / filename
            if result.returncode != 0 or not produced.is_file():
                print(f"  skip {tool_dir}: build failed\n    " + (result.stderr.strip() or "no output")[-400:])
                continue
            text = produced.read_text(encoding="utf-8")
            # Analytics endpoint: relative -> absolute, so it works from file:// on the stick.
            text = text.replace('var ENDPOINT = "/api/tool-events"',
                                'var ENDPOINT = "https://themultiverse.school/api/tool-events"')
            (out_dir / filename).write_text(text, encoding="utf-8")
            built.append((filename, title, desc))
            print(f"  {filename}")
    if not built:
        shutil.rmtree(out_dir)
        return 0
    cards = "\n".join(
        f'<a class="tool" href="{html.escape(f)}"><h2>{html.escape(t)}</h2><p>{html.escape(d)}</p></a>'
        for f, t, d in built)
    (out_dir / "index.html").write_text(TOOLS_INDEX.replace("{cards}", cards), encoding="utf-8")
    return len(built)


TOOLS_INDEX = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Tools</title>
<style>
  :root { --bg: #f6f4ef; --text: #23271f; --muted: #565b4f; --accent: #2f6f4f;
          --border: #e0ddd2; --card-bg: #fff; }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #171a15; --text: #ecebe3; --muted: #b5b8a9; --accent: #6fbf8c;
            --border: #33392b; --card-bg: #1f231b; }
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: var(--bg); color: var(--text); margin: 0; padding: 32px 16px; line-height: 1.5; }
  .wrap { max-width: 720px; margin: 0 auto; }
  h1 { font-family: Georgia, serif; font-size: 1.8rem; margin: 0 0 0.5rem; }
  .intro { color: var(--muted); margin: 0 0 2rem; }
  .tools { display: grid; gap: 1rem; }
  a.tool { display: block; background: var(--card-bg); border: 1px solid var(--border);
           border-radius: 12px; padding: 1.2rem; text-decoration: none; color: var(--text); }
  a.tool:hover { border-color: var(--accent); }
  a.tool h2 { font-size: 1.1rem; margin: 0 0 0.3rem; color: var(--accent); }
  a.tool p { margin: 0; color: var(--muted); font-size: 0.9rem; }
  .privacy { margin-top: 2rem; padding: 1rem; background: var(--card-bg); border: 1px solid var(--border);
             border-radius: 12px; font-size: 0.88rem; color: var(--muted); }
  .back { display: inline-block; margin-top: 1.5rem; color: var(--accent); }
</style>
</head>
<body>
<div class="wrap">
<h1>Security Tools</h1>
<p class="intro">Interactive guides for personal digital security, from The Multiverse School.
They run in your web browser and work with no internet connection.</p>
<div class="tools">
{cards}
</div>
<div class="privacy"><strong>Privacy:</strong> Your answers stay in this browser on this device.
Nothing is sent anywhere unless you opt in to anonymous usage analytics.</div>
<a class="back" href="../START-HERE.html">&larr; Back to Start Here</a>
</div>
</body>
</html>
"""


def build_cli(stick: Path) -> None:
    """Build the command-line binary for this OS with PyInstaller (via uv, never global pip)."""
    print("Building the command-line tool for this computer (PyInstaller via uv) ...")
    env = {k: v for k, v in os.environ.items() if k != "VIRTUAL_ENV"}
    try:
        run(["uv", "run", "--with", "pyinstaller", "pyinstaller", "--clean", "--noconfirm", "rescue.spec"],
            cwd=PROJECT_ROOT, env=env)
    except FileNotFoundError:
        raise StickError("`uv` isn't installed; it's needed for --with-cli.")
    except subprocess.CalledProcessError:
        raise StickError("The PyInstaller build failed (see above).")
    exe = "rescue.exe" if sys.platform == "win32" else "rescue"
    built = DIST_DIR / exe
    if not built.is_file():
        raise StickError(f"PyInstaller finished but {built} isn't there.")
    os_name = {"darwin": "macos", "win32": "windows"}.get(sys.platform, "linux")
    arch = platform.machine().lower()
    dest_dir = stick / "command-line" / f"{os_name}-{arch}"
    dest_dir.mkdir(parents=True, exist_ok=True)
    shutil.copy2(built, dest_dir / exe)
    (dest_dir / exe).chmod(0o755)
    (stick / "command-line" / "SHA256SUMS-cli.txt").write_text(
        f"{sha256_of(dest_dir / exe)}  {os_name}-{arch}/{exe}\n", encoding="utf-8")
    (stick / "command-line" / "README.txt").write_text(
        f"The Reclaim City command-line tool (rescue) for {os_name} ({arch}), built from source on the helper's machine.\n"
        "Read-only by default: `rescue scan`, `rescue export`. Don't pass --auto or --yes;\n"
        "those apply fixes. Most people should use the desktop app instead (see START-HERE).\n",
        encoding="utf-8")


def dir_size(path: Path) -> int:
    return sum(p.stat().st_size for p in path.rglob("*") if p.is_file())


def human(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024 or unit == "GB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{int(n)} B"
        n /= 1024
    return f"{n:.1f} GB"


def assemble(args) -> Path:
    tag = resolve_tag(args.repo, args.version)
    steps = install_steps()
    DIST_DIR.mkdir(parents=True, exist_ok=True)

    # Downloads go into their own new, empty directory, removed afterwards.
    downloads = Path(tempfile.mkdtemp(prefix="rescue-stick-downloads-", dir=DIST_DIR))
    try:
        download_release(args.repo, tag, downloads)
        sums_path = downloads / SUMS_NAME
        if not sums_path.is_file():
            raise StickError(f"The {tag} release has no {SUMS_NAME}; refusing to build an unverified stick.")
        sums = parse_sha256sums(sums_path.read_text(encoding="utf-8"))
        names = [n for n, _ in INSTALLERS]
        print("Verifying checksums ...")
        verify_files(downloads, sums, names)
        for n in names:
            print(f"  OK  {n}  {sums[n]}")

        if STICK_DIR.exists():
            shutil.rmtree(STICK_DIR)
        STICK_DIR.mkdir(parents=True)
        for name, folder in INSTALLERS:
            (STICK_DIR / folder).mkdir()
            shutil.move(str(downloads / name), STICK_DIR / folder / name)
        helpers = STICK_DIR / HELPERS_DIR
        helpers.mkdir()
        shutil.move(str(sums_path), helpers / SUMS_NAME)
    finally:
        shutil.rmtree(downloads, ignore_errors=True)

    # Re-check where the files ended up, so the stick folder is what was verified.
    for name, folder in INSTALLERS:
        verify_files(STICK_DIR / folder, sums, [name])

    has_tools = False
    if not args.skip_tools:
        school = find_school_dir(args.school_dir)
        if school is None:
            print("Skipping tools: school repo not found (use --school-dir PATH).")
        else:
            has_tools = build_school_tools(school, STICK_DIR) > 0
    if args.with_cli:
        build_cli(STICK_DIR)
    build_guides(STICK_DIR)

    (STICK_DIR / "START-HERE.txt").write_text(
        ascii_text(start_here_txt(tag, steps, args.with_cli, has_tools)), encoding="utf-8")
    (STICK_DIR / "START-HERE.html").write_text(
        start_here_html(tag, steps, args.with_cli, has_tools), encoding="utf-8")
    (helpers / "CHECKSUMS.txt").write_text(checksums_note(tag, args.repo, args.with_cli), encoding="utf-8")

    print(f"\nRescue stick ready: {STICK_DIR}")
    print(f"Release: {tag}   Size: {human(dir_size(STICK_DIR))}")
    for p in sorted(STICK_DIR.iterdir()):
        print(f"  {p.name}{'/' if p.is_dir() else ''}")
    print("\nTo put it on a USB drive:  ./scripts/build-usb-stick.sh --write-to /Volumes/YOUR-DRIVE")
    return STICK_DIR


# --- write to a USB drive ----------------------------------------------


def diskutil_info(path: str) -> dict:
    out = subprocess.run(["diskutil", "info", "-plist", path], capture_output=True, check=True).stdout
    return plistlib.loads(out)


def check_write_target(target: str, needed: int, *, info=diskutil_info,
                       disk_usage=shutil.disk_usage, is_mount=os.path.ismount,
                       realpath=os.path.realpath) -> tuple[Path, dict]:
    """Return (resolved target, diskutil info) or raise StickError. Never modifies anything."""
    if sys.platform != "darwin" and info is diskutil_info:
        raise StickError("--write-to works on macOS only. Copy dist/rescue-stick/ to the drive by hand.")
    raw = Path(target)
    if not raw.is_absolute():
        raise StickError(f"{target}: give the full path, like /Volumes/RESCUE.")
    resolved = Path(realpath(target))  # /Volumes/Macintosh HD is a symlink to /
    parts = resolved.parts
    if len(parts) < 3 or parts[0] != "/" or parts[1] != "Volumes":
        raise StickError(f"{target} resolves to {resolved}, which isn't under /Volumes/. Refusing.")
    volume = Path("/", "Volumes", parts[2])
    if not is_mount(str(volume)):
        raise StickError(f"{volume} isn't a mounted drive. Plug the USB drive in and check its name in Finder.")
    try:
        d = info(str(volume))
    except (subprocess.CalledProcessError, FileNotFoundError, plistlib.InvalidFileException) as e:
        raise StickError(f"Couldn't read drive details for {volume} from diskutil: {e}")
    try:
        root = info("/")
    except (subprocess.CalledProcessError, FileNotFoundError, plistlib.InvalidFileException):
        root = {}
    if d.get("MountPoint") in ("/", None) or str(d.get("MountPoint")).rstrip("/") != str(volume):
        raise StickError(f"{volume}: diskutil reports mount point {d.get('MountPoint')!r}. Refusing.")
    same_disk = root.get("ParentWholeDisk") and d.get("ParentWholeDisk") == root.get("ParentWholeDisk")
    if same_disk or d.get("DeviceIdentifier") == root.get("DeviceIdentifier"):
        raise StickError(f"{volume} is on the startup disk. Refusing.")
    if d.get("BusProtocol") == "Disk Image":
        raise StickError(f"{volume} is a mounted disk image, not a USB drive. Refusing.")
    external = (d.get("Internal") is False or d.get("RemovableMedia") or d.get("Removable")
                or d.get("RemovableMediaOrExternalDevice") or d.get("Ejectable"))
    if not external:
        raise StickError(f"{volume}: diskutil says this is an internal, non-removable disk. Refusing.")
    if d.get("WritableVolume") is False or d.get("Writable") is False:
        raise StickError(f"{volume} is read-only.")
    free = disk_usage(str(volume)).free
    margin = 50 * 1024 * 1024
    if free < needed + margin:
        raise StickError(f"{volume} has {human(free)} free; the stick needs {human(needed)} plus some room.")
    return resolved, d


def write_to(target: str, assume_yes: bool) -> None:
    if not STICK_DIR.is_dir() or not (STICK_DIR / "START-HERE.txt").is_file():
        raise StickError(f"{STICK_DIR} isn't built yet. Run the script without --write-to first.")
    needed = dir_size(STICK_DIR)
    dest, d = check_write_target(target, needed)
    fs = (d.get("FilesystemType") or d.get("FilesystemName") or "?")
    print(f"Target: {dest}  ({d.get('MediaName') or d.get('IORegistryEntryName') or 'drive'}, "
          f"{d.get('FilesystemName') or fs}, {human(shutil.disk_usage(str(dest)).free)} free)")
    if str(fs).lower() not in ("exfat", "msdos"):
        print(f"  Note: this drive is {fs}. Windows can't read that; exFAT works on Mac and Windows.")
    existing = [p.name for p in dest.iterdir()] if dest.is_dir() else []
    print(f"\nWill COPY {human(needed)} from {STICK_DIR}/ into {dest}/ :")
    for p in sorted(STICK_DIR.iterdir()):
        print(f"  {p.name}{'/' if p.is_dir() else ''}")
    print("Nothing on the drive is formatted or deleted. Files with the same names are replaced.")
    if existing:
        print(f"The drive already has {len(existing)} item(s); they are left alone.")
    if not assume_yes:
        if input("\nType y to copy: ").strip().lower() != "y":
            print("Cancelled. Nothing was copied.")
            return
    dest.mkdir(exist_ok=True)
    env = dict(os.environ, COPYFILE_DISABLE="1")
    # -r -t only: exFAT has no Unix owners/permissions. No --delete, ever.
    run(["rsync", "-r", "-t", "--exclude", ".DS_Store", f"{STICK_DIR}/", f"{dest}/"], env=env)
    run(["sync"])
    sums = parse_sha256sums((dest / HELPERS_DIR / SUMS_NAME).read_text(encoding="utf-8"))
    print("Verifying the copied installers ...")
    for name, folder in INSTALLERS:
        verify_files(dest / folder, sums, [name])
        print(f"  OK  {folder}/{name}")
    print("\nDone. Eject the drive in Finder before unplugging it.")


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--version", help="release tag, e.g. v0.3.4 (default: latest)")
    ap.add_argument("--repo", default=DEFAULT_REPO, help=argparse.SUPPRESS)
    ap.add_argument("--with-cli", action="store_true",
                    help="also build the command-line tool for this OS (PyInstaller via uv)")
    ap.add_argument("--skip-tools", action="store_true", help="don't bundle the school's offline tools")
    ap.add_argument("--school-dir", help="path to a themultiverse.school checkout")
    ap.add_argument("--write-to", metavar="/Volumes/NAME",
                    help="copy an already-built dist/rescue-stick/ onto a mounted USB drive (copy only)")
    ap.add_argument("--yes", action="store_true", help="with --write-to: don't ask before copying")
    args = ap.parse_args(argv)
    sys.stdout.reconfigure(line_buffering=True)  # keep our lines in order with subprocess output
    try:
        if args.write_to:
            write_to(args.write_to, args.yes)
        else:
            assemble(args)
    except StickError as e:
        print(f"\nStopped: {e}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
