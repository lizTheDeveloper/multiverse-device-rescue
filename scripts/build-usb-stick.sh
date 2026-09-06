#!/usr/bin/env bash
# Build a rescue-stick directory ready to copy onto a USB drive.
#
# Usage:
#   ./scripts/build-usb-stick.sh                    # build binary + assemble stick
#   ./scripts/build-usb-stick.sh --skip-build       # assemble only (binary already in dist/)
#   ./scripts/build-usb-stick.sh --skip-tools       # skip bundling web tools
#   ./scripts/build-usb-stick.sh --school-dir PATH  # path to themultiverse.school checkout
set -euo pipefail
cd "$(dirname "$0")/.."

SKIP_BUILD=false
SKIP_TOOLS=false
SCHOOL_DIR=""

for arg in "$@"; do
  case "$arg" in
    --skip-build) SKIP_BUILD=true ;;
    --skip-tools) SKIP_TOOLS=true ;;
    --school-dir)  shift; SCHOOL_DIR="$1" ;;
    --school-dir=*) SCHOOL_DIR="${arg#*=}" ;;
    *) echo "Unknown option: $arg" >&2; exit 1 ;;
  esac
done

# Try to find the school repo if not specified
if [ -z "$SCHOOL_DIR" ]; then
  for candidate in \
    "../themultiverse.school" \
    "$HOME/src/themultiverse.school" \
    "../the-multiverse-school"; do
    if [ -d "$candidate/tools/shared" ]; then
      SCHOOL_DIR="$candidate"
      break
    fi
  done
fi

STICK_DIR="dist/rescue-stick"

# --- Build the binary ---------------------------------------------------
if [ "$SKIP_BUILD" = false ]; then
  echo "Building standalone binary..."
  python3 scripts/build.py
fi

# --- Determine platform --------------------------------------------------
if [ "$(uname)" = "Darwin" ]; then
  PLATFORM="macos"
  BINARY="dist/rescue"
else
  # Linux builds produce a binary that works on Linux; the layout uses "linux"
  # but the script also handles Windows via Git Bash / MSYS2 where uname
  # returns something with MINGW / MSYS / CYGWIN.
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*) PLATFORM="windows"; BINARY="dist/rescue.exe" ;;
    *)                     PLATFORM="linux";   BINARY="dist/rescue" ;;
  esac
fi

if [ ! -f "$BINARY" ]; then
  echo "Binary not found at $BINARY — run without --skip-build first." >&2
  exit 1
fi

# --- Assemble the stick layout -------------------------------------------
echo "Assembling rescue stick for $PLATFORM..."
rm -rf "$STICK_DIR"
mkdir -p "$STICK_DIR/$PLATFORM"
mkdir -p "$STICK_DIR/guides"
cp "$BINARY" "$STICK_DIR/$PLATFORM/"
chmod +x "$STICK_DIR/$PLATFORM/"* 2>/dev/null || true

# --- Generate START-HERE.txt ---------------------------------------------
cat > "$STICK_DIR/START-HERE.txt" << 'STARTHERE'
=== DEVICE RESCUE ===

This USB drive has a program called Device Rescue on it. It looks over
your computer, tells you in plain English what it finds, and never
changes anything unless you say so.

HOW TO USE IT
-------------

macOS:
  1. Open the "macos" folder on this drive.
  2. Right-click "rescue" and choose "Open".
  3. macOS will warn about an unidentified developer. Click "Open".
  4. A terminal window opens and the scan begins.

Windows:
  1. Open the "windows" folder on this drive.
  2. Double-click "rescue.exe".
  3. Windows may show a SmartScreen warning.
     Click "More info", then "Run anyway".
  4. A terminal window opens and the scan begins.

WHAT TO EXPECT
--------------

The scan takes a few minutes. You'll see results like:

  === disk_space ===
  No issues found.
  === linux_service_health ===
  Found 1 issue(s):
    [warning] No time-synchronisation service appears to be running

Results mean:
  "No issues found"    — The check ran and everything looks fine.
  "Found N issue(s)"   — Read the details. Severity is shown in brackets.
  "Check unavailable"  — The check couldn't run. You have no info here.
  "Not supported here"  — This check doesn't apply to your machine.

SHARING YOUR RESULTS
---------------------

To save a report you can share with someone helping you:

  rescue export

This creates a file at ~/.rescue/cases/ with credentials and personal
info already removed. Read it before sharing — module output is free
text.

WHAT THIS TOOL WILL NEVER ASK FOR
-----------------------------------

  - Your passwords
  - Two-factor / 2FA codes
  - Recovery keys or seed phrases
  - Your Apple ID, Google, or Microsoft account password

If anything asks you for these while claiming to be Device Rescue,
it is not Device Rescue.

SAFETY NOTE
-----------

If the person who may have access to your device is someone you know —
a partner, ex-partner, family member, or housemate — removing
monitoring software can escalate the situation. The safety plan comes
before the technical cleanup.

  National Domestic Violence Hotline (US): 1-800-799-7233
  Coalition Against Stalkerware: https://stopstalkerware.org

GUIDES (in the "guides" folder)
---------------------------------

This drive includes step-by-step walkthroughs you can open in any
browser. Open the "guides" folder and double-click "index.html":

  - Digital Security Reset — recovering after a hack
  - Identity Theft Recovery — credit freezes, fraud reports, the works
  - Home Network Intrusion — kick strangers off your Wi-Fi
  - Home for the Holidays — one afternoon with a family member's laptop
  - Activist Security Checklist
  - Journalist Security Checklist
  - Remediation Reference — 90 fix-it guides for specific issues
STARTHERE

# --- Generate quick-reference.txt ----------------------------------------
cat > "$STICK_DIR/guides/quick-reference.txt" << 'QUICKREF'
DEVICE RESCUE — QUICK REFERENCE
================================

WHAT IT IS
  A program that checks your computer and tells you what it finds.
  It does not change anything unless you say so.

RUN A SCAN
  Open the folder for your computer (macos/ or windows/) and
  run "rescue" (Mac) or "rescue.exe" (Windows).

  The first time, your OS will warn about an unknown app:
    Mac:     Right-click → Open → click "Open" again
    Windows: "More info" → "Run anyway"

READ THE RESULTS
  No issues found       — This check is fine.
  Found N issue(s)      — Read the details. [critical] = act now.
                          [warning] = worth fixing. [info] = FYI.
  Check unavailable     — Could not run. Not the same as "fine."
  Not supported here    — Doesn't apply to this computer.

PICK A SITUATION
  rescue profiles                             — See available scenarios
  rescue --auto --profile home_for_the_holidays  — Targeted scan
  rescue guide home_for_the_holidays          — Step-by-step walkthrough

SAVE A REPORT
  rescue export
  Creates a file with personal info removed.
  Read it before sharing.

IT WILL NEVER ASK FOR
  Passwords, 2FA codes, recovery keys, seed phrases.

SAFETY
  If someone you know may be monitoring you, get safety advice
  before removing their software. It can escalate the situation.
  US hotline: 1-800-799-7233 | https://stopstalkerware.org
QUICKREF

# --- Build HTML guides ---------------------------------------------------
echo "Building HTML guides..."
python3 scripts/build-guides-html.py 2>&1 | sed 's/^/  /'

# --- Bundle security tools from The Multiverse School --------------------
if [ "$SKIP_TOOLS" = false ] && [ -n "$SCHOOL_DIR" ] && [ -d "$SCHOOL_DIR/tools/shared" ]; then
  echo "Building security tools from $SCHOOL_DIR..."
  mkdir -p "$STICK_DIR/tools"

  TOOLS=(
    "password_health:password-health.html:Password Health Check"
    "threat_model:threat-model.html:Personal Threat Model"
    "pretext_anatomy:pretext-anatomy.html:Scam & Phishing Autopsy"
    "ad_surface:ad-surface.html:Ad Tracking Audit"
    "device_rescue:device-rescue.html:Device Rescue (Web)"
    "attack_surface_bench:attack-surface.html:Attack Surface Map"
  )

  BUILT_TOOLS=()
  for entry in "${TOOLS[@]}"; do
    IFS=: read -r tool_dir filename title <<< "$entry"
    if [ -f "$SCHOOL_DIR/tools/$tool_dir/build.py" ]; then
      (cd "$SCHOOL_DIR" && python3 "tools/$tool_dir/build.py") 2>&1 | sed 's/^/  /'
      BUILT_FILE="$SCHOOL_DIR/static/tools/$filename"
      if [ -f "$BUILT_FILE" ]; then
        # Patch the analytics endpoint from relative to absolute so it works
        # when opened from a file:// URL on the USB stick
        sed 's|var ENDPOINT = "/api/tool-events"|var ENDPOINT = "https://themultiverse.school/api/tool-events"|g' \
          "$BUILT_FILE" > "$STICK_DIR/tools/$filename"
        BUILT_TOOLS+=("$filename:$title")
      fi
    fi
  done

  # Generate tools index page
  cat > "$STICK_DIR/tools/index.html" << 'TOOLSHEAD'
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Security Tools — Device Rescue</title>
<style>
  :root { --bg: #f6f4ef; --text: #23271f; --muted: #565b4f; --accent: #2f6f4f;
          --border: #e0ddd2; --card-bg: #fff; --shadow: 0 1px 3px rgba(0,0,0,0.08); }
  @media (prefers-color-scheme: dark) {
    :root { --bg: #171a15; --text: #ecebe3; --muted: #b5b8a9; --accent: #6fbf8c;
            --border: #33392b; --card-bg: #1f231b; --shadow: 0 1px 3px rgba(0,0,0,0.3); }
  }
  * { box-sizing: border-box; }
  body { font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
         background: var(--bg); color: var(--text); margin: 0; padding: 2rem; line-height: 1.5; }
  .wrap { max-width: 720px; margin: 0 auto; }
  h1 { font-family: Georgia, serif; font-size: 1.8rem; margin: 0 0 0.5rem; }
  .intro { color: var(--muted); margin: 0 0 2rem; }
  .tools { display: grid; gap: 1rem; }
  a.tool { display: block; background: var(--card-bg); border: 1px solid var(--border);
           border-radius: 12px; padding: 1.2rem; text-decoration: none; color: var(--text);
           box-shadow: var(--shadow); transition: border-color 0.12s; }
  a.tool:hover { border-color: var(--accent); }
  a.tool h2 { font-size: 1.1rem; margin: 0 0 0.3rem; color: var(--accent); }
  a.tool p { margin: 0; color: var(--muted); font-size: 0.9rem; }
  .privacy { margin-top: 2rem; padding: 1rem; background: var(--card-bg); border: 1px solid var(--border);
             border-radius: 12px; font-size: 0.88rem; color: var(--muted); }
  .privacy strong { color: var(--text); }
  .back { display: inline-block; margin-top: 1.5rem; color: var(--accent); font-size: 0.9rem; }
</style>
</head>
<body>
<div class="wrap">
<h1>Security Tools</h1>
<p class="intro">
  Interactive guides and assessments for personal digital security.
  These run entirely in your browser — your data stays on this device unless
  you choose to send anonymous usage analytics.
</p>
<div class="tools">
TOOLSHEAD

  # Add each tool as a card
  for entry in "${BUILT_TOOLS[@]}"; do
    IFS=: read -r filename title <<< "$entry"
    case "$filename" in
      password-health.html)
        desc="Assess your password practices: manager usage, breach exposure, 2FA audit, recovery keys. Includes an emergency triage flow." ;;
      threat-model.html)
        desc="Figure out who might target you, what they're after, and what to protect first. Builds a playbook for your situation." ;;
      pretext-anatomy.html)
        desc="Got a suspicious email, text, or call? Dissect the pretext, identify the ask, and build a household scam defense card." ;;
      ad-surface.html)
        desc="See how much of your data is used for advertising across Google, Apple, Facebook, and your apps — and reduce it." ;;
      device-rescue.html)
        desc="The browser version of Device Rescue — walk through a device audit, check for stalkerware, and harden your settings." ;;
      attack-surface.html)
        desc="Map your personal attack surface: endpoints, services, credentials. For the more technically inclined." ;;
      *) desc="" ;;
    esac

    cat >> "$STICK_DIR/tools/index.html" << TOOLCARD
<a class="tool" href="$filename">
  <h2>$title</h2>
  <p>$desc</p>
</a>
TOOLCARD
  done

  cat >> "$STICK_DIR/tools/index.html" << 'TOOLSTAIL'
</div>
<div class="privacy">
  <strong>Privacy:</strong> All your answers stay in your browser's local storage on this
  device. Nothing is sent anywhere unless you opt in to anonymous usage analytics,
  which helps improve the tools. You can use everything here with no internet connection.
</div>
<a class="back" href="../START-HERE.txt">← Back to START-HERE</a>
</div>
</body>
</html>
TOOLSTAIL

  echo "  Bundled ${#BUILT_TOOLS[@]} security tools."
elif [ "$SKIP_TOOLS" = false ]; then
  echo "Skipping tools — school repo not found. Use --school-dir PATH to specify it."
fi

# --- Update START-HERE to mention tools -----------------------------------
if [ -d "$STICK_DIR/tools" ] && [ -f "$STICK_DIR/tools/index.html" ]; then
  cat >> "$STICK_DIR/START-HERE.txt" << 'TOOLSNOTE'

SECURITY TOOLS (in the "tools" folder)
---------------------------------------

This drive also includes interactive security guides you can open in
any web browser — no internet needed. Open the "tools" folder and
double-click "index.html" to see them all:

  - Password Health Check — assess your password practices
  - Personal Threat Model — figure out who might target you
  - Scam & Phishing Autopsy — dissect suspicious messages
  - Ad Tracking Audit — see and reduce your ad data footprint
  - Device Rescue (Web) — the browser version of this tool
  - Attack Surface Map — map your personal attack surface

Your answers stay on this device unless you choose to send anonymous
analytics.
TOOLSNOTE
fi

echo ""
echo "Rescue stick ready at: $STICK_DIR/"
echo ""
echo "Contents:"
find "$STICK_DIR" -type f | sort | sed "s|$STICK_DIR/|  |"
echo ""
echo "Copy this folder to a USB drive:"
echo "  macOS:   cp -R $STICK_DIR/* /Volumes/YOUR-USB-DRIVE/"
echo "  Windows: xcopy /E ${STICK_DIR//\//\\}\\* E:\\"
