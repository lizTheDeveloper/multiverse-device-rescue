#!/usr/bin/env bash
# Build a Reclaim City USB stick from the released desktop installers.
# Thin wrapper around scripts/build_rescue_stick.py; see docs/usb-rescue-stick.md.
#
#   ./scripts/build-usb-stick.sh                         # latest release -> dist/rescue-stick/
#   ./scripts/build-usb-stick.sh --version v0.3.4        # a specific release
#   ./scripts/build-usb-stick.sh --with-cli              # also the command-line tool for this OS
#   ./scripts/build-usb-stick.sh --skip-tools            # don't bundle the school's web tools
#   ./scripts/build-usb-stick.sh --school-dir PATH       # where themultiverse.school is
#   ./scripts/build-usb-stick.sh --write-to /Volumes/NAME   # copy the built stick onto a USB drive
set -euo pipefail
cd "$(dirname "$0")/.."
if ! command -v uv >/dev/null 2>&1; then
  echo "This needs uv: https://docs.astral.sh/uv/getting-started/installation/" >&2
  exit 1
fi
exec uv run --script scripts/build_rescue_stick.py "$@"
