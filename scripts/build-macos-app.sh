#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install pyinstaller --break-system-packages >/dev/null 2>&1 || true
python scripts/build.py                       # -> dist/rescue
mkdir -p desktop/engine
cp dist/rescue desktop/engine/rescue
chmod +x desktop/engine/rescue
echo "staged engine at desktop/engine/rescue"
