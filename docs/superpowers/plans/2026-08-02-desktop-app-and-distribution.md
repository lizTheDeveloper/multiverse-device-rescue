# Desktop App + Distribution Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship Multiverse Device Rescue as a double-click Electron app (macOS now, Windows owner-built), with a Hetzner/Coolify landing page and GitHub-Releases downloads, including per-OS permission/popup walkthroughs.

**Architecture:** The Python engine gains a read-only `rescue scan --json` mode. An Electron shell spawns the bundled engine binary, parses its JSON, and renders results + a per-OS permissions onboarding. electron-builder packages a `.dmg` (mac) / NSIS `.exe` (win). Binaries go to GitHub Releases; a static landing page is deployed via Coolify on Hetzner.

**Tech Stack:** Python 3.14 + Click (engine), PyInstaller (engine binary), Electron + electron-builder (desktop shell), plain HTML/CSS/JS (renderer + landing page), GitHub Releases (`gh`), Coolify on Hetzner (`ssh hetzner`, Bitwarden).

## Global Constraints

- **Engine JSON on stdout only.** All human logs/warnings (incl. the startup integrity warning) go to **stderr**, so `scan --json` stdout is a single valid JSON document. (Verbatim from spec §3.1, §9.)
- **Read-only by default.** The GUI runs checks only; any system-mutating fix requires an explicit per-item confirmation (mirrors CLI `--yes`/`auto_apply`). (Spec §3.2.)
- **Unsigned for v1.** No signing/notarization; OS warnings are handled by the walkthroughs. (Spec §5.)
- **Electron security:** `contextIsolation: true`, `nodeIntegration: false`; renderer never spawns processes — only a minimal `preload.js` API. (Spec §2.)
- **Single artifact per OS:** engine binary bundled via electron-builder `extraResources`. (Spec §2, §3.3.)
- **Permissions/popups copy authored once** and shared by the app and the landing page. (Spec §4.)
- **Artifact naming:** `DeviceRescue-<version>-<os>-<arch>.<ext>`. (Spec §3.3.)
- **Owner-in-the-loop tasks** (Coolify deploy, Windows build) are NOT subagent-executable — they need interactive Bitwarden/SSH or a Windows PC.

## File Structure

- `rescue/cli.py` — add `scan` subcommand (`--json`).
- `rescue/serialize.py` (new) — dataclass→JSON helpers (enum coercion, schema).
- `tests/test_cli_scan_json.py` (new) — engine JSON tests.
- `desktop/` (new) — Electron app: `package.json`, `main.js`, `preload.js`, `renderer/{index.html,app.js,styles.css}`, `shared/permissions.js`.
- `desktop/engine/` — where the bundled engine binary is staged for electron-builder.
- `site/` (new) — landing page: `index.html`, `styles.css`, `permissions.js` (generated/copied from shared copy), `Dockerfile` or `nixpacks`/static config for Coolify.
- `shared/permissions-content.json` (new) — canonical per-OS walkthrough copy, consumed by both `desktop/` and `site/`.
- `scripts/build-windows.bat` (new) — owner-run Windows build.
- `scripts/build-macos-app.sh` (new) — build engine + electron `.dmg` on macOS.

---

### Task 1: Engine `rescue scan --json` (read-only JSON output)

**Files:**
- Create: `rescue/serialize.py`
- Modify: `rescue/cli.py` (add `scan` command)
- Test: `tests/test_cli_scan_json.py`

**Interfaces:**
- Produces: `rescue.serialize.checks_to_json(results: list[tuple[ModuleBase, CheckResult]], platform: str) -> str` returning a JSON string with shape `{"schema_version": 1, "platform": str, "modules": [{"name": str, "status": str, "error": str|None, "findings": [ {title, description, severity, category, code, data} ]}]}`.
- Produces CLI: `rescue scan --json` runs `Orchestrator.run_checks()` and prints that JSON to **stdout**; nothing else on stdout.

- [ ] **Step 1: Write the failing test**

```python
# tests/test_cli_scan_json.py
import json, subprocess, sys
from click.testing import CliRunner
from rescue.cli import main

def test_scan_json_is_single_valid_json_document_on_stdout():
    result = CliRunner(mix_stderr=False).invoke(main, ["scan", "--json"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)          # must parse: stdout is pure JSON
    assert doc["schema_version"] == 1
    assert isinstance(doc["platform"], str)
    assert isinstance(doc["modules"], list)

def test_scan_json_enums_are_strings():
    result = CliRunner(mix_stderr=False).invoke(main, ["scan", "--json"])
    doc = json.loads(result.stdout)
    for mod in doc["modules"]:
        assert isinstance(mod["status"], str)
        for f in mod["findings"]:
            assert isinstance(f["severity"], str)   # not an Enum repr
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_cli_scan_json.py -q`
Expected: FAIL — no `scan` command / `no such command 'scan'`.

- [ ] **Step 3: Implement `rescue/serialize.py`**

```python
# rescue/serialize.py
from __future__ import annotations
import json
from dataclasses import asdict, is_dataclass
from enum import Enum
from typing import Any


def _plain(value: Any) -> Any:
    if isinstance(value, Enum):
        return value.value
    if is_dataclass(value):
        return {k: _plain(v) for k, v in asdict(value).items()}
    if isinstance(value, dict):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def checks_to_json(results, platform: str) -> str:
    modules = []
    for mod, check in results:
        modules.append({
            "name": mod.name,
            "status": "error" if check.error else "ok",
            "error": check.error,
            "findings": [_plain(f) for f in check.findings],
        })
    return json.dumps(
        {"schema_version": 1, "platform": platform, "modules": modules},
        indent=2,
    )
```

- [ ] **Step 4: Add the `scan` command to `rescue/cli.py`**

```python
# in rescue/cli.py, near the other @main.command() definitions
@main.command()
@click.option("--json", "as_json", is_flag=True, help="Emit read-only check results as JSON on stdout.")
def scan(as_json):
    """Run read-only checks. With --json, print structured results to stdout."""
    from rescue.serialize import checks_to_json
    profile = gather_profile()
    orch = Orchestrator(modules_dir=_get_modules_dir())
    results = orch.run_checks()
    if as_json:
        click.echo(checks_to_json(results, profile.platform.value))
        return
    for mod, check in results:
        click.echo(mod.report(check))
```

Note: `_run_startup_integrity_check()` already writes to stderr (`err=True`) — leave scan out of that path, or ensure any warning uses `err=True`. Verify no `click.echo(...)` without `err=True` runs before the JSON on the `scan --json` path.

- [ ] **Step 5: Run tests to verify they pass**

Run: `python -m pytest tests/test_cli_scan_json.py -q`
Expected: PASS (2 passed).

- [ ] **Step 6: Verify stdout cleanliness end-to-end**

Run: `rescue scan --json 1>/tmp/out.json 2>/tmp/err.txt; python -c "import json;json.load(open('/tmp/out.json'));print('clean json ok')"`
Expected: prints `clean json ok` (stdout parsed; warnings, if any, are in `/tmp/err.txt`).

- [ ] **Step 7: Commit**

```bash
git add rescue/serialize.py rescue/cli.py tests/test_cli_scan_json.py
git commit -m "feat: rescue scan --json read-only structured output for the GUI"
```

---

### Task 2: Canonical per-OS permissions/popups content

**Files:**
- Create: `shared/permissions-content.json`
- Test: `tests/test_permissions_content.py`

**Interfaces:**
- Produces: `shared/permissions-content.json` with shape `{"macos": [{"title","body","action_label"?,"setting_url"?}], "windows":[…], "linux":[…]}`. Consumed by the Electron renderer (Task 5) and the landing page (Task 8).

- [ ] **Step 1: Write the failing test**

```python
# tests/test_permissions_content.py
import json
from pathlib import Path

DOC = Path(__file__).parent.parent / "shared" / "permissions-content.json"

def test_permissions_content_covers_each_os_with_required_fields():
    data = json.loads(DOC.read_text())
    for os_key in ("macos", "windows", "linux"):
        assert os_key in data and data[os_key], f"missing {os_key}"
        for step in data[os_key]:
            assert step["title"] and step["body"]

def test_macos_mentions_gatekeeper_and_full_disk_access():
    data = json.loads(DOC.read_text())
    blob = json.dumps(data["macos"]).lower()
    assert "open anyway" in blob
    assert "full disk access" in blob
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/test_permissions_content.py -q`
Expected: FAIL — file does not exist.

- [ ] **Step 3: Author `shared/permissions-content.json`**

Include, verbatim from spec §4: macOS steps (Gatekeeper "Open Anyway", Full Disk Access with `setting_url` `x-apple.systempreferences:com.apple.preference.security?Privacy_AllFiles`, Files/Folders TCC, admin password only-for-fixes, Automation); Windows steps (SmartScreen "Run anyway", UAC, antivirus false-positive note); Linux (CLI-only note). Each step: `{"title","body"}` plus optional `action_label`/`setting_url`.

- [ ] **Step 4: Run tests to verify they pass**

Run: `python -m pytest tests/test_permissions_content.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add shared/permissions-content.json tests/test_permissions_content.py
git commit -m "feat: canonical per-OS permissions/popups walkthrough content"
```

---

### Task 3: Electron shell scaffold

**Files:**
- Create: `desktop/package.json`, `desktop/main.js`, `desktop/preload.js`, `desktop/renderer/index.html`, `desktop/renderer/styles.css`, `desktop/renderer/app.js`
- Create: `desktop/.gitignore` (`node_modules/`, `dist/`, `engine/`)

**Interfaces:**
- Produces: an Electron app that launches a window loading `renderer/index.html`. `preload.js` exposes `window.rescue` with `runScan(): Promise<object>` and `openSetting(url): void` (implemented in Task 4).

- [ ] **Step 1: Create `desktop/package.json`**

```json
{
  "name": "device-rescue",
  "version": "0.1.0",
  "description": "Multiverse Device Rescue desktop app",
  "main": "main.js",
  "scripts": { "start": "electron ." },
  "devDependencies": { "electron": "^32.0.0", "electron-builder": "^25.0.0" }
}
```

- [ ] **Step 2: Create `main.js` (window + secure defaults)**

```javascript
const { app, BrowserWindow } = require('electron');
const path = require('path');
function createWindow() {
  const win = new BrowserWindow({
    width: 900, height: 680,
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      contextIsolation: true,
      nodeIntegration: false,
    },
  });
  win.loadFile(path.join(__dirname, 'renderer', 'index.html'));
}
app.whenReady().then(createWindow);
app.on('window-all-closed', () => { if (process.platform !== 'darwin') app.quit(); });
```

- [ ] **Step 3: Create `preload.js` (minimal bridge stub)**

```javascript
const { contextBridge, ipcRenderer, shell } = require('electron');
contextBridge.exposeInMainWorld('rescue', {
  runScan: () => ipcRenderer.invoke('run-scan'),
  openSetting: (url) => ipcRenderer.invoke('open-setting', url),
});
```

- [ ] **Step 4: Create minimal `renderer/index.html`, `styles.css`, `app.js`**

`index.html` loads `styles.css` + `app.js` and has a `<div id="app">Device Rescue</div>`. `app.js` logs `window.rescue` is present. (Full UI in Task 5.)

- [ ] **Step 5: Install and smoke-test**

Run: `cd desktop && npm install && npm start`
Expected: an Electron window opens showing "Device Rescue". Close it.

- [ ] **Step 6: Commit**

```bash
git add desktop/package.json desktop/main.js desktop/preload.js desktop/renderer desktop/.gitignore
git commit -m "feat: Electron shell scaffold with secure defaults"
```

---

### Task 4: IPC bridge — spawn engine, return JSON

**Files:**
- Modify: `desktop/main.js`
- Create: `desktop/engine-runner.js`
- Test: `desktop/test/engine-runner.test.js` (node's built-in `node:test`)

**Interfaces:**
- Consumes: engine binary emitting `scan --json` (Task 1).
- Produces: `engine-runner.js` exports `resolveEnginePath()` and `runScan(spawnFn?)` → resolves parsed JSON object; rejects on non-JSON/nonzero exit. `main.js` registers `ipcMain.handle('run-scan', …)` and `ipcMain.handle('open-setting', (_e,url)=>shell.openExternal(url))`.

- [ ] **Step 1: Write the failing test (inject a fake spawn)**

```javascript
// desktop/test/engine-runner.test.js
const test = require('node:test');
const assert = require('node:assert');
const { parseEngineOutput } = require('../engine-runner');

test('parseEngineOutput returns parsed JSON from stdout', () => {
  const out = JSON.stringify({ schema_version: 1, platform: 'darwin', modules: [] });
  assert.deepStrictEqual(parseEngineOutput(out).schema_version, 1);
});
test('parseEngineOutput throws on non-JSON', () => {
  assert.throws(() => parseEngineOutput('not json'));
});
```

- [ ] **Step 2: Run test to verify it fails**

Run: `cd desktop && node --test`
Expected: FAIL — cannot find `../engine-runner`.

- [ ] **Step 3: Implement `engine-runner.js`**

```javascript
const path = require('path');
const { spawn } = require('child_process');

function resolveEnginePath() {
  const bin = process.platform === 'win32' ? 'rescue.exe' : 'rescue';
  // Packaged: process.resourcesPath/engine/<bin>; dev: ./engine/<bin>
  const base = process.resourcesPath && require('fs').existsSync(path.join(process.resourcesPath, 'engine'))
    ? path.join(process.resourcesPath, 'engine')
    : path.join(__dirname, 'engine');
  return path.join(base, bin);
}
function parseEngineOutput(stdout) { return JSON.parse(stdout); }
function runScan(spawnFn = spawn) {
  return new Promise((resolve, reject) => {
    const p = spawnFn(resolveEnginePath(), ['scan', '--json']);
    let out = '', err = '';
    p.stdout.on('data', d => (out += d));
    p.stderr.on('data', d => (err += d));
    p.on('error', reject);
    p.on('close', code => {
      if (code !== 0) return reject(new Error(`engine exited ${code}: ${err}`));
      try { resolve(parseEngineOutput(out)); } catch (e) { reject(e); }
    });
  });
}
module.exports = { resolveEnginePath, parseEngineOutput, runScan };
```

- [ ] **Step 4: Wire IPC in `main.js`**

Add: `const { ipcMain, shell } = require('electron');` and `const { runScan } = require('./engine-runner');`, then in `whenReady`: `ipcMain.handle('run-scan', () => runScan()); ipcMain.handle('open-setting', (_e, url) => shell.openExternal(url));`

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd desktop && node --test`
Expected: PASS (2 tests).

- [ ] **Step 6: Commit**

```bash
git add desktop/engine-runner.js desktop/main.js desktop/test
git commit -m "feat: Electron IPC bridge spawning the engine scan --json"
```

---

### Task 5: Renderer UI — welcome, permissions, scan, results

**Files:**
- Modify: `desktop/renderer/index.html`, `desktop/renderer/app.js`, `desktop/renderer/styles.css`
- Create: `desktop/renderer/permissions.js` (loads `shared/permissions-content.json`, copied in at build; in dev, read relative path)
- Test: manual smoke test (Electron UI)

**Interfaces:**
- Consumes: `window.rescue.runScan()` (Task 4), permissions content (Task 2).
- Produces: a 4-screen flow. Results render findings grouped by severity; the permissions screen renders the current OS's steps with "Open setting" buttons calling `window.rescue.openSetting(url)`.

- [ ] **Step 1: Build the screen flow in `app.js`**

Implement `showScreen(id)` for `welcome | permissions | scan | results`. Welcome → "Get started" → permissions. Permissions renders `permissions-content.json` for `navigator.platform`-derived OS with an "I've done this / Continue" button. Scan screen has a "Run checkup" button calling `await window.rescue.runScan()` with a spinner; on resolve → results.

- [ ] **Step 2: Render results grouped by severity**

Group `doc.modules[].findings` by `severity` (critical/warning/info); show title + description; render an explicit "Fix…" button ONLY for findings whose data marks them actionable — but v1 shows guidance text and does not auto-apply (per Global Constraints). Show module `error` entries in a "couldn't check" list.

- [ ] **Step 3: Style it (`styles.css`)**

Minimal, legible, light/dark aware. Severity color chips. Large primary buttons.

- [ ] **Step 4: Smoke-test the full flow (dev)**

Run: `cd desktop && npm start` (requires `desktop/engine/rescue` present — see Task 6/7; for a pure-UI check, temporarily symlink the source binary or a stub that prints valid JSON).
Expected: welcome → permissions (shows macOS steps on this Mac) → run checkup → results render without errors. Check DevTools console for no exceptions.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer
git commit -m "feat: renderer UI — welcome, permissions walkthrough, scan, results"
```

---

### Task 6: Rebuild + stage the macOS engine binary

**Files:**
- Create: `scripts/build-macos-app.sh`
- Modify: (none)

**Interfaces:**
- Consumes: `rescue.spec`, `scripts/build.py`.
- Produces: a fresh `dist/rescue` (arm64) built from current source, staged at `desktop/engine/rescue` for electron-builder.

- [ ] **Step 1: Write `scripts/build-macos-app.sh`**

```bash
#!/usr/bin/env bash
set -euo pipefail
cd "$(dirname "$0")/.."
python -m pip install pyinstaller >/dev/null
python scripts/build.py                       # -> dist/rescue
mkdir -p desktop/engine
cp dist/rescue desktop/engine/rescue
chmod +x desktop/engine/rescue
echo "staged engine at desktop/engine/rescue"
```

- [ ] **Step 2: Run it**

Run: `bash scripts/build-macos-app.sh`
Expected: ends with "staged engine at desktop/engine/rescue".

- [ ] **Step 3: Verify the fresh binary emits clean JSON**

Run: `desktop/engine/rescue scan --json 1>/tmp/e.json 2>/dev/null; python -c "import json;print(len(json.load(open('/tmp/e.json'))['modules']),'modules')"`
Expected: prints a module count (e.g. `187 modules`).

- [ ] **Step 4: Commit the script (not the binary)**

```bash
git add scripts/build-macos-app.sh
git commit -m "build: script to build+stage the macOS engine binary for Electron"
```

---

### Task 7: Package macOS `.dmg` with electron-builder

**Files:**
- Modify: `desktop/package.json` (add `build` config + `dist` script)
- Test: manual install smoke test

**Interfaces:**
- Consumes: `desktop/engine/rescue` (Task 6), Electron app (Tasks 3–5).
- Produces: `desktop/dist/DeviceRescue-0.1.0-mac-arm64.dmg` bundling the engine via `extraResources`.

- [ ] **Step 1: Add electron-builder config to `package.json`**

```json
"scripts": { "start": "electron .", "dist": "electron-builder" },
"build": {
  "appId": "xyz.multiverse.devicerescue",
  "productName": "Device Rescue",
  "files": ["main.js", "preload.js", "engine-runner.js", "renderer/**", "shared/**"],
  "extraResources": [{ "from": "engine", "to": "engine" }],
  "mac": { "target": "dmg", "artifactName": "DeviceRescue-${version}-mac-${arch}.${ext}", "identity": null },
  "win": { "target": "nsis", "artifactName": "DeviceRescue-${version}-win-${arch}.${ext}" }
}
```

- [ ] **Step 2: Copy shared content into the app before build**

Add to a `prebuild`/`dist` step (or the build script): `cp ../shared/permissions-content.json shared/permissions-content.json` inside `desktop/` so it's packaged.

- [ ] **Step 3: Build the dmg**

Run: `cd desktop && npm run dist`
Expected: `desktop/dist/DeviceRescue-0.1.0-mac-arm64.dmg` exists.

- [ ] **Step 4: Install smoke test (real behavioral verification)**

Open the `.dmg`, drag to Applications, launch (use Open Anyway per the walkthrough), run a checkup, confirm results render.
Expected: end-to-end scan works from the packaged app.

- [ ] **Step 5: Commit**

```bash
git add desktop/package.json
git commit -m "build: electron-builder config; macOS .dmg bundling the engine"
```

---

### Task 8: Landing page (`site/`)

**Files:**
- Create: `site/index.html`, `site/styles.css`, `site/permissions.js`, `site/permissions-content.json` (copied from `shared/`), `site/Dockerfile`
- Test: local static-serve check

**Interfaces:**
- Consumes: `shared/permissions-content.json` (Task 2); GitHub Release asset URLs (Task 9).
- Produces: a static site with download buttons + per-OS "What you'll see the first time" walkthrough.

- [ ] **Step 1: Build `index.html` + `styles.css`**

Hero, one-line pitch, read-only-by-default safety note, **Download for Mac** button (href = Release asset URL, filled in Task 9), **Download for Windows** button (disabled until its asset exists), and a per-OS walkthrough section rendered by `permissions.js` from `permissions-content.json`. Note the ~500 MB size and system requirements.

- [ ] **Step 2: Add `site/Dockerfile` for Coolify (static via nginx)**

```dockerfile
FROM nginx:alpine
COPY . /usr/share/nginx/html
```

- [ ] **Step 3: Local serve check**

Run: `cd site && python -m http.server 8080` then open `http://localhost:8080`.
Expected: page renders; per-OS walkthrough visible; buttons present.

- [ ] **Step 4: Commit**

```bash
git add site
git commit -m "feat: landing page with downloads + per-OS permissions walkthrough"
```

---

### Task 9: GitHub Release with the macOS `.dmg`

**Files:** none (uses `gh`).

**Interfaces:**
- Consumes: `desktop/dist/DeviceRescue-0.1.0-mac-arm64.dmg` (Task 7).
- Produces: release `v0.1.0` with the dmg attached; asset URL wired into `site/index.html` (Task 8).

⚠️ Outward-facing (publishes publicly). Confirm with owner before running.

- [ ] **Step 1: Create the release + upload the dmg**

Run: `gh release create v0.1.0 desktop/dist/DeviceRescue-0.1.0-mac-arm64.dmg --title "Device Rescue 0.1.0" --notes "First public build (macOS, unsigned). Windows coming soon."`
Expected: prints the release URL.

- [ ] **Step 2: Wire the download URL into the page**

Set the Mac button href to `https://github.com/lizTheDeveloper/multiverse-device-rescue/releases/download/v0.1.0/DeviceRescue-0.1.0-mac-arm64.dmg`. Commit.

```bash
git add site/index.html && git commit -m "docs: point landing page Mac download at v0.1.0 release asset"
```

---

### Task 10: Deploy the landing page on Hetzner via Coolify  ⚠️ OWNER-ASSISTED

**Files:** none (infra).

**Interfaces:** Consumes `site/` (Task 8). Produces a live URL.

Not subagent-executable — needs interactive Bitwarden unlock + `ssh hetzner`.

- [ ] **Step 1: Owner confirms access**

Run (owner, interactive): `! ssh hetzner "echo ok"` and unlock Bitwarden.

- [ ] **Step 2: Read Coolify + domain creds from Bitwarden**

Via `ssh hetzner` and `bw`, retrieve the Coolify admin/API token and the target domain.

- [ ] **Step 3: Create a Coolify static/Docker app pointing at the repo `site/` dir**

Configure a new Coolify resource (Dockerfile build from `site/`), set the domain, deploy. Coolify pulls from GitHub (no GitHub Actions).

- [ ] **Step 4: Verify**

Open the deployed URL; confirm the page renders and the Mac download link resolves to the Release asset.

---

### Task 11: Windows build handoff  ⚠️ OWNER-RUN

**Files:**
- Create: `scripts/build-windows.bat`

**Interfaces:** Produces `DeviceRescue-0.1.0-win-x64.exe`, uploaded to the v0.1.0 release; then enable the Windows button on the page.

Not subagent-executable — requires a Windows PC.

- [ ] **Step 1: Write `scripts/build-windows.bat`**

```bat
@echo off
setlocal
cd /d %~dp0\..
python -m pip install pyinstaller || goto :err
python scripts\build.py || goto :err
if not exist desktop\engine mkdir desktop\engine
copy /Y dist\rescue.exe desktop\engine\rescue.exe || goto :err
cd desktop
call npm install || goto :err
copy /Y ..\shared\permissions-content.json shared\permissions-content.json || goto :err
call npm run dist || goto :err
echo Build complete: see desktop\dist\
goto :eof
:err
echo Build failed & exit /b 1
```

- [ ] **Step 2: Owner runs it on Windows, uploads the exe**

Run (owner, Windows): `scripts\build-windows.bat`, then
`gh release upload v0.1.0 desktop\dist\DeviceRescue-0.1.0-win-x64.exe`.

- [ ] **Step 3: Enable the Windows button**

Set the Windows button href to the uploaded asset and remove the disabled state. Commit + redeploy (Task 10 redeploy).

- [ ] **Step 4: Commit the script**

```bash
git add scripts/build-windows.bat
git commit -m "build: Windows build script for owner-run .exe packaging"
```

---

## Self-Review

**Spec coverage:** §2 Electron/JSON bridge → Tasks 1,3,4. §3.1 JSON → Task 1. §3.2 UI/read-only → Task 5. §3.3 packaging → Tasks 6,7. §3.4 Releases → Task 9. §3.5 landing page → Task 8. §4 per-OS walkthroughs → Tasks 2,5,8. §5 unsigned → Tasks 7 (`identity:null`), 8/2 (walkthroughs). §6 sequencing → task order. §7 Windows handoff → Task 11. §8 testing → smoke steps in Tasks 1,6,7,8. Deploy → Task 10. All covered.

**Placeholder scan:** UI copy in Tasks 2/5/8 references spec §4 for exact content; the JSON file (Task 2) is the single source authored there. No "TBD"/"handle edge cases". Code steps show code.

**Type consistency:** `runScan()`/`parseEngineOutput()`/`resolveEnginePath()` consistent across Tasks 4–5; JSON schema (`schema_version`, `platform`, `modules[].{name,status,error,findings}`) consistent across Tasks 1,4,5,8.

## Dependency graph (for execution / fan-out)

- **Independent (can start in parallel):** Task 1 (engine JSON), Task 2 (permissions content), Task 11 script authoring.
- **Then:** Task 3 (scaffold) → Task 4 (needs 1's schema + 3) → Task 5 (needs 2,4). Task 6 (needs 1) can run parallel to 3–5.
- **Then:** Task 7 (needs 5,6) → Task 9 (needs 7) → Task 8 (needs 2,9 for final URL; page shell can start after 2) → Task 10 (needs 8, owner).
- **Owner-in-the-loop:** Tasks 10, 11 (not subagent-executable).
