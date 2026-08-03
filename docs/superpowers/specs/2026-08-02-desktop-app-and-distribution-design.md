# Desktop app + distribution — design

**Status:** approved in brainstorming 2026-08-02; pending spec review.
**Goal:** let a non-technical person download Multiverse Device Rescue, double-click
it, and run a guided check on macOS and Windows — with a landing page hosted on
Hetzner (via Coolify) and downloads served from GitHub Releases.

## 1. Overview

Today the tool is a Python CLI + Textual TUI, packaged as a single-file
PyInstaller binary (`rescue.spec`, `scripts/build.py`). There is no graphical
front end, no download page, and no published release.

This project adds:

1. **An Electron desktop app** ("Device Rescue") that wraps the existing engine
   in a point-and-click window, with built-in onboarding that walks the user
   through the OS permission prompts and warning popups they will see.
2. **A `--json` output mode** on the engine so the Electron UI consumes
   structured results instead of scraping human text.
3. **Packaging + distribution**: `.dmg` (macOS) and `.exe`/NSIS installer
   (Windows), published to **GitHub Releases**.
4. **A landing page** deployed on **Hetzner via Coolify**, with the same
   permissions/popups walkthrough per OS and big download buttons.

### Non-goals
- **No code signing / notarization now.** Ship unsigned; document the one-time
  OS override. (macOS notarization would remove the warning later; a $99/yr
  Apple Developer ID is out of scope for v1.)
- **No Linux GUI.** Linux stays CLI-only (the engine already supports it); the
  landing page mentions the CLI path for Linux but ships no Electron build.
- **No re-implementation of checks in JS.** The Python engine stays the single
  source of truth; Electron is a thin shell over it.
- **No auto-update** in v1 (users re-download from the page). Revisit later.

## 2. Architecture

```
┌──────────────────────────── Electron app ────────────────────────────┐
│  Renderer (UI)          Main process                                   │
│  ┌───────────────┐      ┌──────────────────────────────────────────┐  │
│  │ Onboarding /  │◀────▶│ IPC bridge (preload, contextIsolation on) │  │
│  │ permissions   │      │   spawns bundled engine binary as a child  │  │
│  │ Scan screen   │      │   `rescue scan --json` → parses stdout      │  │
│  │ Results view  │      └──────────────────────────────────────────┘  │
│  └───────────────┘                     │                               │
└────────────────────────────────────────┼───────────────────────────────┘
                                          ▼
                         Bundled PyInstaller engine binary
                    (rescue / rescue.exe, in app resources)
```

- **Engine as subprocess.** The Electron main process spawns the bundled
  PyInstaller binary (`rescue scan --json`), reads stdout, and forwards parsed
  results to the renderer over IPC. The engine is bundled inside the Electron
  app's `resources/` (via electron-builder `extraResources`), so there is one
  downloadable artifact per OS.
- **Security posture of the shell:** `contextIsolation: true`,
  `nodeIntegration: false`, a minimal `preload.js` exposing only
  `runScan()` / `openSystemSetting()` style calls. The renderer never spawns
  processes directly.
- **Why Electron over Tauri:** chosen by the project owner. Accepted tradeoff:
  larger artifacts (~150–200 MB Electron + ~350 MB engine ≈ 500 MB download).

## 3. Components

### 3.1 Engine: `--json` output mode
- Add a dedicated **`rescue scan --json`** subcommand — read-only checks only,
  never fixes — that runs `Orchestrator.run_checks()` and serializes results to
  JSON on stdout:
  `{ "schema_version", "platform", "modules": [ { name, status, findings:[…],
  error } ] }`.
- Serialization: `dataclasses.asdict` on `Finding` / `CheckResult`, with enum
  values coerced to their `.value` (all model enums are `str`-backed).
- Human logs/warnings go to **stderr only**, so stdout is clean JSON (this
  matters — the engine already prints an integrity warning at startup).
- Add tests: JSON is valid, schema_version present, enums are strings, stdout
  contains nothing but the JSON document.

### 3.2 Electron app (`desktop/`)
- `desktop/` package: `main.js`, `preload.js`, `renderer/` (HTML/CSS/JS UI),
  `package.json` with electron-builder config.
- Screens:
  1. **Welcome** — what it does + the read-only-by-default safety framing.
  2. **Permissions walkthrough** (per-OS, see §4) — shown before first scan.
  3. **Scan** — a "Run checkup" button; progress; then results.
  4. **Results** — findings grouped by severity, each with plain-language
     explanation; heavy/opt-in actions (e.g. iPhone spyware scan) clearly
     gated behind an explicit button, never automatic.
- The app runs the engine in **read-only check mode** by default. Any fix that
  mutates the system requires an explicit per-item confirmation in the UI
  (mirrors the CLI's `--yes`/`auto_apply` gate).

### 3.3 Packaging (electron-builder)
- macOS: `.dmg` (drag-to-Applications), arm64 (+ x64 if feasible).
- Windows: NSIS `.exe` installer (built by the owner on their Windows PC via a
  provided script; see §7).
- electron-builder `extraResources` bundles the platform engine binary.
- Artifacts named `DeviceRescue-<version>-<os>-<arch>.<ext>`.

### 3.4 Distribution (GitHub Releases)
- A tagged release (`v0.1.0`) holds the macOS `.dmg` now; the Windows installer
  is added when the owner builds it. Landing page links directly to these
  assets. Releases handle the large files and give stable URLs.

### 3.5 Landing page (Coolify on Hetzner)
- Static, self-contained page (`site/`): hero + one-line pitch, safety framing,
  **Download for Mac / Download for Windows** buttons (Windows enabled once its
  asset exists), and a per-OS **"What you'll see the first time"** section (§4).
- Deployed via **Coolify** (pulls the repo/dir from GitHub and serves it — no
  GitHub Actions). Deploy steps: `ssh hetzner`, read Coolify + domain creds
  from Bitwarden, create/point a static-site app at the repo, set the domain.

## 4. Per-OS permissions & popups walkthrough (in BOTH the app and the page)

This content is authored once as shared copy and rendered in the Electron
onboarding screen and on the landing page.

### macOS
1. **"Device Rescue can't be opened because Apple cannot check it for malware."**
   (Unsigned download / Gatekeeper.) → **System Settings → Privacy & Security →**
   scroll to the message about Device Rescue → **"Open Anyway"** → confirm. One
   time per download. (Right-click→Open no longer reliably works on Sequoia.)
2. **Full Disk Access** — for checks that read protected locations (other apps'
   data, iOS backups, etc.): **System Settings → Privacy & Security → Full Disk
   Access → enable Device Rescue** (toggle on; may prompt to quit/reopen). The
   app detects missing access and links straight to this pane.
3. **Files & Folders / Documents-Desktop-Downloads prompts** (TCC) — click
   **Allow**; explain what each is for.
4. **Administrator password** — only appears if the user chooses to apply a fix
   that changes a system setting; read-only checks never prompt for it.
5. (If the app uses Automation to open Settings panes) **"Device Rescue wants to
   control System Events"** → **Allow**.

### Windows
1. **"Windows protected your PC" (SmartScreen)** — unsigned installer →
   **More info → Run anyway**.
2. **User Account Control (UAC)** elevation prompt — appears for checks/fixes
   that need admin; **Yes** to allow. Read-only checks run without it where
   possible.
3. **Antivirus / Defender false-positive note** — an unsigned PyInstaller-based
   binary is sometimes flagged; explain it's expected for unsigned tools and how
   to allow it. (Signing later removes this.)

### Linux (page only, brief)
- CLI install path (`pip install .` / release binary); note no GUI build yet.

## 5. Signing status
- Unsigned for v1. The walkthroughs (§4) are the mitigation. The spec records
  notarization (macOS) and Authenticode signing (Windows) as the clear next
  step to remove all warnings, deferred by owner decision.

## 6. Build & deploy sequencing
1. Engine `--json` mode + tests.
2. Rebuild + verify the macOS engine binary from current source.
3. Electron app (`desktop/`): shell, IPC, screens, permissions onboarding.
4. `electron-builder` → macOS `.dmg`; smoke-test the double-click flow.
5. Landing page (`site/`) with per-OS walkthroughs.
6. GitHub Release `v0.1.0` with the macOS `.dmg`.
7. Coolify deploy of the page on Hetzner (SSH + Bitwarden creds + domain).
8. Provide `build-windows.bat`; owner builds `.exe`; add it to the release and
   flip the Windows button on.

## 7. Windows build handoff
- `scripts/build-windows.bat`: creates a venv, `pip install -r` deps +
  PyInstaller + electron-builder, builds the engine `.exe`, then the Electron
  installer, and prints the output path. Owner runs it on their Windows PC and
  uploads the artifact to the GitHub Release.

## 8. Testing / verification
- Engine: unit tests for `--json` (valid JSON, clean stdout, enum coercion).
- Electron: manual smoke test — launch, run a read-only checkup, see results;
  verify the permissions screen renders the correct OS content.
- Packaging: install the `.dmg` on this Mac, confirm double-click launches and a
  scan completes end-to-end (real behavioral verification, not just a build).
- Landing page: verify download links resolve to the Release assets and the page
  renders on the deployed Coolify URL.

## 9. Risks & open questions
- **Artifact size** (~500 MB) — acceptable; note on the page.
- **macOS x64 coverage** — build arm64 first; add Intel if the toolchain allows
  from this machine, else defer.
- **Coolify specifics** — exact app-type/domain steps confirmed at deploy time
  from Bitwarden/`ssh hetzner`; Bitwarden must be unlocked interactively.
- **Engine startup integrity warning** must go to stderr so it never corrupts
  the `--json` stdout stream.
- **Full Disk Access UX** — the app should degrade gracefully (report what it
  couldn't read) rather than fail if the user declines.
