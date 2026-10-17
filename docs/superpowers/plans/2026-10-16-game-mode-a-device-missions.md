# Game Mode A: Device Missions Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The Device Rescue desktop app can show a scan as a Reclaim City-style city. Each warning or critical finding is a mission: a briefing, then a fix (the person's own, or the existing "Fix it for me"), then a re-check of that one module. A building lights up only when the re-check confirms the problem is gone.

**Architecture:**
- **Engine.** It gains `rescue scan --json --module <name>` (repeatable). Each module entry in the scan JSON also gains its `category`.
- **Electron.**
  - The renderer is served from a privileged `app://rescue/` scheme. `assets/` maps to the game's art in the git submodule `desktop/vendor/reclaim-city`, and `rc/` maps to an allowlist of game source files.
  - The main process keeps the last full scan, merges re-check results into it, and re-arms the existing fix and mark policies from the merged result.
- **Game mode.** ES modules in `desktop/renderer/game/`, rendered into a shadow root on a new `screen-city` section.
  - Pure modules turn scan JSON into a city, track progress and produce HTML.
  - One DOM controller wires them to `window.rescue` and to the existing `FixFlow` and `MarkFlow`.
- **Glue.** `app.js` keeps ownership of screens, the scan and the safety gate. It talks to game mode through `window.RescueGame` and `window.RescueHost`.

**Tech Stack:** Python 3.11+ / click (engine); Electron 41, plain JS with no bundler (desktop); `node --test` (desktop tests, Node 22); pytest (engine tests).

**Spec:** `docs/superpowers/specs/2026-10-16-game-mode-device-missions-design.md`. Read its "Changes made during planning" section first, because it overrides parts of the sections below it. Overview: `docs/superpowers/specs/2026-10-16-consumer-security-game-overview.md`.

## Global Constraints

- **Vendored game commit:** privacy-the-game `317e61c844f00dbb192249239b58f1e28a2eeb60`. Submodule path `desktop/vendor/reclaim-city`, URL `https://github.com/lizTheDeveloper/privacy-the-game.git`.
- **Opt-out keys:** set `reclaim-city.analytics-off = "1"` and `umami.disabled = "1"` in localStorage before any vendored module is imported.
- **Never load from the vendored game:** `src/app.js`, `src/index.html`, `src/sw.js`, or any Sentry/Umami script. The CSP stays `default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;`.
- **Fixes:** every fix goes through the existing `FixFlow` confirmation (`desktop/renderer/fix-flow.js`), and every mark through `MarkFlow` (`mark-flow.js`). Game mode never calls `runFix`, `runAction` or `markMine` directly.
- **Done means re-checked.** A mission is `reclaimed` only when a re-check or a full scan no longer reports it. `yours` (marked by the person) is never counted as fixed.
- **"Couldn't check" is never shown as safe.** A district with failed checks is fog, and a district where no checks ran says "No checks ran here", never "clear".
- **Safety gate:** game mode is hidden for the worry `watched` (`safety: true`), for the worry `phone`, and when a module in `ALWAYS_SAFETY_MODULES` (`stalkerware_scan`, `mvt_spyware_scan`, `keylogger_indicators`) reports a warning or critical finding. It's checked after every scan and every re-check.
- **District names (placeholders until review):** security → The Gatehouse, network → The Wires, integrity → The Foundations, performance → The Engine Room, bloatware → The Junkyard, anything else → The Outskirts.
- **Storage keys:** `device-rescue.game.v1` for progress, `device-rescue.view` for the last view chosen (`list` | `city`).
- **Escaping:** everything that comes from the engine is HTML-escaped before it's rendered.
- **Disk:** the submodule is added with `--reference /Users/annhoward/src/privacy-the-game`, so it shares objects with the existing clone. Never commit `node_modules`.
- **Writing rules:** no time estimates in docs or UI copy. Copy is written for a frightened non-technical person: short, direct, and never "you're safe" or "all clear".

## Review Focus

1. **A finding whose `category` isn't one of the five** (for example `"test"`, or a category added later) must land in The Outskirts. It must not be dropped or crash the build. Owned by Task 7.
2. **Re-checking a module that comes back missing** from the partial result (the platform filter dropped it), with `status: "error"`, or with `supported: false`, must say "Couldn't re-check" and give no credit. It must not read as "gone". Owned by Task 3 (main) and Task 8 (outcome).
3. **Engine text containing HTML** (`<img src=x onerror=…>` in a title, description, path or step body) must render as text in every game view. Owned by Task 9.
4. **localStorage that throws or holds corrupt JSON** (sandboxed or private storage) must still let the city render from the scan, with progress starting empty. Owned by Task 8.
5. **A finding that disappears because its module couldn't run in the next full scan** must keep its earlier status. It must not be credited as reclaimed. Owned by Task 8.
6. **A finding the person marked as theirs**, which the engine lowers to `info` and retitles, must stay a mission with status `yours`. It must not become a note and then count as reclaimed. Found during planning in `rescue/known_items.py`. Owned by Task 7.

---

## File Structure

**Engine**
- Modify `rescue/cli.py`: `scan --module`.
- Modify `rescue/serialize.py`: each module entry gets `category`.
- Test `tests/test_cli_scan_module.py`.
- Modify `docs/cli.md`.

**Desktop main process** (CommonJS)
- Create `desktop/app-protocol.js`: `resolveAppPath`, `serveApp`.
- Create `desktop/recheck.js`: `mergeModuleResult`, `handleRecheck`.
- Modify `desktop/engine-runner.js`: `scanModuleArgs`, `runRecheck`.
- Modify `desktop/main.js`: register the scheme, load `app://rescue/index.html`, keep the last scan, add the `recheck-module` IPC.
- Modify `desktop/preload.js`: `recheckModule`.
- Modify `desktop/package.json`: test glob, `files`.

**Renderer, classic scripts** (CommonJS-exportable)
- Modify `desktop/renderer/fix-flow.js` and `mark-flow.js`: an optional `hooks.onResult`.
- Modify `desktop/renderer/app.js`: `mayBeWatched`, `gameOfferedFor`, the Welcome button, the results switch, the city screen, `window.RescueHost`.
- Modify `desktop/renderer/index.html`: the city screen, the module script, the fonts stylesheet.
- Create `desktop/renderer/game-fonts.css` and `desktop/renderer/game/fonts/*.woff2` plus `OFL.txt`.

**Renderer, game mode** (ES modules; `desktop/renderer/game/package.json` sets `"type": "module"`)
- `game/opt-out.js`: `applyOptOut`.
- `game/boot-core.js`: `boot()`. `game/boot.js` is the entry point and calls `boot()`.
- `game/escape.js`: `esc`.
- `game/findings-to-city.js`: `DISTRICTS`, `findingIdentity`, `missionSteps`, `findingsToCity`.
- `game/progress.js`: `STORE_KEY`, `loadProgress`, `saveProgress`, `reconcile`, `setStatus`, `recheckOutcome`, `countReclaimed`.
- `game/scout-lines.js`: `SCOUT`, `mapScoutLine`, `debriefReply`.
- `game/views/hud.js`, `views/map.js`, `views/district.js`, `views/briefing.js`, `views/outcome.js`, `views/milestone.js`: pure HTML.
- `game/controller.js`: `createController`, the only file in game mode that touches the DOM.
- `game/game.css`: styles inside the shadow root.

**Vendor**
- `.gitmodules` and `desktop/vendor/reclaim-city` (the submodule).

**Tests** (`desktop/test/`)
- `app-protocol.test.js`, `recheck.test.js`
- `engine-runner.test.js` (extended), `fix-flow.test.js` (extended), `mark-flow.test.js` (extended)
- `game-gate.test.js`, `game-boot.test.js`, `game-findings-to-city.test.js`, `game-progress.test.js`, `game-views.test.js`, `game-vendor-contract.test.js`

**CI and docs**
- `.github/workflows/tests.yml`, `.github/workflows/release.yml`
- `CONTRIBUTING.md`, `README.md`

---

### Task 1: Engine: `scan --module` and module `category` in the JSON

**Files:**
- Modify: `rescue/cli.py`, the `scan` command (around lines 140–184)
- Modify: `rescue/serialize.py`, `checks_to_json` (around lines 143–163)
- Modify: `docs/cli.md` (the `rescue scan` section, around lines 117–171)
- Test: `tests/test_cli_scan_module.py`

**Interfaces:**
- Consumes: `rescue.profiles.Profile(name, display_name, description, include_modules=[...])`, `rescue.registry.discover_modules(dir)`, `Orchestrator(modules_dir=..., profile=...)`.
- Produces:
  - CLI: `rescue scan --json --module <name> [--module <name> ...]`. It exits `1` for an unknown module and `2` when combined with `--profile`.
  - JSON: each `modules[]` entry gains `"category": <str|null>`. Task 7 relies on this.

- [ ] **Step 1: Write the failing tests**

Create `tests/test_cli_scan_module.py`:

```python
import json
from unittest.mock import patch

from click.testing import CliRunner

from rescue.cli import main
from rescue.models import CheckResult


def _mock_module(name, category="security"):
    return type("MockModule", (), {"name": name, "category": category,
                                   "report": lambda self, check, fix=None: ""})()


def test_module_option_builds_a_profile_with_only_those_modules():
    mod = _mock_module("launch_agent_audit")
    with patch("rescue.cli.discover_modules") as disc, patch("rescue.cli.Orchestrator") as Orch:
        disc.return_value = [mod, _mock_module("disk_space", "performance")]
        Orch.return_value.run_checks.return_value = [(mod, CheckResult(module_name=mod.name, findings=[]))]
        result = CliRunner().invoke(main, ["scan", "--json", "--module", "launch_agent_audit"])
    assert result.exit_code == 0, result.output
    profile = Orch.call_args.kwargs["profile"]
    assert profile.include_modules == ["launch_agent_audit"]
    doc = json.loads(result.stdout)
    assert [m["name"] for m in doc["modules"]] == ["launch_agent_audit"]


def test_module_option_repeats_and_dedupes_in_order():
    a, b = _mock_module("a_mod"), _mock_module("b_mod")
    with patch("rescue.cli.discover_modules") as disc, patch("rescue.cli.Orchestrator") as Orch:
        disc.return_value = [a, b]
        Orch.return_value.run_checks.return_value = []
        result = CliRunner().invoke(main, ["scan", "--json", "--module", "b_mod", "--module", "a_mod", "--module", "b_mod"])
    assert result.exit_code == 0, result.output
    assert Orch.call_args.kwargs["profile"].include_modules == ["b_mod", "a_mod"]


def test_unknown_module_exits_1_and_lists_available_names():
    with patch("rescue.cli.discover_modules") as disc:
        disc.return_value = [_mock_module("disk_space")]
        result = CliRunner().invoke(main, ["scan", "--json", "--module", "nope"])
    assert result.exit_code == 1
    assert "Unknown module" in result.stderr
    assert "disk_space" in result.stderr
    assert result.stdout == ""


def test_module_and_profile_together_is_a_usage_error():
    result = CliRunner().invoke(main, ["scan", "--json", "--module", "disk_space", "--profile", "digital_security_reset"])
    assert result.exit_code == 2
    assert "not both" in result.stderr


def test_module_entries_carry_their_category():
    mod = _mock_module("launch_agent_audit", "security")
    with patch("rescue.cli.Orchestrator") as Orch:
        Orch.return_value.run_checks.return_value = [(mod, CheckResult(module_name=mod.name, findings=[]))]
        result = CliRunner().invoke(main, ["scan", "--json"])
    doc = json.loads(result.stdout)
    assert doc["modules"][0]["category"] == "security"


def test_module_without_category_attribute_serializes_null():
    mod = type("Bare", (), {"name": "bare", "report": lambda self, check, fix=None: ""})()
    with patch("rescue.cli.Orchestrator") as Orch:
        Orch.return_value.run_checks.return_value = [(mod, CheckResult(module_name="bare", findings=[]))]
        result = CliRunner().invoke(main, ["scan", "--json"])
    assert json.loads(result.stdout)["modules"][0]["category"] is None


def test_real_single_module_scan_is_read_only(monkeypatch):
    # A real, cheap, cross-platform module. run_fixes must never be reached.
    monkeypatch.setenv("RESCUE_TEST_MODE", "1")
    with patch("rescue.orchestrator.Orchestrator.run_fixes", side_effect=AssertionError("scan must not fix")):
        result = CliRunner().invoke(main, ["scan", "--json", "--no-attribution", "--module", "disk_space"])
    assert result.exit_code == 0, result.output
    doc = json.loads(result.stdout)
    assert [m["name"] for m in doc["modules"]] == ["disk_space"]
    assert doc["modules"][0]["category"] == "performance"
```

- [ ] **Step 2: Run the tests to make sure they fail**

Run: `.venv/bin/python -m pytest tests/test_cli_scan_module.py -q`
Expected: FAIL. You'll see `no such option: --module`, and `KeyError: 'category'` in the category tests.

Before going on, confirm the module's real category with `grep -rn "category" modules/performance/disk_space/*.py`. If `disk_space` isn't `performance`, change the expected value in the last test to the real category.

- [ ] **Step 3: Implement `--module` in `rescue/cli.py`**

Add `Profile` to the imports from `rescue.profiles`:

```python
from rescue.profiles import Profile, ProfileValidationError, discover_profiles, validate_profile_modules
```

Add this helper just under `_load_profile_or_exit`:

```python
def _module_only_profile(module_names):
    """A throwaway profile that runs only the named modules, in the order given."""
    names = list(dict.fromkeys(module_names))
    available = {m.name for m in discover_modules(_get_modules_dir())}
    unknown = [n for n in names if n not in available]
    if unknown:
        click.echo(f"Unknown module(s): {', '.join(unknown)}", err=True)
        click.echo(f"Available: {', '.join(sorted(available))}", err=True)
        raise SystemExit(1)
    return Profile(
        name="selected_modules",
        display_name="Selected modules",
        description="Only the modules named with --module.",
        include_modules=names,
    )
```

Change the `scan` command's decorators and the start of its body. Leave the rest as it is:

```python
@main.command()
@click.option("--json", "as_json", is_flag=True, help="Emit read-only check results as JSON on stdout.")
@click.option("--profile", "profile_name", default=None, help="Only run the modules a profile selects.")
@click.option(
    "--module",
    "module_names",
    multiple=True,
    help="Only run this module (repeatable). Read-only; same JSON. Not with --profile.",
)
@click.option(
    "--progress",
    is_flag=True,
    help='Write one {"progress": ...} JSON line per check to stderr as the scan runs.',
)
@click.option(
    "--trace",
    is_flag=True,
    help='Also write one {"exec": ...} JSON line to stderr for every external command run. Implies --progress.',
)
@click.option(
    "--no-attribution",
    is_flag=True,
    help='Skip the "Who made it?" lookups (code-signature checks) that add made_by to findings.',
)
def scan(as_json, profile_name, module_names, progress, trace, no_attribution):
    """Run read-only checks. With --json, print structured results to stdout."""
    from rescue.serialize import checks_to_json
    if profile_name and module_names:
        raise click.UsageError("Use --profile or --module, not both.")
    if module_names:
        threat_profile = _module_only_profile(module_names)
    else:
        threat_profile = _load_profile_or_exit(profile_name) if profile_name else None
    profile = gather_profile()
```

- [ ] **Step 4: Add `category` in `rescue/serialize.py`**

In `checks_to_json`, add one key to the dict appended per module, straight after `"name": mod.name,`:

```python
            "category": getattr(mod, "category", None),
```

Add one line to the docstring under "Returns": `Each module entry has name, category, status, error, supported, unsupported_reason, findings.`

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `.venv/bin/python -m pytest tests/test_cli_scan_module.py tests/test_cli_scan_json.py tests/test_scan_trace.py -q`
Expected: all PASS.

- [ ] **Step 6: Update `docs/cli.md`**

In the `rescue scan` section:
- Change the usage line to `$ rescue scan [--json] [--profile <name> | --module <name> ...]`.
- Remove the sentence saying scan "takes no profile".
- Add these rows to the flag table:

```markdown
| `--profile <name>` | Only run the modules the named profile selects. Exits `1` on an unknown or invalid profile. |
| `--module <name>` | Only run this module. Repeat it to run several. Read-only, same JSON. Exits `1` on an unknown module (the valid names go to stderr), and `2` if combined with `--profile`. The desktop app uses it to re-check one finding after a fix. |
```

In the JSON example, add `"category": "integrity",` after `"name": "linux_package_updates",`.

- [ ] **Step 7: Run the whole Python suite**

Run: `RESCUE_TEST_MODE=1 .venv/bin/python -m pytest -q`
Expected: PASS, with the same skips as `main`.

- [ ] **Step 8: Commit**

```bash
git add rescue/cli.py rescue/serialize.py tests/test_cli_scan_module.py docs/cli.md
git commit -m "Let scan run named modules only, and say each module's category"
```

---

### Task 2: Vendor the game, and point the test runner at our tests only

**Files:**
- Create: `.gitmodules`, `desktop/vendor/reclaim-city` (submodule)
- Modify: `desktop/package.json` (`scripts.test`, `build.files`)
- Test: `desktop/test/game-vendor-contract.test.js`

**Interfaces:**
- Produces:
  - Vendored files that later tasks import: `desktop/vendor/reclaim-city/src/components/scout.js`, which exports `scoutSprite(feeling, {size, style, attrs})` and `FEELINGS`.
  - Vendored files that later tasks link: `desktop/vendor/reclaim-city/src/style.css` and `desktop/vendor/reclaim-city/src/assets/**`.

- [ ] **Step 1: Write the failing contract test**

Create `desktop/test/game-vendor-contract.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const fs = require('fs');
const path = require('path');

const SRC = path.join(__dirname, '..', 'vendor', 'reclaim-city', 'src');
const need = (rel) => path.join(SRC, rel);

test('the Reclaim City submodule is checked out (run: git submodule update --init)', () => {
  assert.ok(fs.existsSync(need('components/scout.js')),
    'desktop/vendor/reclaim-city is empty. Run: git submodule update --init');
});

test('every file game mode loads from the game exists', () => {
  for (const rel of ['components/scout.js', 'style.css', 'assets/characters/scout_0.png',
    'assets/iso_occupied.png', 'assets/iso_progress.png', 'assets/iso_liberated.png',
    'assets/iso_tower_occ.png', 'assets/iso_tower_lib.png']) {
    assert.ok(fs.existsSync(need(rel)), `missing ${rel}`);
  }
});

test('scoutSprite renders a sheet that exists on disk, for every feeling game mode uses', async () => {
  const { scoutSprite, FEELINGS } = await import(path.join(SRC, 'components', 'scout.js'));
  for (const feeling of ['happy', 'proud', 'wave', 'thinkingA', 'worried']) {
    assert.ok(FEELINGS[feeling], `feeling ${feeling} gone upstream`);
    const html = scoutSprite(feeling, { size: 64 });
    const m = html.match(/url\((assets\/characters\/scout\/[a-z-]+\.png)\)/);
    assert.ok(m, `no sheet url in: ${html}`);
    assert.ok(fs.existsSync(need(m[1])), `sheet missing on disk: ${m[1]}`);
  }
});

test('scout.js imports nothing (game mode relies on it being self-contained)', () => {
  const text = fs.readFileSync(need('components/scout.js'), 'utf8');
  assert.doesNotMatch(text, /^\s*import\s/m);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-vendor-contract.test.js`
Expected: FAIL with `desktop/vendor/reclaim-city is empty`.

- [ ] **Step 3: Add the submodule, pinned, sharing objects with the existing local clone**

```bash
cd /Users/annhoward/src/multiverse_device_rescue
git submodule add --reference /Users/annhoward/src/privacy-the-game \
  https://github.com/lizTheDeveloper/privacy-the-game.git desktop/vendor/reclaim-city
git -C desktop/vendor/reclaim-city checkout 317e61c844f00dbb192249239b58f1e28a2eeb60
git add .gitmodules desktop/vendor/reclaim-city
```

Never `cd` into `/Users/annhoward/src/privacy-the-game` to change anything. It has uncommitted work.

- [ ] **Step 4: Point the test runner at our tests only**

In `desktop/package.json`, set `"test": "node --test \"test/**/*.test.js\""`. Bare `node --test` would also find the submodule's vitest files, and they'd fail.

In `build.files`, add these entries after `"renderer/**"`:

```json
      "app-protocol.js",
      "recheck.js",
      "vendor/reclaim-city/src/components/scout.js",
      "vendor/reclaim-city/src/style.css",
      "vendor/reclaim-city/src/assets/**"
```

(`app-protocol.js` and `recheck.js` are created in Tasks 3 and 4. Listing them now is harmless.)

- [ ] **Step 5: Run the desktop suite**

Run: `cd desktop && npm test`
Expected: PASS. The count goes up by the 4 contract tests, and nothing from `vendor/` runs.

- [ ] **Step 6: Commit**

```bash
git add .gitmodules desktop/vendor/reclaim-city desktop/package.json desktop/test/game-vendor-contract.test.js
git commit -m "Vendor Reclaim City at 317e61c as a submodule for game mode"
```

---

### Task 3: Serve the app from `app://rescue/`

**Files:**
- Create: `desktop/app-protocol.js`
- Modify: `desktop/main.js` (top-level `require`s, before `app.whenReady`, `createWindow`)
- Test: `desktop/test/app-protocol.test.js`

**Interfaces:**
- Produces:
  - `resolveAppPath(url: string, baseDir: string) -> {file: string, mime: string} | null`
  - `serveApp(url, baseDir, readFile = fs.promises.readFile) -> Promise<Response>`
  - `APP_ORIGIN = 'app://rescue/'`
  - `RC_ALLOW: RegExp[]`, exported so Spec B can extend it.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/app-protocol.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const path = require('path');
const { resolveAppPath, serveApp, APP_ORIGIN } = require('../app-protocol');

const BASE = path.join('/tmp', 'desk');
const R = (p) => path.join(BASE, 'renderer', p);
const V = (p) => path.join(BASE, 'vendor', 'reclaim-city', 'src', p);

test('the page and its own files come from renderer/', () => {
  assert.deepStrictEqual(resolveAppPath(`${APP_ORIGIN}index.html`, BASE), { file: R('index.html'), mime: 'text/html; charset=utf-8' });
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}`, BASE).file, R('index.html'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}app.js`, BASE).mime, 'text/javascript; charset=utf-8');
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}game/views/map.js`, BASE).file, R('game/views/map.js'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}game/fonts/inter-latin-400-normal.woff2`, BASE).mime, 'font/woff2');
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}permissions-content.json`, BASE).mime, 'application/json');
});

test('assets/ is the game art, png only', () => {
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}assets/characters/scout/happy.png`, BASE).file, V('assets/characters/scout/happy.png'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}assets/x.js`, BASE), null);
});

test('rc/ serves only the allowlisted game sources', () => {
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/components/scout.js`, BASE).file, V('components/scout.js'));
  assert.strictEqual(resolveAppPath(`${APP_ORIGIN}rc/style.css`, BASE).mime, 'text/css; charset=utf-8');
  for (const p of ['rc/app.js', 'rc/index.html', 'rc/sw.js', 'rc/utils/analytics.js', 'rc/utils/errors.js']) {
    assert.strictEqual(resolveAppPath(`${APP_ORIGIN}${p}`, BASE), null, p);
  }
});

test('odd hosts, schemes, encodings and file types are refused', () => {
  for (const url of [
    `${APP_ORIGIN}assets/..%2f..%2fapp.js`, `${APP_ORIGIN}rc/..%2f..%2fmain.js`, `${APP_ORIGIN}game\\..\\..\\main.js`,
    `${APP_ORIGIN}a%00.js`, 'app://evil/index.html', 'file:///etc/passwd', 'https://rescue/index.html',
    `${APP_ORIGIN}engine/rescue`, `${APP_ORIGIN}index.html.exe`, 'not a url',
  ]) {
    assert.strictEqual(resolveAppPath(url, BASE), null, url);
  }
});

test('dot segments never climb out of renderer/ (the URL parser collapses them first)', () => {
  // new URL('app://rescue/%2e%2e/main.js').pathname is '/main.js': it can only
  // ever name renderer/main.js, which does not exist, never desktop/main.js.
  for (const url of [`${APP_ORIGIN}../main.js`, `${APP_ORIGIN}%2e%2e/main.js`, `${APP_ORIGIN}game/%2e%2e/%2e%2e/main.js`,
    `${APP_ORIGIN}assets/../../../main.js`, `${APP_ORIGIN}rc/../../main.js`]) {
    const hit = resolveAppPath(url, BASE);
    assert.ok(hit === null || hit.file.startsWith(path.join(BASE, 'renderer') + path.sep), `${url} -> ${hit && hit.file}`);
  }
});

test('serveApp answers 404 for refused paths and sets the type for served ones', async () => {
  const miss = await serveApp('app://evil/x', BASE, async () => Buffer.from(''));
  assert.strictEqual(miss.status, 404);
  const hit = await serveApp(`${APP_ORIGIN}app.js`, BASE, async (f) => { assert.strictEqual(f, R('app.js')); return Buffer.from('ok'); });
  assert.strictEqual(hit.status, 200);
  assert.strictEqual(hit.headers.get('content-type'), 'text/javascript; charset=utf-8');
  assert.strictEqual(await hit.text(), 'ok');
});

test('serveApp answers 404 when the file is missing', async () => {
  const res = await serveApp(`${APP_ORIGIN}nope.js`, BASE, async () => { const e = new Error('x'); e.code = 'ENOENT'; throw e; });
  assert.strictEqual(res.status, 404);
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/app-protocol.test.js`
Expected: FAIL with `Cannot find module '../app-protocol'`.

- [ ] **Step 3: Write `desktop/app-protocol.js`**

```js
// The app:// scheme the window loads from.
//
// app://rescue/<path> serves desktop/renderer/<path>. Two prefixes are mapped
// into the vendored Reclaim City game (desktop/vendor/reclaim-city/src), because
// its components use page-relative art paths ("assets/...") and game mode is ES
// modules, which need a real origin:
//   assets/<png>   -> the game's art
//   rc/<allowed>   -> only the game sources listed in RC_ALLOW
// Everything else is refused, and so is any path that tries to climb out.
const fs = require('fs');
const path = require('path');

const APP_ORIGIN = 'app://rescue/';
const MIME = {
  '.html': 'text/html; charset=utf-8',
  '.js': 'text/javascript; charset=utf-8',
  '.css': 'text/css; charset=utf-8',
  '.json': 'application/json',
  '.png': 'image/png',
  '.svg': 'image/svg+xml',
  '.woff2': 'font/woff2',
  '.txt': 'text/plain; charset=utf-8',
};
// Game sources game mode may load. Spec B extends this list.
const RC_ALLOW = [/^components\/scout\.js$/, /^style\.css$/];
const SAFE_PATH = /^[A-Za-z0-9._\-/]+$/;

function within(root, file) {
  const r = path.resolve(root) + path.sep;
  return path.resolve(file).startsWith(r);
}

function resolveAppPath(url, baseDir) {
  let u;
  try { u = new URL(url); } catch (_) { return null; }
  if (u.protocol !== 'app:' || u.host !== 'rescue') return null;
  let rel;
  try { rel = decodeURIComponent(u.pathname); } catch (_) { return null; }
  rel = rel.replace(/^\/+/, '');
  if (rel === '') rel = 'index.html';
  if (!SAFE_PATH.test(rel)) return null;
  const parts = rel.split('/');
  if (parts.some((p) => p === '' || p === '.' || p === '..')) return null;
  const mime = MIME[path.extname(rel).toLowerCase()];
  if (!mime) return null;

  const vendorSrc = path.join(baseDir, 'vendor', 'reclaim-city', 'src');
  let root;
  let file;
  if (parts[0] === 'assets') {
    if (path.extname(rel).toLowerCase() !== '.png') return null;
    root = path.join(vendorSrc, 'assets');
    file = path.join(vendorSrc, rel);
  } else if (parts[0] === 'rc') {
    const inner = parts.slice(1).join('/');
    if (!RC_ALLOW.some((re) => re.test(inner))) return null;
    root = vendorSrc;
    file = path.join(vendorSrc, inner);
  } else {
    root = path.join(baseDir, 'renderer');
    file = path.join(root, rel);
  }
  return within(root, file) ? { file, mime } : null;
}

async function serveApp(url, baseDir, readFile = fs.promises.readFile) {
  const hit = resolveAppPath(url, baseDir);
  if (!hit) return new Response('Not found', { status: 404 });
  try {
    const body = await readFile(hit.file);
    return new Response(body, { status: 200, headers: { 'content-type': hit.mime } });
  } catch (_) {
    return new Response('Not found', { status: 404 });
  }
}

module.exports = { APP_ORIGIN, RC_ALLOW, MIME, resolveAppPath, serveApp };
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/app-protocol.test.js`
Expected: PASS (7 tests).

- [ ] **Step 5: Wire it into `desktop/main.js`**

Change the first line to `const { app, BrowserWindow, ipcMain, shell, net, protocol } = require('electron');`. Then add these lines after the existing `require`s:

```js
const { APP_ORIGIN, serveApp } = require('./app-protocol');

// Must run before the app is ready. "standard" gives app:// a real origin, so
// ES modules, fetch() of local JSON and the CSP's 'self' all work.
protocol.registerSchemesAsPrivileged([
  { scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true } },
]);
```

In `createWindow`, replace `win.loadFile(path.join(__dirname, 'renderer', 'index.html'));` with:

```js
  win.loadURL(`${APP_ORIGIN}index.html`);
```

At the top of the `app.whenReady().then(() => {` callback, add:

```js
  protocol.handle('app', (request) => serveApp(request.url, __dirname));
```

- [ ] **Step 6: Run the app and make sure nothing regressed**

The window needs a working engine:

```bash
cd /Users/annhoward/src/multiverse_device_rescue
RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start
```

Check by hand:
1. The Welcome screen renders with its styles.
2. "Get started" → pick "I'm not sure" → the scan screen shows its permission tips. That proves `fetch('permissions-content.json')` works over `app://`.
3. Open DevTools (View → Toggle Developer Tools). The Console has no CSP errors.

Quit the app.

- [ ] **Step 7: Run the desktop suite**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 8: Commit**

```bash
git add desktop/app-protocol.js desktop/main.js desktop/test/app-protocol.test.js
git commit -m "Serve the desktop window from app://rescue/ so game mode can load modules and art"
```

---

### Task 4: Re-check one module: engine runner, merge, IPC, preload

**Files:**
- Modify: `desktop/engine-runner.js` (add after `runUndo`, and update `module.exports`)
- Create: `desktop/recheck.js`
- Modify: `desktop/main.js` (the `run-scan` handler, plus the new `recheck-module` handler)
- Modify: `desktop/preload.js`
- Test: `desktop/test/recheck.test.js`, `desktop/test/engine-runner.test.js` (add tests)

**Interfaces:**
- Consumes:
  - `runEngineJson(buildArgs, moduleName, spawnFn, timeoutMs, fail)` and `parseEngineOutput(out)`, both already in `engine-runner.js`.
  - `fixPolicy.remember(doc)` and `markPolicy.remember(doc)`.
- Produces:
  - `scanModuleArgs(name) -> string[]`
  - `runRecheck(name, spawnFn?, timeoutMs?) -> Promise<doc | {engine_error, message}>`. It never rejects.
  - `mergeModuleResult(lastDoc, partialDoc, name) -> {doc, module}`
  - `handleRecheck(name, {getLastDoc, setLastDoc, runRecheck, policies}) -> Promise<{ok:true, doc, module} | {ok:false, error:'not_allowed'|'no_scan'|'engine_error'|'not_rechecked', message}>`. It never throws.
  - IPC: `recheck-module`. Preload: `window.rescue.recheckModule(name)`.

- [ ] **Step 1: Write the failing tests**

Create `desktop/test/recheck.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { mergeModuleResult, handleRecheck } = require('../recheck');

const LAST = { schema_version: 1, platform: 'darwin', modules: [
  { name: 'a_mod', category: 'security', status: 'ok', supported: true, findings: [{ title: 'old a' }] },
  { name: 'b_mod', category: 'network', status: 'ok', supported: true, findings: [{ title: 'old b' }] },
] };
const PARTIAL = { schema_version: 1, platform: 'darwin', modules: [
  { name: 'a_mod', category: 'security', status: 'ok', supported: true, findings: [] },
] };

test('mergeModuleResult swaps only the re-checked module and keeps order', () => {
  const { doc, module } = mergeModuleResult(LAST, PARTIAL, 'a_mod');
  assert.deepStrictEqual(doc.modules.map((m) => m.name), ['a_mod', 'b_mod']);
  assert.deepStrictEqual(doc.modules[0].findings, []);
  assert.strictEqual(doc.modules[1], LAST.modules[1]);
  assert.strictEqual(module, PARTIAL.modules[0]);
  assert.strictEqual(LAST.modules[0].findings.length, 1, 'input not mutated');
});

test('mergeModuleResult reports a module missing from the partial result', () => {
  const { doc, module } = mergeModuleResult(LAST, { modules: [] }, 'a_mod');
  assert.strictEqual(module, null);
  assert.strictEqual(doc, LAST);
});

function deps(over = {}) {
  let last = LAST;
  const remembered = [];
  return {
    remembered,
    get last() { return last; },
    d: {
      getLastDoc: () => last,
      setLastDoc: (d) => { last = d; },
      runRecheck: async () => PARTIAL,
      policies: [{ remember: (d) => remembered.push(['fix', d]) }, { remember: (d) => remembered.push(['mark', d]) }],
      ...over,
    },
  };
}

test('handleRecheck merges, stores, and re-arms both policies from the merged scan', async () => {
  const t = deps();
  const r = await handleRecheck('a_mod', t.d);
  assert.strictEqual(r.ok, true);
  assert.deepStrictEqual(r.doc.modules.map((m) => m.name), ['a_mod', 'b_mod']);
  assert.strictEqual(t.last, r.doc);
  assert.deepStrictEqual(t.remembered.map(([k]) => k), ['fix', 'mark']);
  assert.strictEqual(t.remembered[0][1], r.doc);
});

test('handleRecheck refuses names that are not plain identifiers or not in the last scan', async () => {
  for (const name of ['../x', 'A_MOD', '', null, 'c_mod']) {
    let ran = false;
    const t = deps({ runRecheck: async () => { ran = true; return PARTIAL; } });
    const r = await handleRecheck(name, t.d);
    assert.strictEqual(r.ok, false, String(name));
    assert.strictEqual(r.error, 'not_allowed');
    assert.strictEqual(ran, false);
  }
});

test('handleRecheck with no scan yet', async () => {
  const t = deps({ getLastDoc: () => null });
  const r = await handleRecheck('a_mod', t.d);
  assert.deepStrictEqual([r.ok, r.error], [false, 'no_scan']);
});

test('engine failure and a missing module are not credited and change nothing', async () => {
  for (const [run, error] of [
    [async () => ({ engine_error: 'timeout', message: 'x' }), 'engine_error'],
    [async () => { throw new Error('boom'); }, 'engine_error'],
    [async () => ({ schema_version: 1, modules: [] }), 'not_rechecked'],
  ]) {
    const t = deps({ runRecheck: run });
    const r = await handleRecheck('a_mod', t.d);
    assert.deepStrictEqual([r.ok, r.error], [false, error]);
    assert.strictEqual(t.last, LAST);
    assert.strictEqual(t.remembered.length, 0);
  }
});
```

Add these tests to the end of `desktop/test/engine-runner.test.js`, and add `scanModuleArgs, runRecheck` to its `require('../engine-runner')`:

```js
test('scanModuleArgs builds a read-only single-module scan', () => {
  assert.deepStrictEqual(scanModuleArgs('launch_agent_audit'), ['scan', '--json', '--module', 'launch_agent_audit']);
  for (const bad of ['../x', 'a b', '', null, 'X']) assert.throws(() => scanModuleArgs(bad));
});

test('runRecheck resolves with the parsed scan, and with engine_error on garbage', async () => {
  const { EventEmitter } = require('events');
  const fakeSpawn = (stdout, code) => () => {
    const p = new EventEmitter();
    p.stdout = new EventEmitter(); p.stderr = new EventEmitter(); p.kill = () => {};
    setImmediate(() => { p.stdout.emit('data', stdout); p.emit('close', code); });
    return p;
  };
  const ok = await runRecheck('a_mod', fakeSpawn('{"schema_version":1,"modules":[]}', 0));
  assert.deepStrictEqual(ok, { schema_version: 1, modules: [] });
  const bad = await runRecheck('a_mod', fakeSpawn('not json', 1));
  assert.strictEqual(bad.engine_error, 'engine_error');
  const refused = await runRecheck('../x', fakeSpawn('', 0));
  assert.strictEqual(refused.engine_error, 'engine_error');
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/recheck.test.js test/engine-runner.test.js`
Expected: FAIL with `Cannot find module '../recheck'` and `scanModuleArgs is not a function`.

- [ ] **Step 3: Add `scanModuleArgs` and `runRecheck` to `desktop/engine-runner.js`**

Add these after `runUndo`:

```js
// Re-check one module after a fix: the same read-only scan, limited to it.
const RECHECK_TIMEOUT_MS = 180000;

function scanModuleArgs(moduleName) {
  if (typeof moduleName !== 'string' || !FIX_MODULE_NAME.test(moduleName)) {
    throw new Error(`invalid module name: ${moduleName}`);
  }
  return ['scan', '--json', '--module', moduleName];
}

// Resolves with the engine's scan document, or {engine_error, message}. Never rejects.
function runRecheck(moduleName, spawnFn = spawn, timeoutMs = RECHECK_TIMEOUT_MS) {
  return runEngineJson(() => scanModuleArgs(moduleName), moduleName, spawnFn, timeoutMs,
    (error, message) => ({ engine_error: error, message }));
}
```

Add `scanModuleArgs, runRecheck` to `module.exports`.

- [ ] **Step 4: Write `desktop/recheck.js`**

```js
// Re-checking one module after a fix.
//
// The engine scans just that module. Its result replaces that module's entry in
// the last full scan, and both gatekeeping policies are re-armed from the merged
// scan. Merging whole scans (rather than patching one module's entries) keeps
// mark-policy's cross-module grouping correct. A re-check that fails, or that
// comes back without the module (it could not run here), changes nothing and
// is never treated as "fixed".
const MODULE_NAME = /^[a-z0-9_]+$/;

function mergeModuleResult(lastDoc, partialDoc, name) {
  const mods = partialDoc && Array.isArray(partialDoc.modules) ? partialDoc.modules : [];
  const fresh = mods.find((m) => m && m.name === name) || null;
  if (!fresh || !lastDoc || !Array.isArray(lastDoc.modules)) return { doc: lastDoc, module: null };
  const has = lastDoc.modules.some((m) => m && m.name === name);
  const modules = has
    ? lastDoc.modules.map((m) => (m && m.name === name ? fresh : m))
    : [...lastDoc.modules, fresh];
  return { doc: { ...lastDoc, modules }, module: fresh };
}

function fail(error, message) {
  return { ok: false, error, message };
}

// Pure handler behind ipcMain.handle('recheck-module'). Never throws.
async function handleRecheck(name, { getLastDoc, setLastDoc, runRecheck, policies }) {
  const last = getLastDoc();
  if (typeof name !== 'string' || !MODULE_NAME.test(name)) return fail('not_allowed', 'That check can’t be re-run from here.');
  if (!last || !Array.isArray(last.modules)) return fail('no_scan', 'Run the checkup first.');
  if (!last.modules.some((m) => m && m.name === name)) return fail('not_allowed', 'That check wasn’t part of this checkup.');
  let partial;
  try {
    partial = await runRecheck(name);
  } catch (err) {
    return fail('engine_error', `We couldn’t re-check this: ${err && err.message ? err.message : err}`);
  }
  if (!partial || partial.engine_error) {
    return fail('engine_error', (partial && partial.message) || 'We couldn’t re-check this.');
  }
  const { doc, module } = mergeModuleResult(last, partial, name);
  if (!module) return fail('not_rechecked', 'That check couldn’t run just now.');
  setLastDoc(doc);
  for (const p of policies) p.remember(doc);
  return { ok: true, doc, module };
}

module.exports = { mergeModuleResult, handleRecheck };
```

- [ ] **Step 5: Wire up `main.js` and `preload.js`**

`main.js`:
- Add `runRecheck` to the `engine-runner` `require`, and add `const { handleRecheck } = require('./recheck');`.
- Inside `app.whenReady`, after `const markPolicy = createMarkPolicy();`, add:

```js
  // The last full scan this process ran, with any re-checks merged in.
  let lastDoc = null;
```

- In the `run-scan` handler, after `markPolicy.remember(doc);`, add `lastDoc = doc;`.
- After the `unmark-mine` handler, add:

```js
  ipcMain.handle('recheck-module', (_e, name) =>
    handleRecheck(name, {
      getLastDoc: () => lastDoc,
      setLastDoc: (d) => { lastDoc = d; },
      runRecheck: (n) => runRecheck(n),
      policies: [fixPolicy, markPolicy],
    }));
```

`preload.js`: add this after `unmarkMine`:

```js
  recheckModule: (name) => ipcRenderer.invoke('recheck-module', name),
```

- [ ] **Step 6: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add desktop/engine-runner.js desktop/recheck.js desktop/main.js desktop/preload.js desktop/test/recheck.test.js desktop/test/engine-runner.test.js
git commit -m "Re-check a single module after a fix, merging it into the last scan"
```

---

### Task 5: Let game mode hear fix, undo and mark results

**Files:**
- Modify: `desktop/renderer/fix-flow.js` (`attach`, `confirm`, `undo`)
- Modify: `desktop/renderer/mark-flow.js` (`attach`, `send`)
- Test: `desktop/test/fix-flow.test.js`, `desktop/test/mark-flow.test.js` (add tests)

**Interfaces:**
- Produces:
  - `FixFlow.attach(root, api, hooks?)`, where `hooks.onResult({kind: 'fix'|'undo', module: string, result, described})` is called after the engine answers.
  - `MarkFlow.attach(root, api, hooks?)`, where `hooks.onResult({kind: 'marked'|'removed', result, described})` is called the same way.
  - A throwing hook never breaks the flow. The behavior without hooks is unchanged.

- [ ] **Step 1: Write the failing tests**

Add to `desktop/test/fix-flow.test.js`, below the existing `attach` tests (they reuse its `fakeRoot()` helper):

```js
test('onResult hears the engine answer after Yes, fix it', async () => {
  const { root, els } = fakeRoot();
  const heard = [];
  const result = { applied: true, verified: true, status: 'fixed', how_to_undo: ['Undo it.'] };
  FixFlow.attach(root, { runFix: async () => result }, { onResult: (e) => heard.push(e) });
  root.click(els.open);
  await root.click(els.confirm);
  assert.strictEqual(heard.length, 1);
  assert.strictEqual(heard[0].kind, 'fix');
  assert.strictEqual(heard[0].module, 'firewall_audit');
  assert.strictEqual(heard[0].result, result);
  assert.strictEqual(heard[0].described.tone, 'success');
});

test('a throwing onResult does not break the flow', async () => {
  const { root, els } = fakeRoot();
  FixFlow.attach(root, { runFix: async () => ({ applied: true, verified: true, status: 'fixed', how_to_undo: ['u'] }) },
    { onResult: () => { throw new Error('hook'); } });
  root.click(els.open);
  await root.click(els.confirm);
  assert.match(els.status.innerHTML, /fixed/);
});

test('onResult is not called when the person cancels', () => {
  const { root, els } = fakeRoot();
  let heard = 0;
  FixFlow.attach(root, { runFix: async () => ({}) }, { onResult: () => { heard++; } });
  root.click(els.open);
  root.click(els.cancel);
  assert.strictEqual(heard, 0);
});
```

Add to `desktop/test/mark-flow.test.js`, below the existing `cardsRoot` helper and its tests (they reuse `cardsRoot`, `ID_A` and `ID_B`):

```js
test('onResult hears the engine answer after a mark', async () => {
  const { root, cards: [a] } = cardsRoot([{ 'data-mark-id': ID_A, 'data-mark-group': ID_A }]);
  const heard = [];
  const result = { status: 'marked', ids: [ID_A], how_to_undo: ['u'] };
  MarkFlow.attach(root, { markMine: async () => result }, { onResult: (e) => heard.push(e) });
  root.click(a.open);
  await root.click(a.confirm);
  assert.strictEqual(heard.length, 1);
  assert.strictEqual(heard[0].kind, 'marked');
  assert.strictEqual(heard[0].result, result);
  assert.strictEqual(heard[0].described.done, true);
});

test('a throwing onResult does not break a mark', async () => {
  const { root, cards: [a] } = cardsRoot([{ 'data-mark-id': ID_A, 'data-mark-group': ID_A }]);
  MarkFlow.attach(root, { markMine: async () => ({ status: 'marked', ids: [ID_A], how_to_undo: ['u'] }) },
    { onResult: () => { throw new Error('hook'); } });
  root.click(a.open);
  await root.click(a.confirm);
  assert.match(a.status.innerHTML, /Marked as yours/);
});
```

- [ ] **Step 2: Run them to make sure they fail**

Run: `cd desktop && node --test test/fix-flow.test.js test/mark-flow.test.js`
Expected: FAIL. `heard.length` is `0`.

- [ ] **Step 3: Implement it in `fix-flow.js`**

Change the signature to `function attach(root, api, hooks) {`, and add this as its first lines:

```js
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
    function notify(kind, card, result, described) {
      if (!onResult) return;
      try { onResult({ kind, module: card.getAttribute('data-fix-module'), result, described }); } catch (_) { /* a listener must never break a fix */ }
    }
```

In `confirm`, right after `const d = describeFixResult(result);`, add `notify('fix', card, result, d);`.

In `undo`, replace the line `if (describeFixResult(result).restored === true) {` with:

```js
        const d = describeFixResult(result);
        notify('undo', card, result, d);
        if (d.restored === true) {
```

- [ ] **Step 4: Implement it in `mark-flow.js`**

Change the signature to `function attach(root, api, hooks) {`, and add this as its first lines:

```js
    const onResult = hooks && typeof hooks.onResult === 'function' ? hooks.onResult : null;
```

In `send`, right after `d = describeMarkResult(result);`, add:

```js
        if (onResult) { try { onResult({ kind, result, described: d }); } catch (_) { /* never break a mark */ } }
```

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/fix-flow.js desktop/renderer/mark-flow.js desktop/test/fix-flow.test.js desktop/test/mark-flow.test.js
git commit -m "Let a caller hear fix, undo and mark results"
```

---

### Task 6: The safety gate: `mayBeWatched` and `gameOfferedFor`

**Files:**
- Modify: `desktop/renderer/app.js` (`learnMoreFor` around lines 234–244, plus `module.exports`)
- Test: `desktop/test/game-gate.test.js`

**Interfaces:**
- Produces, both exported from `app.js` for Node:
  - `mayBeWatched(situation, doc) -> boolean`
  - `gameOfferedFor(situation, doc) -> boolean`
- `learnMoreFor` behaves exactly as before.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-gate.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const { mayBeWatched, gameOfferedFor, learnMoreFor, SITUATIONS } = require('../renderer/app.js');

const byId = (id) => SITUATIONS.find((s) => s.id === id);
const withFinding = (module, severity) => ({ modules: [{ name: module, findings: [{ severity }] }] });

test('closed for the worries where someone may be watching', () => {
  assert.strictEqual(gameOfferedFor(byId('watched'), { modules: [] }), false);
  assert.strictEqual(gameOfferedFor(byId('phone'), { modules: [] }), false);
});

test('closed when monitoring software is found, whatever the worry', () => {
  for (const mod of ['stalkerware_scan', 'mvt_spyware_scan', 'keylogger_indicators']) {
    for (const sev of ['critical', 'warning']) {
      assert.strictEqual(gameOfferedFor(byId('unsure'), withFinding(mod, sev)), false, `${mod} ${sev}`);
    }
  }
});

test('an info finding from a monitoring module does not close it', () => {
  assert.strictEqual(gameOfferedFor(byId('unsure'), withFinding('stalkerware_scan', 'info')), true);
});

test('open for every other worry, including ones with no matching chapter', () => {
  for (const id of ['hacked', 'wifi', 'identity', 'sketchy', 'helping', 'unsure']) {
    assert.strictEqual(gameOfferedFor(byId(id), { modules: [] }), true, id);
    assert.strictEqual(gameOfferedFor(byId(id), null), true, `${id} before any scan`);
  }
});

test('closed with no worry picked', () => {
  assert.strictEqual(gameOfferedFor(null, { modules: [] }), false);
});

test('learnMoreFor still hides the game link exactly when mayBeWatched says so', () => {
  for (const s of SITUATIONS) {
    if (mayBeWatched(s, { modules: [] })) assert.strictEqual(learnMoreFor(s, { modules: [] }), null, s.id);
  }
  assert.strictEqual(learnMoreFor(byId('hacked'), withFinding('stalkerware_scan', 'warning')), null);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-gate.test.js`
Expected: FAIL with `gameOfferedFor is not a function`.

- [ ] **Step 3: Implement it in `app.js`**

Replace the body of `learnMoreFor` and add the two helpers above it:

```js
/**
 * Whether the person may be watched by someone close to them: they said so
 * ("watching me"), they're worried about iPhone spyware, or the scan found
 * monitoring software. Then nothing playful is offered: not the Reclaim City
 * link, not game mode. Turning things off can alert whoever is watching.
 */
function mayBeWatched(situation, doc) {
  if (situation && (situation.safety || situation.id === 'phone')) return true;
  const modules = (doc && doc.modules) || [];
  return modules.some((mod) => mod && ALWAYS_SAFETY_MODULES.has(mod.name)
    && (mod.findings || []).some((f) => f && (f.severity === 'critical' || f.severity === 'warning')));
}

/** Whether to offer game mode ("Play it as a game" and the city view). */
function gameOfferedFor(situation, doc) {
  return !!situation && !mayBeWatched(situation, doc);
}

function learnMoreFor(situation, doc) {
  if (!situation || mayBeWatched(situation, doc)) return null;
  const entry = LEARN_MORE[situation.id];
  if (!entry) return null;
  return { text: `${GAME_INTRO} ${entry.text}`, url: RECLAIM_CITY_URL + entry.path };
}
```

Add `mayBeWatched, gameOfferedFor,` to `module.exports`.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && npm test`
Expected: PASS. That includes the existing `learn-more.test.js` and `safety-note.test.js`.

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/app.js desktop/test/game-gate.test.js
git commit -m "Pull out the may-be-watched check and use it to gate game mode"
```

---

### Task 7: Turn a scan into a city (`findings-to-city.js`)

**Files:**
- Create: `desktop/renderer/game/package.json`, `desktop/renderer/game/findings-to-city.js`
- Test: `desktop/test/game-findings-to-city.test.js`

**Interfaces:**
- Consumes: scan JSON from Task 1 (`modules[].category`, `findings[].{title, description, severity, code, data, markable, remediation, fixable}`).
- Produces:
  - `DISTRICTS: Array<{id, category, name, blurb}>`
  - `findingIdentity(finding) -> string`
  - `missionSteps(finding) -> Array<{number, title, body}>`
  - `findingsToCity(doc) -> City`, where:
    - `City = { districts: District[], totals: {critical, warning, info, fog} }`
    - `District = { id, name, blurb, category, missions: Mission[], notes: Finding[], fog: Array<{module, reason}>, checksRan: number, status: 'hot'|'warn'|'fog'|'partial'|'clear'|'none' }`
    - `Mission = { id, module, code, severity: 'critical'|'warning', title, description, steps, walkthroughTitle, safetyNote, findings: Finding[], primary: Finding, fixable: boolean, markable: boolean, marked: boolean, districtId }`
    - Every `Finding` here carries `module`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-findings-to-city.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/findings-to-city.js');

const mod = (name, category, findings, extra = {}) => ({ name, category, status: 'ok', error: null, supported: true, unsupported_reason: null, findings, ...extra });
const f = (severity, extra = {}) => ({ title: `${severity} thing`, description: 'Something.', severity, code: 'security.m.x', data: {}, ...extra });

test('findings land in districts by category; info goes to notes', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [
    mod('launch_agent_audit', 'security', [f('critical', { data: { plist: '/a.plist' } }), f('info')]),
    mod('disk_space', 'performance', [f('warning', { code: 'performance.disk_space.low' })]),
  ] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.missions.length, 1);
  assert.strictEqual(gate.missions[0].severity, 'critical');
  assert.strictEqual(gate.notes.length, 1);
  assert.strictEqual(gate.status, 'hot');
  assert.strictEqual(city.districts.find((d) => d.id === 'engine-room').status, 'warn');
  assert.deepStrictEqual(city.totals, { critical: 1, warning: 1, info: 1, fog: 0 });
});

test('a category we do not know goes to The Outskirts instead of disappearing', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('odd', 'test', [f('warning')]), mod('nocat', undefined, [f('critical')])] });
  const out = city.districts.find((d) => d.id === 'outskirts');
  assert.ok(out, 'outskirts present when used');
  assert.strictEqual(out.missions.length, 2);
});

test('The Outskirts is left out when nothing goes there', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [])] });
  assert.ok(!city.districts.some((d) => d.id === 'outskirts'));
  assert.strictEqual(city.districts.length, 5);
});

test('unknown severity is treated as info, like the list view', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [f('weird')])] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.missions.length, 0);
  assert.strictEqual(gate.notes.length, 1);
});

test('fog for unsupported and errored checks; a district of only failed checks is fog, never clear', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [
    mod('wifi_security_audit', 'network', [], { supported: false, unsupported_reason: 'Needs Location Services.' }),
    mod('router_security_audit', 'network', [], { status: 'error', error: 'timed out' }),
    mod('update_checker', 'integrity', []),
    mod('dns_config', 'integrity', [], { status: 'error', error: 'boom' }),
  ] });
  const wires = city.districts.find((d) => d.id === 'wires');
  assert.strictEqual(wires.status, 'fog');
  assert.deepStrictEqual(wires.fog.map((x) => x.reason), ['Needs Location Services.', 'timed out']);
  assert.strictEqual(city.districts.find((d) => d.id === 'foundations').status, 'partial');
  assert.strictEqual(city.totals.fog, 3);
});

test('a district where no checks ran at all says none, not clear', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [])] });
  assert.strictEqual(city.districts.find((d) => d.id === 'junkyard').status, 'none');
  assert.strictEqual(city.districts.find((d) => d.id === 'gatehouse').status, 'clear');
});

test('steps come from the walkthrough, and fall back to What to do, then to the description', async () => {
  const { missionSteps } = await load();
  const steps = [{ number: 1, title: 'Remove high-risk background tasks', body: 'Body.' }];
  assert.deepStrictEqual(missionSteps(f('critical', { remediation: { title: 'T', steps } })), steps);
  assert.deepStrictEqual(
    missionSteps(f('warning', { description: 'Your disk is full.\n\nWhat to do:\n1. Empty the Trash.\n2. Delete old downloads.' })).map((s) => s.title),
    ['Empty the Trash.', 'Delete old downloads.'],
  );
  assert.deepStrictEqual(missionSteps(f('warning', { description: 'Just this.' })).map((s) => s.title), ['Just this.']);
});

test('identity is stable across scans and uses the mark id when there is one', async () => {
  const { findingIdentity } = await load();
  const a = { ...f('critical', { data: { plist: '/x.plist', pid: 1 } }), module: 'm' };
  const b = { ...f('critical', { data: { plist: '/x.plist', pid: 2 } }), module: 'm' };
  assert.strictEqual(findingIdentity(a), findingIdentity(b));
  assert.strictEqual(findingIdentity({ ...a, markable: { id: 'abc123' } }), 'mark:abc123');
  assert.strictEqual(findingIdentity({ ...a, data: { known_item_id: 'abc123', marked_by_user: true } }), 'mark:abc123');
});

test('two findings with one identity become one mission that lists both, at the higher severity', async () => {
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('a', 'security', [f('warning', { title: 'one' }), f('critical', { title: 'two' })])] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.missions.length, 1);
  assert.strictEqual(gate.missions[0].severity, 'critical');
  assert.strictEqual(gate.missions[0].findings.length, 2);
});

test('mission flags: fixable, markable, marked', async () => {
  const { findingsToCity } = await load();
  const fixable = { will_change: 'x', how_to_undo: ['y'] };
  const city = findingsToCity({ modules: [mod('a', 'security', [
    f('warning', { fixable, markable: { id: 'm1' }, data: { plist: '/1' } }),
    f('warning', { data: { known_item_id: 'm2', marked_by_user: true } }),
  ])] });
  const [m1, m2] = city.districts.find((d) => d.id === 'gatehouse').missions;
  assert.deepStrictEqual([m1.fixable, m1.markable, m1.marked], [true, true, false]);
  assert.strictEqual(m2.marked, true);
});

test('a finding the person marked stays a mission even though the engine lowered it to info', async () => {
  // rescue/known_items.py sets severity INFO on a marked finding and keeps the
  // old one in data.original_severity. If it became a note, the mission would
  // vanish and the next scan would count it as reclaimed: never allowed.
  const { findingsToCity } = await load();
  const city = findingsToCity({ modules: [mod('launch_agent_audit', 'security', [
    f('info', { title: 'Marked as yours: ai.example', data: { known_item_id: 'abc', marked_by_user: true, original_severity: 'warning' } }),
  ])] });
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  assert.strictEqual(gate.notes.length, 0);
  assert.strictEqual(gate.missions.length, 1);
  assert.deepStrictEqual([gate.missions[0].id, gate.missions[0].severity, gate.missions[0].marked], ['mark:abc', 'warning', true]);
});

test('garbage in does not throw', async () => {
  const { findingsToCity } = await load();
  for (const doc of [null, {}, { modules: null }, { modules: [null, { name: 'x' }, { name: 'y', findings: [null] }] }]) {
    const city = findingsToCity(doc);
    assert.ok(Array.isArray(city.districts));
  }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-findings-to-city.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Create `desktop/renderer/game/package.json`**

```json
{ "type": "module", "private": true }
```

- [ ] **Step 4: Write `desktop/renderer/game/findings-to-city.js`**

Checked during planning: `markable().id` (`rescue/known_items.py` ~729) and the later `data.known_item_id` (~691) are both `item_id(BACKGROUND_TASK, identity)`. So a mission keeps its `mark:<id>` identity after it's marked. Marking also sets the finding's severity to INFO and changes its title (~697–699), which is why `findingsToCity` reads `data.marked_by_user` before the severity.

```js
// Turns a Device Rescue scan (rescue scan --json) into a city: one district per
// kind of problem, one mission per warning or critical finding, notes for info
// findings, and fog where a check couldn't run. Pure; no DOM.

export const DISTRICTS = [
  { id: 'gatehouse', category: 'security', name: 'The Gatehouse', blurb: 'Security: things that start on their own, permissions, protection.' },
  { id: 'wires', category: 'network', name: 'The Wires', blurb: 'Network: your Wi-Fi, router and connections.' },
  { id: 'foundations', category: 'integrity', name: 'The Foundations', blurb: 'Integrity: updates, disk health, system files.' },
  { id: 'engine-room', category: 'performance', name: 'The Engine Room', blurb: 'Performance: speed, memory and storage.' },
  { id: 'junkyard', category: 'bloatware', name: 'The Junkyard', blurb: 'Clutter: preinstalled extras and leftovers.' },
];
const OUTSKIRTS = { id: 'outskirts', category: null, name: 'The Outskirts', blurb: 'Everything else the checkup noticed.' };
const SEVERITY_RANK = { critical: 2, warning: 1 };
// Data fields that name the thing a finding is about, most specific first.
const STABLE_KEYS = ['plist', 'path', 'program', 'label', 'bundle_id', 'extension_id', 'name', 'target', 'id'];

function districtFor(category) {
  return DISTRICTS.find((d) => d.category === category) || OUTSKIRTS;
}

export function findingIdentity(finding) {
  const fd = finding || {};
  if (fd.markable && typeof fd.markable.id === 'string') return `mark:${fd.markable.id}`;
  const data = fd.data && typeof fd.data === 'object' ? fd.data : {};
  if (typeof data.known_item_id === 'string') return `mark:${data.known_item_id}`;
  const what = fd.code || fd.title || '';
  for (const key of STABLE_KEYS) {
    if (typeof data[key] === 'string' && data[key] !== '') return `${fd.module}|${what}|${key}=${data[key]}`;
  }
  return `${fd.module}|${what}`;
}

export function missionSteps(finding) {
  const rem = finding && finding.remediation;
  if (rem && Array.isArray(rem.steps) && rem.steps.length) return rem.steps;
  const text = String((finding && finding.description) || '');
  const m = text.split(/what to do:?/i);
  if (m.length > 1) {
    const lines = m.slice(1).join(' ').split('\n').map((l) => l.trim())
      .filter(Boolean).map((l) => l.replace(/^(\d+[.)]|[-*•])\s*/, ''));
    if (lines.length) return lines.map((title, i) => ({ number: i + 1, title, body: '' }));
  }
  return [{ number: 1, title: text.trim() || 'Follow the steps in the list view.', body: '' }];
}

function emptyDistrict(d) {
  return { id: d.id, name: d.name, blurb: d.blurb, category: d.category, missions: [], notes: [], fog: [], checksRan: 0, status: 'none' };
}

function statusOf(d) {
  if (d.missions.length) return d.missions.some((m) => m.severity === 'critical') ? 'hot' : 'warn';
  if (d.fog.length && d.checksRan === 0) return 'fog';
  if (d.fog.length) return 'partial';
  return d.checksRan > 0 || d.notes.length ? 'clear' : 'none';
}

export function findingsToCity(doc) {
  const byId = new Map([...DISTRICTS, OUTSKIRTS].map((d) => [d.id, emptyDistrict(d)]));
  const missions = new Map();
  const totals = { critical: 0, warning: 0, info: 0, fog: 0 };
  const modules = doc && Array.isArray(doc.modules) ? doc.modules : [];

  for (const mod of modules) {
    if (!mod || typeof mod.name !== 'string') continue;
    const district = byId.get(districtFor(mod.category).id);
    if (mod.status === 'error' || mod.supported === false) {
      district.fog.push({ module: mod.name, reason: mod.unsupported_reason || mod.error || 'This check couldn’t run.' });
      totals.fog += 1;
    } else {
      district.checksRan += 1;
    }
    for (const raw of Array.isArray(mod.findings) ? mod.findings : []) {
      if (!raw || typeof raw !== 'object') continue;
      const finding = { ...raw, module: mod.name };
      // A finding the person marked as theirs comes back as info (known_items.py),
      // with its old severity kept. It stays a mission, shown as "yours".
      const markedByUser = !!(finding.data && finding.data.marked_by_user === true);
      const original = markedByUser && finding.data.original_severity;
      const sev = markedByUser
        ? (SEVERITY_RANK[original] ? original : 'warning')
        : (SEVERITY_RANK[finding.severity] ? finding.severity : 'info');
      totals[sev] += 1;
      if (sev === 'info') { district.notes.push(finding); continue; }
      const id = findingIdentity(finding);
      const existing = missions.get(id);
      if (existing) {
        existing.findings.push(finding);
        if (SEVERITY_RANK[sev] > SEVERITY_RANK[existing.severity]) { existing.severity = sev; existing.primary = finding; }
        existing.fixable = existing.fixable || !!finding.fixable;
        existing.markable = existing.markable || !!finding.markable;
        existing.marked = existing.marked && !!(finding.data && finding.data.marked_by_user === true);
        continue;
      }
      const mission = {
        id, module: mod.name, code: finding.code || null, severity: sev, districtId: district.id,
        title: finding.title || 'Something worth a look',
        description: finding.description || '',
        steps: missionSteps(finding),
        walkthroughTitle: (finding.remediation && finding.remediation.title) || null,
        safetyNote: (finding.remediation && finding.remediation.safety_note) || null,
        findings: [finding], primary: finding,
        fixable: !!finding.fixable, markable: !!finding.markable,
        marked: !!(finding.data && finding.data.marked_by_user === true),
      };
      missions.set(id, mission);
      district.missions.push(mission);
    }
  }

  for (const m of missions.values()) {
    m.title = m.primary.title || m.title;
    m.description = m.primary.description || m.description;
    m.steps = missionSteps(m.primary);
  }
  const districts = [...byId.values()]
    .filter((d) => d.id !== 'outskirts' || d.missions.length || d.notes.length || d.fog.length)
    .map((d) => {
      d.missions.sort((a, b) => SEVERITY_RANK[b.severity] - SEVERITY_RANK[a.severity]);
      return { ...d, status: statusOf(d) };
    });
  return { districts, totals };
}
```

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-findings-to-city.test.js`
Expected: PASS (12 tests).

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/package.json desktop/renderer/game/findings-to-city.js desktop/test/game-findings-to-city.test.js
git commit -m "Turn a scan into a city of districts, missions, notes and fog"
```

---

### Task 8: Progress, reconciliation and re-check outcomes (`progress.js`)

**Files:**
- Create: `desktop/renderer/game/progress.js`
- Test: `desktop/test/game-progress.test.js`

**Interfaces:**
- Consumes: the `City` and `Mission` shapes from Task 7.
- Produces:
  - `STORE_KEY = 'device-rescue.game.v1'`
  - `emptyProgress() -> {version: 1, missions: {}}`
  - `loadProgress(storage) -> Progress`. It never throws.
  - `saveProgress(storage, progress) -> boolean`. It never throws.
  - `ranOkModules(doc) -> Set<string>`
  - `reconcile(progress, city, ranOk: Set<string>, now: string) -> {progress, cameBack: string[]}`
  - `setStatus(progress, id, status, module, now) -> Progress`, where status is `'open'|'later'`
  - `recheckOutcome(missionId, cityAfter, recheckResponse) -> 'reclaimed'|'not-yet'|'yours'|'couldnt'`
  - `countReclaimed(progress) -> number`
  - `Progress = {version: 1, missions: {[id]: {status: 'open'|'later'|'yours'|'reclaimed', module, updatedAt}}}`

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-progress.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');
const load = () => import('../renderer/game/progress.js');

const NOW = '2026-10-16T12:00:00Z';
const mission = (id, module = 'm', extra = {}) => ({ id, module, marked: false, ...extra });
const cityWith = (...ms) => ({ districts: [{ id: 'gatehouse', missions: ms, notes: [], fog: [] }] });
const memStore = (init = {}) => { const s = { ...init }; return { getItem: (k) => (k in s ? s[k] : null), setItem: (k, v) => { s[k] = String(v); }, raw: s }; };

test('a new finding opens a mission', async () => {
  const { reconcile, emptyProgress } = await load();
  const { progress } = reconcile(emptyProgress(), cityWith(mission('a')), new Set(['m']), NOW);
  assert.strictEqual(progress.missions.a.status, 'open');
  assert.strictEqual(progress.missions.a.module, 'm');
});

test('gone after a scan where its module ran: reclaimed', async () => {
  const { reconcile, emptyProgress } = await load();
  let { progress } = reconcile(emptyProgress(), cityWith(mission('a')), new Set(['m']), NOW);
  ({ progress } = reconcile(progress, cityWith(), new Set(['m']), NOW));
  assert.strictEqual(progress.missions.a.status, 'reclaimed');
});

test('gone because its module could not run: status kept, never credited', async () => {
  const { reconcile, emptyProgress } = await load();
  let { progress } = reconcile(emptyProgress(), cityWith(mission('a')), new Set(['m']), NOW);
  ({ progress } = reconcile(progress, cityWith(), new Set([]), NOW));
  assert.strictEqual(progress.missions.a.status, 'open');
});

test('reclaimed and back again: open, and reported as came back', async () => {
  const { reconcile } = await load();
  const start = { version: 1, missions: { a: { status: 'reclaimed', module: 'm', updatedAt: NOW } } };
  const { progress, cameBack } = reconcile(start, cityWith(mission('a')), new Set(['m']), NOW);
  assert.strictEqual(progress.missions.a.status, 'open');
  assert.deepStrictEqual(cameBack, ['a']);
});

test('marked by the person: yours, and never counted as fixed', async () => {
  const { reconcile, emptyProgress, countReclaimed } = await load();
  const { progress } = reconcile(emptyProgress(), cityWith(mission('a', 'm', { marked: true })), new Set(['m']), NOW);
  assert.strictEqual(progress.missions.a.status, 'yours');
  assert.strictEqual(countReclaimed(progress), 0);
});

test('later survives a rescan while the finding is still there', async () => {
  const { reconcile, setStatus, emptyProgress } = await load();
  let p = setStatus(emptyProgress(), 'a', 'later', 'm', NOW);
  ({ progress: p } = reconcile(p, cityWith(mission('a')), new Set(['m']), NOW));
  assert.strictEqual(p.missions.a.status, 'later');
});

test('recheckOutcome', async () => {
  const { recheckOutcome } = await load();
  const okModule = { ok: true, module: { name: 'm', status: 'ok', supported: true } };
  assert.strictEqual(recheckOutcome('a', cityWith(), okModule), 'reclaimed');
  assert.strictEqual(recheckOutcome('a', cityWith(mission('a')), okModule), 'not-yet');
  assert.strictEqual(recheckOutcome('a', cityWith(mission('a', 'm', { marked: true })), okModule), 'yours');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: false, error: 'engine_error' }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: false, error: 'not_rechecked' }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: true, module: { name: 'm', status: 'error' } }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), { ok: true, module: { name: 'm', status: 'ok', supported: false } }), 'couldnt');
  assert.strictEqual(recheckOutcome('a', cityWith(), null), 'couldnt');
});

test('storage: round trip, corrupt JSON, wrong version, and storage that throws', async () => {
  const { loadProgress, saveProgress, STORE_KEY, emptyProgress } = await load();
  const s = memStore();
  const p = { version: 1, missions: { a: { status: 'later', module: 'm', updatedAt: NOW } } };
  assert.strictEqual(saveProgress(s, p), true);
  assert.deepStrictEqual(loadProgress(s), p);
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: '{not json' })), emptyProgress());
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: '{"version":9,"missions":{}}' })), emptyProgress());
  assert.deepStrictEqual(loadProgress(memStore({ [STORE_KEY]: '{"version":1,"missions":{"a":{"status":"bogus"}}}' })), emptyProgress());
  const throwing = { getItem() { throw new Error('denied'); }, setItem() { throw new Error('denied'); } };
  assert.deepStrictEqual(loadProgress(throwing), emptyProgress());
  assert.strictEqual(saveProgress(throwing, p), false);
  assert.deepStrictEqual(loadProgress(null), emptyProgress());
});

test('ranOkModules lists only modules that ran cleanly', async () => {
  const { ranOkModules } = await load();
  const s = ranOkModules({ modules: [
    { name: 'a', status: 'ok', supported: true }, { name: 'b', status: 'error' },
    { name: 'c', status: 'ok', supported: false }, null,
  ] });
  assert.deepStrictEqual([...s], ['a']);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-progress.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Write `desktop/renderer/game/progress.js`**

```js
// Mission progress for game mode. The scan is the source of truth: progress only
// remembers what the person chose ("later") and what changed between scans.
// "reclaimed" is only ever set by evidence: a re-check or a full scan where the
// finding's module ran and no longer reports it.
export const STORE_KEY = 'device-rescue.game.v1';
const STATUSES = new Set(['open', 'later', 'yours', 'reclaimed']);

export function emptyProgress() {
  return { version: 1, missions: {} };
}

function valid(p) {
  return p && p.version === 1 && p.missions && typeof p.missions === 'object' && !Array.isArray(p.missions)
    && Object.values(p.missions).every((r) => r && STATUSES.has(r.status));
}

export function loadProgress(storage) {
  try {
    const raw = storage ? storage.getItem(STORE_KEY) : null;
    if (!raw) return emptyProgress();
    const p = JSON.parse(raw);
    return valid(p) ? p : emptyProgress();
  } catch (_) {
    return emptyProgress();
  }
}

export function saveProgress(storage, progress) {
  try {
    storage.setItem(STORE_KEY, JSON.stringify(progress));
    return true;
  } catch (_) {
    return false;
  }
}

export function ranOkModules(doc) {
  const out = new Set();
  for (const m of (doc && Array.isArray(doc.modules) ? doc.modules : [])) {
    if (m && typeof m.name === 'string' && m.status !== 'error' && m.supported !== false) out.add(m.name);
  }
  return out;
}

function allMissions(city) {
  return (city && Array.isArray(city.districts) ? city.districts : []).flatMap((d) => d.missions || []);
}

export function reconcile(progress, city, ranOk, now) {
  const next = { version: 1, missions: { ...(progress && progress.missions) } };
  const cameBack = [];
  const present = new Set();
  for (const m of allMissions(city)) {
    present.add(m.id);
    const prev = next.missions[m.id];
    let status;
    if (m.marked) status = 'yours';
    else if (!prev || prev.status === 'yours') status = 'open';
    else if (prev.status === 'reclaimed') { status = 'open'; cameBack.push(m.id); }
    else status = prev.status;
    if (!prev || prev.status !== status) next.missions[m.id] = { status, module: m.module, updatedAt: now };
  }
  for (const [id, rec] of Object.entries(next.missions)) {
    if (present.has(id) || rec.status === 'reclaimed') continue;
    if (ranOk.has(rec.module)) next.missions[id] = { ...rec, status: 'reclaimed', updatedAt: now };
  }
  return { progress: next, cameBack };
}

export function setStatus(progress, id, status, module, now) {
  return { version: 1, missions: { ...progress.missions, [id]: { status, module, updatedAt: now } } };
}

export function recheckOutcome(missionId, cityAfter, response) {
  if (!response || response.ok !== true || !response.module) return 'couldnt';
  if (response.module.status === 'error' || response.module.supported === false) return 'couldnt';
  const m = allMissions(cityAfter).find((x) => x.id === missionId);
  if (!m) return 'reclaimed';
  return m.marked ? 'yours' : 'not-yet';
}

export function countReclaimed(progress) {
  return Object.values((progress && progress.missions) || {}).filter((r) => r.status === 'reclaimed').length;
}
```

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-progress.test.js`
Expected: PASS (9 tests).

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/progress.js desktop/test/game-progress.test.js
git commit -m "Track mission progress that only the scan can mark as reclaimed"
```

---

### Task 9: Scout's lines and the pure views

**Files:**
- Create: `desktop/renderer/game/escape.js`, `game/scout-lines.js`, `game/views/hud.js`, `game/views/map.js`, `game/views/district.js`, `game/views/briefing.js`, `game/views/outcome.js`, `game/views/milestone.js`
- Test: `desktop/test/game-views.test.js`

**Interfaces:**
- Consumes: `City`, `District` and `Mission` (Task 7); `Progress` and outcomes (Task 8). A `scout(feeling, size)` function is injected. The controller passes `(f, size) => scoutSprite(f, { size })` from the vendored `scout.js`.
- Produces:
  - `esc(value) -> string`
  - `SCOUT`, `mapScoutLine(city) -> string`, `debriefReply(answer) -> string`
  - `renderHud({title, city, progress}) -> string`
  - `renderMap({city, progress, cameBack, scout}) -> string`
  - `renderDistrict({district, progress, scout}) -> string`
  - `renderBriefing({mission, status, controlsHtml, scout, busy, wantsSafety}) -> string`
  - `renderOutcome({kind: 'reclaimed'|'not-yet'|'yours'|'couldnt', mission, scout, message, undoHtml}) -> string`. `undoHtml` is markup the controller builds from `FixFlow.resultHtml` so the fix can be undone from the city.
  - `districtComplete(district, progress) -> boolean`: true when every mission is `reclaimed` or `yours`, and there's at least one mission.
  - `renderMilestone({district, progress, scout}) -> string`. Share cards stay off, because they would describe the person's computer.
  - Every view takes plain data and returns an HTML string. Clickable things use `data-go="map"`, `data-go="district:<id>"`, `data-go="mission:<id>"`, `data-act="i-did-it"|"later"|"recheck"|"debrief:<answer>"|"list"`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-views.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');

const EVIL = '<img src=x onerror=alert(1)>';
const scout = (feeling) => `<i data-scout="${feeling}"></i>`;
const views = async () => ({
  ...(await import('../renderer/game/views/map.js')),
  ...(await import('../renderer/game/views/district.js')),
  ...(await import('../renderer/game/views/briefing.js')),
  ...(await import('../renderer/game/views/outcome.js')),
  ...(await import('../renderer/game/views/hud.js')),
  ...(await import('../renderer/game/scout-lines.js')),
  ...(await import('../renderer/game/findings-to-city.js')),
  ...(await import('../renderer/game/progress.js')),
});

function evilCity(findingsToCity) {
  return findingsToCity({ modules: [
    { name: 'launch_agent_audit', category: 'security', status: 'ok', supported: true, findings: [
      { title: EVIL, description: EVIL, severity: 'critical', code: 'security.launch_agent_audit.suspicious_path',
        data: { plist: EVIL }, remediation: { title: EVIL, steps: [{ number: 1, title: EVIL, body: EVIL }] } },
      { title: EVIL, description: EVIL, severity: 'info', data: {} },
    ] },
    { name: 'wifi_security_audit', category: 'network', status: 'ok', supported: false, unsupported_reason: EVIL, findings: [] },
  ] });
}

test('no view lets engine text through as HTML', async () => {
  const v = await views();
  const city = evilCity(v.findingsToCity);
  const gate = city.districts.find((d) => d.id === 'gatehouse');
  const mission = gate.missions[0];
  const html = [
    v.renderHud({ title: 'YOUR COMPUTER', city, progress: v.emptyProgress() }),
    v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout }),
    v.renderDistrict({ district: gate, progress: v.emptyProgress(), scout }),
    v.renderDistrict({ district: city.districts.find((d) => d.id === 'wires'), progress: v.emptyProgress(), scout }),
    v.renderBriefing({ mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false }),
    v.renderOutcome({ kind: 'not-yet', mission, scout, message: EVIL }),
    v.renderOutcome({ kind: 'couldnt', mission, scout, message: EVIL }),
  ].join('\n');
  assert.ok(!html.includes('<img src=x'), 'raw engine HTML leaked');
  assert.match(html, /&lt;img src=x onerror=alert\(1\)&gt;/);
});

test('fog says it is not safe; none says no checks ran; neither says clear', async () => {
  const v = await views();
  const city = v.findingsToCity({ modules: [
    { name: 'wifi_security_audit', category: 'network', status: 'ok', supported: false, unsupported_reason: 'Needs permission.', findings: [] },
  ] });
  const map = v.renderMap({ city, progress: v.emptyProgress(), cameBack: [], scout });
  assert.match(map, /Couldn’t check here\. That doesn’t mean it’s safe\./);
  assert.match(map, /No checks ran here/);
});

test('the briefing shows the controls it is given, the steps, and the three ways out', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts.find((d) => d.id === 'gatehouse').missions[0];
  const html = v.renderBriefing({ mission, status: 'open', controlsHtml: '<div data-fix-module="m">FIX</div>', scout, busy: false, wantsSafety: false });
  assert.match(html, /data-fix-module="m">FIX/);
  assert.match(html, /data-act="i-did-it"/);
  assert.match(html, /data-act="later"/);
  assert.match(html, /data-go="district:gatehouse"/);
});

test('while a re-check runs the briefing says so and offers nothing to click twice', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts.find((d) => d.id === 'gatehouse').missions[0];
  const html = v.renderBriefing({ mission, status: 'open', controlsHtml: 'X', scout, busy: true, wantsSafety: false });
  assert.match(html, /Checking again/);
  assert.doesNotMatch(html, /data-act="i-did-it"/);
});

test('the safety note shows when asked for and the mission has one', async () => {
  const v = await views();
  const mission = { ...evilCity(v.findingsToCity).districts[0].missions[0], safetyNote: 'Talk to an advocate first.' };
  assert.match(v.renderBriefing({ mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: true }), /Talk to an advocate first\./);
  assert.doesNotMatch(v.renderBriefing({ mission, status: 'open', controlsHtml: '', scout, busy: false, wantsSafety: false }), /Talk to an advocate/);
});

test('outcomes: reclaimed has the debrief, not-yet goes back to steps, couldnt offers a retry', async () => {
  const v = await views();
  const mission = evilCity(v.findingsToCity).districts[0].missions[0];
  assert.match(v.renderOutcome({ kind: 'reclaimed', mission, scout }), /data-act="debrief:easy"/);
  assert.match(v.renderOutcome({ kind: 'reclaimed', mission, scout, undoHtml: '<div data-fix-undo-here></div>' }), /data-fix-undo-here/);
  assert.match(v.renderOutcome({ kind: 'yours', mission, scout }), /BACK TO THE DISTRICT/);
  assert.match(v.renderOutcome({ kind: 'not-yet', mission, scout }), /data-go="mission:/);
  assert.match(v.renderOutcome({ kind: 'couldnt', mission, scout }), /data-act="recheck"/);
  assert.match(v.renderOutcome({ kind: 'couldnt', mission, scout }), /doesn’t mean it’s fixed/);
});

test('a district milestone needs every mission reclaimed or yours, and lists the yours ones apart', async () => {
  const { districtComplete, renderMilestone } = await import('../renderer/game/views/milestone.js');
  const district = { id: 'gatehouse', name: 'The Gatehouse', missions: [{ id: 'a', title: 'A' }, { id: 'b', title: EVIL }], notes: [], fog: [] };
  const p = (a, b) => ({ version: 1, missions: { a: { status: a, module: 'm' }, b: { status: b, module: 'm' } } });
  assert.strictEqual(districtComplete(district, p('reclaimed', 'open')), false);
  assert.strictEqual(districtComplete(district, p('reclaimed', 'later')), false);
  assert.strictEqual(districtComplete(district, p('reclaimed', 'yours')), true);
  assert.strictEqual(districtComplete({ ...district, missions: [] }, p('open', 'open')), false);
  const html = renderMilestone({ district, progress: p('reclaimed', 'yours'), scout });
  assert.match(html, /THE GATEHOUSE/);
  assert.match(html, /marked as yours/i);
  assert.ok(!html.includes('<img src=x'));
  assert.doesNotMatch(html, /share/i);
});

test('the HUD counts reclaimed from progress and never counts yours', async () => {
  const v = await views();
  const city = evilCity(v.findingsToCity);
  const progress = { version: 1, missions: { x: { status: 'reclaimed', module: 'm' }, y: { status: 'yours', module: 'm' } } };
  const hud = v.renderHud({ title: 'T', city, progress });
  assert.match(hud, />1<\/b> <small>RECLAIMED/);
  assert.match(hud, /data-act="list"/);
});

test('no Scout line promises safety', async () => {
  const { SCOUT } = await views();
  const all = JSON.stringify(SCOUT).toLowerCase();
  for (const banned of ['you’re safe', "you're safe", 'all clear', 'not hacked', 'nothing to worry']) {
    assert.ok(!all.includes(banned), banned);
  }
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-views.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Write `game/escape.js` and `game/scout-lines.js`**

`desktop/renderer/game/escape.js`:

```js
export function esc(value) {
  return String(value == null ? '' : value)
    .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;').replace(/'/g, '&#39;');
}
```

`desktop/renderer/game/scout-lines.js`:

```js
// Scout's fixed lines. Short, plain, never a promise that everything is fine.
// They are placeholders listed for review in the spec (section 9).
export const SCOUT = {
  mapHot: 'Start with {district}. Something there is worth a look first. Finding something doesn’t mean you’ve been hacked.',
  mapWarn: 'Nothing urgent. {district} has the most worth a look.',
  mapQuiet: 'Nothing stood out in the checks that ran. Fog means a place I couldn’t see into.',
  cameBack: 'Something you fixed came back since last time. It’s dark again on the map.',
  briefing: {
    critical: 'This one is worth doing first. Read what it is, then pick how you want to handle it.',
    warning: 'This isn’t urgent, but it’s worth a look when you’re ready.',
  },
  checking: 'Checking again. This only looks; it doesn’t change anything.',
  reclaimed: 'Device Rescue checked again, and it’s gone.',
  notYet: 'It’s still showing. Some programs put themselves back. Let’s look at the steps again.',
  couldnt: 'I couldn’t check again just now. That doesn’t mean it’s fixed.',
  yours: 'Marked as yours. It stays listed, and you can change your mind any time.',
  debrief: {
    easy: 'Good. Every one you do makes the next one easier.',
    nervous: 'That’s normal. You did it anyway, and Device Rescue kept a way back.',
    worried: 'That’s fair. The rest of the city is still here, and the list view has every detail.',
  },
};

export function mapScoutLine(city) {
  const ds = (city && city.districts) || [];
  const hot = ds.find((d) => d.status === 'hot');
  if (hot) return SCOUT.mapHot.replace('{district}', hot.name);
  const warm = ds.filter((d) => d.status === 'warn').sort((a, b) => b.missions.length - a.missions.length)[0];
  if (warm) return SCOUT.mapWarn.replace('{district}', warm.name);
  return SCOUT.mapQuiet;
}

export function debriefReply(answer) {
  return SCOUT.debrief[answer] || SCOUT.debrief.easy;
}
```

- [ ] **Step 4: Write the views**

`desktop/renderer/game/views/hud.js`:

```js
import { esc } from '../escape.js';
import { countReclaimed } from '../progress.js';

export function renderHud({ title, city, progress }) {
  const t = (city && city.totals) || { critical: 0, warning: 0, fog: 0 };
  const open = (city.districts || []).reduce((n, d) => n + d.missions.length, 0);
  const done = countReclaimed(progress);
  return `
  <header class="hud">
    <span class="hud-title">${esc(title)}</span>
    <span class="stat mag"><b>${t.critical}</b> <small>CRITICAL</small></span>
    <span class="stat amb"><b>${t.warning}</b> <small>WARNING</small></span>
    <span class="stat lime"><b>${done}</b> <small>RECLAIMED</small></span>
    ${open ? `<span class="stat grey"><b>${open}</b> <small>TO DO</small></span>` : ''}
    ${t.fog ? `<span class="stat grey"><b>${t.fog}</b> <small>COULDN’T CHECK</small></span>` : ''}
    <span class="switch"><button type="button" data-act="list">LIST</button><b class="on">CITY</b></span>
  </header>`;
}
```

`desktop/renderer/game/views/map.js`:

```js
import { esc } from '../escape.js';
import { SCOUT, mapScoutLine } from '../scout-lines.js';

const SKYLINE = {
  hot: ['iso_tower_occ', 'iso_occupied', 'iso_tower_occ'],
  warn: ['iso_progress', 'iso_occupied'],
  clear: ['iso_liberated', 'iso_tower_lib'],
  partial: ['iso_liberated', 'iso_occupied'],
  fog: ['iso_occupied', 'iso_tower_occ'],
  none: ['iso_occupied'],
};

export function skyline(status) {
  const cls = status === 'fog' || status === 'none' ? 'skyline fog' : 'skyline';
  const tone = { hot: 'dark', warn: 'warm', clear: 'lit', partial: 'lit' }[status] || '';
  return `<div class="${cls}" aria-hidden="true">${(SKYLINE[status] || SKYLINE.none)
    .map((img) => `<img class="${img.includes('tower') ? 'tower ' : ''}${tone}" src="assets/${img}.png" alt="">`).join('')}</div>`;
}

export function districtBadges(d) {
  const crit = d.missions.filter((m) => m.severity === 'critical').length;
  const warn = d.missions.length - crit;
  const out = [];
  if (crit) out.push(`<span class="badge crit">${crit} CRITICAL</span>`);
  if (warn) out.push(`<span class="badge warn">${warn} WARNING</span>`);
  if (d.notes.length) out.push(`<span class="badge skip">${d.notes.length} NOTES</span>`);
  if (d.fog.length) out.push(`<span class="badge fog">${d.fog.length} COULDN’T CHECK</span>`);
  if (d.status === 'clear') out.push('<span class="badge safe">NOTHING FOUND</span>');
  return out.join('');
}

export function districtLine(d) {
  if (d.status === 'fog') return 'Couldn’t check here. That doesn’t mean it’s safe.';
  if (d.status === 'none') return 'No checks ran here on this computer.';
  if (d.status === 'clear') return 'Nothing found in the checks that ran here.';
  return d.blurb;
}

export function renderMap({ city, cameBack, scout }) {
  const cards = city.districts.map((d) => `
      <button type="button" class="district ${esc(d.status)}" data-go="district:${esc(d.id)}">
        <h4>${esc(d.name.toUpperCase())}</h4>
        ${skyline(d.status)}
        <p>${esc(districtLine(d))}</p>
        <span class="d-foot">${districtBadges(d)}</span>
      </button>`).join('');
  const line = cameBack && cameBack.length ? SCOUT.cameBack : mapScoutLine(city);
  return `
  <section class="map" aria-label="Your computer as a city">
    <div class="districts">${cards}</div>
    <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(line)}</p></div>
  </section>`;
}
```

`desktop/renderer/game/views/district.js`:

```js
import { esc } from '../escape.js';
import { skyline, districtLine } from './map.js';

const STATUS_BADGE = {
  open: '', later: '<span class="badge skip">LATER</span>',
  yours: '<span class="badge yours">YOURS</span>', reclaimed: '<span class="badge safe">RECLAIMED</span>',
};

export function renderDistrict({ district: d, progress, scout }) {
  const status = (id) => (progress.missions[id] && progress.missions[id].status) || 'open';
  const missions = d.missions.map((m) => `
      <li><button type="button" class="mission-row" data-go="mission:${esc(m.id)}">
        <span class="badge ${m.severity === 'critical' ? 'crit' : 'warn'}">${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</span>
        <span class="mission-text">${esc(m.title)}</span>
        ${STATUS_BADGE[status(m.id)] || ''}
      </button></li>`).join('');
  const notes = d.notes.map((n) => `<li>${esc(n.title)}</li>`).join('');
  const fog = d.fog.map((x) => `<li><strong>${esc(x.module)}</strong>: ${esc(x.reason)}</li>`).join('');
  return `
  <section class="district-screen">
    <div class="crumbs"><button type="button" data-go="map">Your computer</button> / <b>${esc(d.name)}</b></div>
    <h2 class="m-title">${esc(d.name)}</h2>
    ${skyline(d.status)}
    <p class="intel">${esc(districtLine(d))}</p>
    ${missions ? `<div class="panel active"><div class="label">MISSIONS</div><ul class="missions">${missions}</ul></div>` : ''}
    ${fog ? `<div class="panel fogged"><div class="label">COULDN’T CHECK HERE</div><p class="intel">That doesn’t mean it’s safe.</p><ul class="fog-list">${fog}</ul></div>` : ''}
    ${notes ? `<details class="panel"><summary class="label">NOTES (${d.notes.length})</summary><ul class="notes">${notes}</ul></details>` : ''}
    <div class="scout-row">${scout('happy', 54)}<p class="say">${esc(d.missions.length ? 'Pick one. You can stop after any of them.' : 'Nothing to do here right now.')}</p></div>
  </section>`;
}
```

`desktop/renderer/game/views/briefing.js`:

```js
import { esc } from '../escape.js';
import { SCOUT } from '../scout-lines.js';

export function renderBriefing({ mission: m, status, controlsHtml, scout, busy, wantsSafety }) {
  const steps = m.steps.map((s) => `
      <li class="step"><span class="step-n">${esc(s.number)}</span>
        <span class="step-t">${esc(s.title)}${s.body ? `<small>${esc(s.body)}</small>` : ''}</span></li>`).join('');
  const also = m.findings.length > 1
    ? `<div class="panel"><div class="label">ALSO REPORTED AS</div><ul class="notes">${m.findings.slice(1).map((f) => `<li>${esc(f.title)}</li>`).join('')}</ul></div>` : '';
  const safety = wantsSafety && m.safetyNote ? `<div class="panel safety" role="note">${esc(m.safetyNote)}</div>` : '';
  const actions = busy
    ? `<p class="checking" role="status" aria-live="polite">${esc(SCOUT.checking)} Checking again…</p>`
    : `<div class="row">
        <button type="button" class="btn-s" data-act="i-did-it">I DID IT MYSELF</button>
        <button type="button" class="btn-t" data-act="later">LATER</button>
      </div>`;
  return `
  <section class="brief">
    <div class="brief-main">
      <div class="crumbs"><button type="button" data-go="district:${esc(m.districtId)}">Back</button> / <b>${m.severity === 'critical' ? 'CRITICAL' : 'WARNING'}</b>${status === 'later' ? ' · saved for later' : ''}</div>
      <h2 class="m-title"><span>${esc(m.title)}</span></h2>
      <div class="panel"><div class="label">WHAT IT IS</div><p class="intel">${esc(m.description)}</p></div>
      ${safety}
      <div class="panel active"><div class="label">YOUR MOVE</div>
        ${m.walkthroughTitle ? `<p class="from">From the walkthrough “${esc(m.walkthroughTitle)}”.</p>` : ''}
        <ol class="steps">${steps}</ol></div>
      ${also}
      <div class="controls" ${busy ? 'hidden' : ''}>${controlsHtml}</div>
      ${actions}
    </div>
    <aside class="brief-side">${scout(m.severity === 'critical' ? 'worried' : 'thinkingA', 72)}
      <span class="scout-name">SCOUT</span><p class="say">${esc(SCOUT.briefing[m.severity])}</p></aside>
  </section>`;
}
```

`desktop/renderer/game/views/outcome.js`:

```js
import { esc } from '../escape.js';
import { SCOUT } from '../scout-lines.js';

export function renderOutcome({ kind, mission: m, scout, message, undoHtml }) {
  if (kind === 'reclaimed') {
    return `
    <section class="outcome o-win">
      <span class="badge safe">CHECKED AGAIN: GONE</span>
      <h2>RECLAIMED</h2>
      <p>${esc(SCOUT.reclaimed)}</p>
      ${undoHtml || ''}
      <p class="label">HOW DID THAT GO?</p>
      <div class="choices">
        <button type="button" class="choice" data-act="debrief:easy">Easier than I thought</button>
        <button type="button" class="choice" data-act="debrief:nervous">A bit nerve-wracking</button>
        <button type="button" class="choice" data-act="debrief:worried">I’m still worried</button>
      </div>
      ${scout('proud', 72)}
    </section>`;
  }
  if (kind === 'yours') {
    return `
    <section class="outcome o-yours">
      <span class="badge yours">MARKED AS YOURS</span><h2>YOURS</h2><p>${esc(SCOUT.yours)}</p>
      <button type="button" class="btn-s" data-go="district:${esc(m.districtId)}">BACK TO THE DISTRICT</button>
    </section>`;
  }
  if (kind === 'not-yet') {
    return `
    <section class="outcome o-not">
      <span class="badge warn">CHECKED AGAIN: STILL THERE</span><h2>NOT YET</h2>
      <p>Here’s what’s still showing: ${esc(m.title)}</p>
      ${message ? `<p>${esc(message)}</p>` : ''}
      <div class="scout-row">${scout('thinkingA', 54)}<p class="say">${esc(SCOUT.notYet)}</p></div>
      <button type="button" class="btn-s" data-go="mission:${esc(m.id)}">BACK TO THE STEPS</button>
    </section>`;
  }
  return `
    <section class="outcome o-err">
      <span class="badge fog">COULDN’T RE-CHECK</span><h2>COULDN’T RE-CHECK</h2>
      <p>${esc(SCOUT.couldnt)} The building stays dark until a check can see it.</p>
      ${message ? `<p class="from">${esc(message)}</p>` : ''}
      <div class="row"><button type="button" class="btn-s" data-act="recheck">TRY THE RE-CHECK AGAIN</button>
      <button type="button" class="btn-t" data-go="mission:${esc(m.id)}">BACK TO THE STEPS</button></div>
    </section>`;
}
```

`desktop/renderer/game/views/milestone.js`:

```js
import { esc } from '../escape.js';

const statusOf = (progress, id) => (progress.missions[id] && progress.missions[id].status) || 'open';

export function districtComplete(district, progress) {
  return district.missions.length > 0
    && district.missions.every((m) => ['reclaimed', 'yours'].includes(statusOf(progress, m.id)));
}

export function renderMilestone({ district: d, progress, scout }) {
  const fixed = d.missions.filter((m) => statusOf(progress, m.id) === 'reclaimed');
  const yours = d.missions.filter((m) => statusOf(progress, m.id) === 'yours');
  return `
  <section class="outcome o-win milestone">
    <span class="badge safe">DISTRICT TAKEN BACK</span>
    <h2>${esc(d.name.toUpperCase())}</h2>
    ${scout('proud', 72)}
    <p>Every mission here is done. Device Rescue checked each fix again.</p>
    ${fixed.length ? `<div class="panel"><div class="label">FIXED AND CHECKED</div><ul class="notes">${fixed.map((m) => `<li>${esc(m.title)}</li>`).join('')}</ul></div>` : ''}
    ${yours.length ? `<div class="panel"><div class="label">MARKED AS YOURS</div><p class="intel">These stay listed. They weren’t fixed, because you said they’re yours.</p><ul class="notes">${yours.map((m) => `<li>${esc(m.title)}</li>`).join('')}</ul></div>` : ''}
    <button type="button" class="btn-s" data-go="map">BACK TO THE CITY</button>
  </section>`;
}
```

- [ ] **Step 5: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-views.test.js`
Expected: PASS (9 tests). If the HUD regex fails, check that the markup is exactly `<b>1</b> <small>RECLAIMED`.

- [ ] **Step 6: Commit**

```bash
git add desktop/renderer/game/escape.js desktop/renderer/game/scout-lines.js desktop/renderer/game/views desktop/test/game-views.test.js
git commit -m "Add the city's map, district, briefing, outcome and milestone views"
```

---

### Task 10: Boot with the analytics switch-off set first

**Files:**
- Create: `desktop/renderer/game/opt-out.js`, `game/boot-core.js`, `game/boot.js`
- Test: `desktop/test/game-boot.test.js`

**Interfaces:**
- Produces:
  - `OPT_OUT = {'reclaim-city.analytics-off': '1', 'umami.disabled': '1'}`
  - `applyOptOut(storage) -> boolean`
  - `boot({storage, importModule, win}) -> Promise<controller>`. `importModule(specifier)` is `(s) => import(s)` in the browser and a stub in tests.
  - It sets `win.RescueGame` and dispatches `rescue-game-ready` on `win`.

- [ ] **Step 1: Write the failing test**

Create `desktop/test/game-boot.test.js`:

```js
const test = require('node:test');
const assert = require('node:assert');

test('boot sets both opt-out keys before importing any game code', async () => {
  const { boot } = await import('../renderer/game/boot-core.js');
  const store = {}; const storage = { setItem: (k, v) => { store[k] = v; }, getItem: (k) => store[k] ?? null };
  const seenAtImport = [];
  const events = [];
  const win = { dispatchEvent: (e) => events.push(e.type), localStorage: storage };
  const controller = { show() {} };
  await boot({
    storage, win,
    importModule: async (spec) => {
      seenAtImport.push([spec, store['reclaim-city.analytics-off'], store['umami.disabled']]);
      if (spec.endsWith('controller.js')) return { createController: () => controller };
      return { scoutSprite: () => '' };
    },
  });
  assert.ok(seenAtImport.length >= 2);
  for (const [spec, a, u] of seenAtImport) assert.deepStrictEqual([a, u], ['1', '1'], spec);
  assert.strictEqual(win.RescueGame, controller);
  assert.deepStrictEqual(events, ['rescue-game-ready']);
});

test('applyOptOut survives storage that throws', async () => {
  const { applyOptOut } = await import('../renderer/game/opt-out.js');
  assert.strictEqual(applyOptOut({ setItem() { throw new Error('denied'); } }), false);
  assert.strictEqual(applyOptOut(null), false);
});
```

- [ ] **Step 2: Run it to make sure it fails**

Run: `cd desktop && node --test test/game-boot.test.js`
Expected: FAIL with `Cannot find module`.

- [ ] **Step 3: Write the three files**

`desktop/renderer/game/opt-out.js`:

```js
// Reclaim City's own "turn sharing off" switch. Game mode never loads the
// game's analytics or error-reporting scripts, but the switch is set anyway,
// first, so no game code ever starts with sharing on.
export const OPT_OUT = { 'reclaim-city.analytics-off': '1', 'umami.disabled': '1' };

export function applyOptOut(storage) {
  try {
    for (const [k, v] of Object.entries(OPT_OUT)) storage.setItem(k, v);
    return true;
  } catch (_) {
    return false;
  }
}
```

`desktop/renderer/game/boot-core.js`:

```js
import { applyOptOut } from './opt-out.js';

export async function boot({ storage, importModule, win }) {
  applyOptOut(storage);
  const [{ createController }, { scoutSprite }] = await Promise.all([
    importModule('./controller.js'),
    importModule('../rc/components/scout.js'),
  ]);
  const controller = createController({ win, storage, scoutSprite });
  win.RescueGame = controller;
  win.dispatchEvent(new Event('rescue-game-ready'));
  return controller;
}
```

`desktop/renderer/game/boot.js`:

```js
import { boot } from './boot-core.js';

boot({ storage: window.localStorage, importModule: (s) => import(s), win: window })
  .catch((err) => { console.error('Game mode could not start:', err); });
```

`import()` in `boot.js`'s arrow function resolves against `boot.js`'s own URL, `app://rescue/game/boot.js`. So `./controller.js` becomes `app://rescue/game/controller.js`, and `../rc/components/scout.js` becomes `app://rescue/rc/components/scout.js`, which the protocol maps to the vendored file.

- [ ] **Step 4: Run the tests and make sure they pass**

Run: `cd desktop && node --test test/game-boot.test.js`
Expected: PASS. (`Event` is a global in Node 22.)

- [ ] **Step 5: Commit**

```bash
git add desktop/renderer/game/opt-out.js desktop/renderer/game/boot-core.js desktop/renderer/game/boot.js desktop/test/game-boot.test.js
git commit -m "Start game mode only after Reclaim City's sharing switch is off"
```

---

### Task 11: The controller, styles, fonts and page wiring

**Files:**
- Create: `desktop/renderer/game/controller.js`, `game/game.css`, `desktop/renderer/game-fonts.css`, `desktop/renderer/game/fonts/` (woff2 files plus `OFL.txt`)
- Modify: `desktop/renderer/index.html` (the welcome card buttons, a new `screen-city` section, a results switch, the stylesheet link, the module script)
- Modify: `desktop/renderer/app.js` (the screens map, `showScreen`, Welcome, `runCheckup`, the results switch, `window.RescueHost`)
- Modify: `desktop/app-protocol.js` (no change needed; `game/fonts/*.woff2` is already served from `renderer/`)
- Test: covered by Tasks 7–10 plus the manual check in Step 9.

**Interfaces:**
- Consumes: everything above, plus `window.rescue.recheckModule`, `window.FixFlow`, `window.MarkFlow`, and `wantsSafetyNote(situation, finding)` from app.js (passed in through `RescueHost`).
- Produces:
  - `createController({win, storage, scoutSprite}) -> { show(doc, situation), update(doc), isReady: true }`
  - `window.RescueHost = { showList(), docChanged(doc) -> boolean, wantsSafety(finding) -> boolean }`, set by app.js.

- [ ] **Step 1: Add the fonts**

```bash
cd /Users/annhoward/src/multiverse_device_rescue/desktop/renderer/game
mkdir -p fonts && cd fonts
OV=$(npm view @fontsource/orbitron version); IV=$(npm view @fontsource/inter version); JV=$(npm view @fontsource/jetbrains-mono version)
for w in 600 700 800 900; do curl -fsSLO "https://cdn.jsdelivr.net/npm/@fontsource/orbitron@$OV/files/orbitron-latin-$w-normal.woff2"; done
for w in 400 500 600 700; do curl -fsSLO "https://cdn.jsdelivr.net/npm/@fontsource/inter@$IV/files/inter-latin-$w-normal.woff2"; done
for w in 400 600 700; do curl -fsSLO "https://cdn.jsdelivr.net/npm/@fontsource/jetbrains-mono@$JV/files/jetbrains-mono-latin-$w-normal.woff2"; done
curl -fsSL "https://cdn.jsdelivr.net/npm/@fontsource/orbitron@$OV/LICENSE" -o OFL.txt
ls -la
```

Expected: 11 `.woff2` files plus `OFL.txt`. All three families are SIL OFL 1.1. Add one line at the top of `OFL.txt`: `Orbitron, Inter and JetBrains Mono, from Fontsource. Each is licensed under the SIL Open Font License 1.1.`

- [ ] **Step 2: Write `desktop/renderer/game-fonts.css`**

`@font-face` has to be at document level. Inside a shadow root it's ignored.

```css
/* Fonts for game mode (Reclaim City's faces). Local files only; see game/fonts/OFL.txt. */
@font-face { font-family: 'Orbitron'; font-weight: 600; font-display: swap; src: url(game/fonts/orbitron-latin-600-normal.woff2) format('woff2'); }
@font-face { font-family: 'Orbitron'; font-weight: 700; font-display: swap; src: url(game/fonts/orbitron-latin-700-normal.woff2) format('woff2'); }
@font-face { font-family: 'Orbitron'; font-weight: 800; font-display: swap; src: url(game/fonts/orbitron-latin-800-normal.woff2) format('woff2'); }
@font-face { font-family: 'Orbitron'; font-weight: 900; font-display: swap; src: url(game/fonts/orbitron-latin-900-normal.woff2) format('woff2'); }
@font-face { font-family: 'Inter'; font-weight: 400; font-display: swap; src: url(game/fonts/inter-latin-400-normal.woff2) format('woff2'); }
@font-face { font-family: 'Inter'; font-weight: 500; font-display: swap; src: url(game/fonts/inter-latin-500-normal.woff2) format('woff2'); }
@font-face { font-family: 'Inter'; font-weight: 600; font-display: swap; src: url(game/fonts/inter-latin-600-normal.woff2) format('woff2'); }
@font-face { font-family: 'Inter'; font-weight: 700; font-display: swap; src: url(game/fonts/inter-latin-700-normal.woff2) format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 400; font-display: swap; src: url(game/fonts/jetbrains-mono-latin-400-normal.woff2) format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 600; font-display: swap; src: url(game/fonts/jetbrains-mono-latin-600-normal.woff2) format('woff2'); }
@font-face { font-family: 'JetBrains Mono'; font-weight: 700; font-display: swap; src: url(game/fonts/jetbrains-mono-latin-700-normal.woff2) format('woff2'); }
```

- [ ] **Step 3: Write `desktop/renderer/game/game.css`**

This goes inside the shadow root, after `rc/style.css`. The tokens are copied from Reclaim City's `:root`, because `:root` doesn't match inside a shadow root.

The component classes match the approved mockups, which are committed as `docs/superpowers/specs/2026-10-16-game-mode-mockups.html` (published at https://claude.ai/artifact/WbCeYuokcwuxY63EzWFEVK). From that file's `<style>` block, copy these rule groups verbatim:
- `.hud`, `.hud-title`, `.stat*`, `.switch*`
- `.label`, `.panel*`, `.btn-p`, `.btn-s*`, `.btn-t`, `.row`, `.badge*`
- `.say`, `.scout-name`, `.map`, `.districts`, `.district*`, `.skyline*`, `.d-foot`
- `.brief*`, `.crumbs`, `.m-title*`, `.intel`, `.mono`, `.steps`, `.step*`
- `.outcome*`, `.o-*`, `.choices`, `.choice*`

Leave out the page chrome: `.page`, `.intro`, `nav.jump`, `.shot*`, `.win*`, `.dr*`, `.train`, `.boss`. Spec C adds `.train` and `.boss`.

Change three things while copying:
1. Every `.switch b` selector becomes `.switch b, .switch button`.
2. Add `.scout-row { display: flex; gap: 12px; align-items: flex-start; }`.
3. Add `.mission-row { display: flex; gap: 10px; align-items: center; width: 100%; padding: 10px 0; }`.

Start the file with:

```css
:host {
  --cyan: #00E5FF; --magenta: #FF2D9B; --lime: #C6FF00; --amber: #FF9F00;
  --charcoal: #1A1F2B; --midnight: #090B10; --offwhite: #EDEFF3;
  --dim: rgba(237,239,243,0.55); --faint: rgba(237,239,243,0.32); --line: rgba(0,229,255,0.15);
  --font-display: 'Orbitron', 'Arial Black', sans-serif;
  --font-body: 'Inter', system-ui, -apple-system, sans-serif;
  --font-mono: 'JetBrains Mono', ui-monospace, Menlo, monospace;
  display: block; color-scheme: dark;
  background: linear-gradient(180deg, #090B10 0%, #0d1018 45%, #121828 100%);
  color: var(--offwhite); font-family: var(--font-body); font-size: 15px; line-height: 1.55;
  min-height: 100%;
}
button { font: inherit; color: inherit; background: none; border: 0; cursor: pointer; text-align: inherit; }
button.district { display: grid; width: 100%; }
:focus-visible { outline: 2px solid var(--cyan); outline-offset: 2px; }
@media (prefers-reduced-motion: reduce) { * { animation: none !important; transition: none !important; } }
/* Device Rescue's fix and mark controls, in the city's colors */
.fix-it .btn, .mark-it .btn { font-family: var(--font-display); font-size: 10px; letter-spacing: 1px; padding: 10px 16px; border: 1px solid rgba(0,229,255,0.3); color: var(--cyan); background: rgba(0,229,255,0.08); }
.fix-it .btn--primary { background: var(--cyan); color: var(--midnight); }
.fix-panel { border: 1px solid rgba(0,229,255,0.45); background: rgba(0,229,255,0.05); padding: 16px; margin-top: 10px; display: grid; gap: 8px; }
.fix-status__box { border-left: 2px solid var(--cyan); padding: 6px 12px; margin-top: 10px; }
.fix-status--error { border-left-color: var(--magenta); }
.fix-status--warning { border-left-color: var(--amber); }
.panel.safety { border-color: rgba(255,159,0,0.45); }
.checking { font-family: var(--font-mono); color: var(--cyan); }
```

Then add the mockup rules for the listed classes. Check the result at 720px wide (the window's `minWidth`): the district grid must wrap, and the briefing must stack to one column below 720px.

- [ ] **Step 4: Write `desktop/renderer/game/controller.js`**

```js
// The only DOM code in game mode. Renders the city into a shadow root on the
// "city" screen and wires clicks, fixes, marks and re-checks.
import { findingsToCity } from './findings-to-city.js';
import { loadProgress, saveProgress, reconcile, setStatus, ranOkModules, recheckOutcome } from './progress.js';
import { renderHud } from './views/hud.js';
import { renderMap } from './views/map.js';
import { renderDistrict } from './views/district.js';
import { renderBriefing } from './views/briefing.js';
import { renderOutcome } from './views/outcome.js';
import { districtComplete, renderMilestone } from './views/milestone.js';
import { debriefReply } from './scout-lines.js';
import { esc } from './escape.js';

export function createController({ win, storage, scoutSprite }) {
  const doc0 = win.document;
  const host = doc0.getElementById('city-host');
  const shadow = host.attachShadow({ mode: 'open' });
  shadow.innerHTML = '<link rel="stylesheet" href="rc/style.css"><link rel="stylesheet" href="game/game.css"><div class="frame" id="frame"></div>';
  const frame = shadow.getElementById('frame');
  const scout = (feeling, size) => scoutSprite(feeling, { size });
  const now = () => new Date().toISOString();

  const s = { doc: null, situation: null, city: null, progress: loadProgress(storage), cameBack: [],
    screen: 'map', districtId: null, missionId: null, outcome: null, message: '', busy: false };

  function rebuild(doc) {
    s.doc = doc;
    s.city = findingsToCity(doc);
    const r = reconcile(s.progress, s.city, ranOkModules(doc), now());
    s.progress = r.progress;
    s.cameBack = r.cameBack;
    saveProgress(storage, s.progress);
  }
  const mission = (id) => s.city.districts.flatMap((d) => d.missions).find((m) => m.id === id) || null;
  const district = (id) => s.city.districts.find((d) => d.id === id) || null;

  function screenHtml() {
    if (s.screen === 'milestone' && district(s.districtId)) {
      return renderMilestone({ district: district(s.districtId), progress: s.progress, scout });
    }
    if (s.screen === 'district' && district(s.districtId)) {
      return renderDistrict({ district: district(s.districtId), progress: s.progress, scout });
    }
    if (s.screen === 'mission' && mission(s.missionId)) {
      const m = mission(s.missionId);
      const controls = `${win.FixFlow.fixControlsHtml(m.primary, { watched: false })}${win.MarkFlow.markControlsHtml(m.primary)}`;
      return renderBriefing({ mission: m, status: (s.progress.missions[m.id] || {}).status || 'open', controlsHtml: controls,
        scout, busy: s.busy, wantsSafety: win.RescueHost.wantsSafety(m.primary) });
    }
    if (s.screen === 'outcome' && s.outcome) {
      // After a fix the engine can undo, offer Undo here too. FixFlow handles the
      // click, because this sits inside a [data-fix-module] card on the frame.
      const lf = s.lastFix;
      const undoHtml = s.outcome === 'reclaimed' && lf && lf.result && lf.result.quarantine_id
        ? `<div class="fix-it" data-fix-module="${esc(lf.module)}"><div class="fix-status" data-fix-status>${win.FixFlow.resultHtml(lf.result)}</div></div>`
        : '';
      return renderOutcome({ kind: s.outcome, mission: s.outcomeMission, scout, message: s.message, undoHtml });
    }
    s.screen = 'map';
    return renderMap({ city: s.city, progress: s.progress, cameBack: s.cameBack, scout });
  }

  function render() {
    try {
      frame.innerHTML = renderHud({ title: 'YOUR COMPUTER', city: s.city, progress: s.progress }) + screenHtml();
    } catch (err) {
      console.error('City view failed:', err);
      frame.innerHTML = `<p class="say">${esc('The city view hit a problem. Here’s the same thing as a list.')}</p>`;
      win.RescueHost.showList();
    }
  }

  async function recheck(missionId) {
    const m = mission(missionId) || s.outcomeMission;
    if (!m || s.busy) return;
    s.busy = true; s.screen = 'mission'; s.missionId = m.id; render();
    let res;
    try { res = await win.rescue.recheckModule(m.module); } catch (_) { res = null; }
    s.busy = false;
    if (res && res.ok) {
      if (!win.RescueHost.docChanged(res.doc)) return; // the gate closed: app.js showed the list
      rebuild(res.doc);
    }
    s.outcome = recheckOutcome(m.id, s.city, res);
    s.outcomeMission = mission(m.id) || m;
    s.message = res && !res.ok ? res.message || '' : '';
    s.screen = 'outcome';
    render();
  }

  frame.addEventListener('click', (e) => {
    const el = e.target.closest('[data-go],[data-act]');
    if (!el || s.busy) return;
    const go = el.getAttribute('data-go');
    const act = el.getAttribute('data-act');
    if (go === 'map') { s.screen = 'map'; render(); return; }
    if (go && go.startsWith('district:')) { s.screen = 'district'; s.districtId = go.slice(9); render(); return; }
    if (go && go.startsWith('milestone:')) { s.screen = 'milestone'; s.districtId = go.slice(10); render(); return; }
    if (go && go.startsWith('mission:')) { s.screen = 'mission'; s.missionId = go.slice(8); render(); return; }
    if (act === 'list') { win.RescueHost.showList(); return; }
    if (act === 'i-did-it') { recheck(s.missionId); return; }
    if (act === 'recheck') { recheck(s.outcomeMission && s.outcomeMission.id); return; }
    if (act === 'later') {
      const m = mission(s.missionId);
      if (m) { s.progress = setStatus(s.progress, m.id, 'later', m.module, now()); saveProgress(storage, s.progress); s.screen = 'district'; s.districtId = m.districtId; }
      render(); return;
    }
    if (act && act.startsWith('debrief:')) {
      const choices = frame.querySelector('.choices');
      const d = district(s.outcomeMission.districtId);
      const next = d && districtComplete(d, s.progress)
        ? `<button type="button" class="btn-p" data-go="milestone:${esc(d.id)}">SEE ${esc(d.name.toUpperCase())}</button>`
        : `<button type="button" class="btn-s" data-go="district:${esc(s.outcomeMission.districtId)}">BACK TO THE DISTRICT</button>`;
      if (choices) choices.outerHTML = `<p class="say">${esc(debriefReply(act.slice(8)))}</p>${next}`;
    }
  });

  // Device Rescue's own fix and mark flows, delegated on the frame so they survive re-renders.
  win.FixFlow.attach(frame, win.rescue, { onResult: ({ kind, module, result, described }) => {
    if (kind === 'fix') s.lastFix = { module, result };
    if (kind === 'undo' && described && described.restored) s.lastFix = null;
    if (described && (described.tone === 'success' || described.tone === 'info' || described.restored)) recheck(s.missionId);
  } });
  win.MarkFlow.attach(frame, win.rescue, { onResult: ({ described }) => {
    if (described && described.done) recheck(s.missionId);
  } });

  return {
    isReady: true,
    show(doc, situation) {
      s.situation = situation;
      rebuild(doc);
      s.screen = 'map'; s.outcome = null;
      render();
    },
    update(doc) { rebuild(doc); render(); },
  };
}
```

- [ ] **Step 5: Change `index.html`**

In `<head>`, after the `styles.css` link, add:

```html
  <link rel="stylesheet" href="game-fonts.css" />
```

Replace the Get started button in the welcome card with:

```html
          <div class="welcome-actions">
            <button id="btn-get-started" class="btn btn--primary btn--large" type="button">Get started</button>
            <button id="btn-play-game" class="btn btn--game btn--large" type="button">Play it as a game
              <small>Same checkup, as a city to take back</small></button>
          </div>
```

In the results card, directly after `<div id="results-summary" class="results-summary"></div>`, add:

```html
          <p id="results-city-switch" hidden>
            <button id="btn-see-city" class="btn btn--game" type="button">See it as a city</button>
          </p>
```

After the closing `</section>` of `screen-results`, add:

```html
      <!-- Screen 5: the same results as a city (game mode). Rendered in a shadow root. -->
      <section id="screen-city" class="screen screen--city" data-screen="city" aria-label="Your computer as a city" hidden>
        <div id="city-host"></div>
      </section>
```

After `<script src="app.js"></script>`, add:

```html
  <script type="module" src="game/boot.js"></script>
```

In `styles.css`, add the following. It's in Device Rescue's own file, uses its own token names, and adds no new colors to the list view:

```css
.welcome-actions { display: flex; flex-wrap: wrap; gap: 12px; align-items: center; }
.btn--game { background: #0b0e15; color: #00E5FF; border: 1px solid #0b0e15; }
.btn--game small { display: block; font-weight: 400; font-size: 12px; color: rgba(237,239,243,0.65); }
.screen--city { padding: 0; }
#city-host { min-height: 70vh; }
```

- [ ] **Step 6: Wire up `app.js`**

Inside the browser-only IIFE:
- Add `city: document.getElementById('screen-city'),` to `screens`.
- In `showScreen`, change the dot toggle to use `const dotName = name === 'city' ? 'results' : name;`.
- Then add the following after the `let situation = null;` line:

```js
    let wantsCity = false; // came in through "Play it as a game"
    const VIEW_KEY = 'device-rescue.view';
    function rememberView(v) { try { localStorage.setItem(VIEW_KEY, v); } catch (_) { /* per-viewer nicety only */ } }
    function rememberedView() { try { return localStorage.getItem(VIEW_KEY); } catch (_) { return null; } }

    function cityAvailable(doc) {
      return gameOfferedFor(situation, doc) && !!(window.RescueGame && window.RescueGame.isReady);
    }
    function showCity(doc) {
      if (!cityAvailable(doc)) { showScreen('results'); return; }
      window.RescueGame.show(doc, situation);
      rememberView('city');
      showScreen('city');
    }
    function renderCitySwitch(doc) {
      document.getElementById('results-city-switch').hidden = !cityAvailable(doc);
    }

    window.RescueHost = {
      showList() { rememberView('list'); showScreen('results'); },
      // A re-check changed the scan. Keep the list in step, and close the city if
      // the gate closed (e.g. monitoring software turned up).
      docChanged(doc) {
        lastScanDoc = doc;
        renderResults(doc);
        renderLearnMore(doc);
        renderCitySwitch(doc);
        if (!gameOfferedFor(situation, doc)) { showScreen('results'); return false; }
        return true;
      },
      wantsSafety(finding) { return wantsSafetyNote(situation, finding); },
    };
    window.addEventListener('rescue-game-ready', () => { if (lastScanDoc) renderCitySwitch(lastScanDoc); });
```

In `runCheckup`, replace the two lines `setScanBusy(false);` and `showScreen('results');` (on success) with:

```js
        setScanBusy(false);
        renderCitySwitch(doc);
        if ((wantsCity || rememberedView() === 'city') && cityAvailable(doc)) showCity(doc);
        else showScreen('results');
```

Change the `btn-get-started` handler to `wantsCity = false; showScreen('worry');`, and add:

```js
    document.getElementById('btn-play-game').addEventListener('click', () => {
      wantsCity = true;
      showScreen('worry');
    });
    document.getElementById('btn-see-city').addEventListener('click', () => {
      if (lastScanDoc) showCity(lastScanDoc);
    });
```

In `resetToWelcome`, add `wantsCity = false;`.

- [ ] **Step 7: Run the desktop suite**

Run: `cd desktop && npm test`
Expected: PASS.

- [ ] **Step 8: Write the whole-flow manual check down as a doc so it survives**

Add `desktop/MANUAL-QA.md`, or append a section if the file exists. Use exactly the steps in Step 9, so whoever runs a release repeats them.

- [ ] **Step 9: Manual check on a Mac**

Set up a harmless test launch agent:

```bash
mkdir -p ~/Library/LaunchAgents ~/Library/Application\ Support/.dr-qa
printf '#!/bin/sh\nexit 0\n' > ~/Library/Application\ Support/.dr-qa/helper && chmod +x ~/Library/Application\ Support/.dr-qa/helper
cat > ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist <<'EOF'
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0"><dict><key>Label</key><string>com.devicerescue.qa.helper</string>
<key>ProgramArguments</key><array><string>/Users/USER/Library/Application Support/.dr-qa/helper</string></array></dict></plist>
EOF
sed -i '' "s#/Users/USER#$HOME#" ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist
```

Then run `RESCUE_ENGINE="$PWD/.venv/bin/rescue" npm --prefix desktop start` and check:
1. Click **Play it as a game**, then **I'm not sure**, then **Run checkup**. The city appears with The Gatehouse dark, and DevTools' Console shows no CSP errors.
2. DevTools → Network, filtered to "All": every request is `app://rescue/…`. There is no `https://`.
3. Open The Gatehouse, then the `com.devicerescue.qa.helper` mission. Click **Fix it for me**, check that the panel text matches the list view's, and click **Yes, fix it**. "Checking again" appears, then **RECLAIMED**.
4. Click **LIST**. The finding is gone from the list view too. Click **See it as a city** to go back.
5. Go back into the city, to the RECLAIMED screen of that mission (do the fix again if needed), and click **Undo**. It re-checks and shows **NOT YET**, and the building is dark again on the map. Then run a full checkup from the list. The mission is still open, not reclaimed.
6. Start over, pick **I think someone is watching me**, and run the checkup. No city is offered anywhere.
7. Clean up: `rm ~/Library/LaunchAgents/com.devicerescue.qa.helper.plist; rm -r ~/Library/Application\ Support/.dr-qa`.

Record anything that doesn't match as a bug and fix it before you commit.

- [ ] **Step 10: Commit**

```bash
git add desktop/renderer/game desktop/renderer/game-fonts.css desktop/renderer/index.html desktop/renderer/app.js desktop/renderer/styles.css desktop/MANUAL-QA.md docs/superpowers/specs/2026-10-16-game-mode-mockups.html
git commit -m "Add game mode: the scan as a city, with re-checked missions"
```

---

### Task 12: CI runs the desktop tests with the submodule

**Files:**
- Modify: `.github/workflows/tests.yml` (a new `desktop` job)
- Modify: `.github/workflows/release.yml` (checkout)

- [ ] **Step 1: Add the job to `tests.yml`**

Add this under `jobs:`:

```yaml
  desktop:
    name: desktop app tests
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          submodules: true
      - uses: actions/setup-node@v4
        with:
          node-version: '22'
          cache: npm
          cache-dependency-path: desktop/package-lock.json
      - name: Install and test
        working-directory: desktop
        env:
          # The tests never start Electron; skip its ~100MB download.
          ELECTRON_SKIP_BINARY_DOWNLOAD: '1'
        run: |
          npm ci
          npm test
```

- [ ] **Step 2: Make `release.yml` check out the submodule**

Change `- uses: actions/checkout@v4` in the `build` job to:

```yaml
      - uses: actions/checkout@v4
        with:
          submodules: true
```

- [ ] **Step 3: Validate the YAML locally**

Run: `python -c "import yaml,sys; [yaml.safe_load(open(f)) for f in ['.github/workflows/tests.yml','.github/workflows/release.yml']]; print('ok')"`
Expected: `ok`.

- [ ] **Step 4: Commit**

```bash
git add .github/workflows/tests.yml .github/workflows/release.yml
git commit -m "Run the desktop tests in CI, with the game submodule checked out"
```

---

### Task 13: Docs

**Files:**
- Modify: `CONTRIBUTING.md` (the clone step)
- Modify: `README.md` (the "What it checks" section)

- [ ] **Step 1: In `CONTRIBUTING.md`, change the clone command and add the submodule note**

```markdown
git clone --recurse-submodules https://github.com/lizTheDeveloper/multiverse-device-rescue.git
```

Under it, add: `Already cloned? Run git submodule update --init. The desktop app's game mode uses Reclaim City's art and components from desktop/vendor/reclaim-city. Don't edit files there. Change them in privacy-the-game and bump the pinned commit.`

- [ ] **Step 2: In `README.md`, after "When it finds something, it explains…", add:**

```markdown
Prefer to play? Choose **Play it as a game** and the same checkup becomes a
city to take back, one building at a time, in the style of
[Reclaim City](https://play.multiversegames.ai/reclaim-city/). It's the same
checks and the same fixes, and each fix still asks first. A building only lights
up once Device Rescue has checked again and the problem is gone. If you've said
someone may be watching you, the app doesn't offer the game.
```

- [ ] **Step 3: Commit**

```bash
git add CONTRIBUTING.md README.md
git commit -m "Document game mode and the Reclaim City submodule"
```

---

## Self-Review Notes

- **Spec coverage:**

  | Spec section | Task |
  | --- | --- |
  | §2.1 vendored code (as amended) | 2, 3, 10, 11 |
  | §2.2 engine `--module` | 1 |
  | §2.3 IPC and gatekeeping (as amended: merge plus `remember`) | 4 |
  | §3 city mapping (fog, notes, identity, steps) | 7 |
  | §4 entry, gate, mission loop, undo | 5, 6, 11 |
  | §5 progress | 8 |
  | §6 errors | 4, 8, 9, 11 |
  | §7 tests | each task; CI in 12 |
  | Overview rule 4 (nothing leaves) | 3 (CSP and origin), 10 (opt-out first), 11 (network check) |
  | Overview rule 6 (always back to the list) | 9 (HUD switch), 11 (render failure falls back) |

- **Deferred to review on purpose:** the district names and Scout's lines are placeholders, as spec §9 says.
- **Known limitation:** a re-check's partial scan links marks only within that module. The merged scan keeps the other modules' mark groups, so a mark made right after a re-check covers this module's id only until the next full scan. That's safe, because it never covers more than the person agreed to.
