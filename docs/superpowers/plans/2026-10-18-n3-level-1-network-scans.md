# N3 Level 1 Network Scans Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Connection and port checks on macOS, Linux and Windows from one shared collector; an opt-in, bounded, stoppable `rescue watch` connection watch with DNS where visible; and a WATCH CONNECTIONS instrument on the command center deck.

**Architecture:** A data-only helper package `modules/network/conn_common/` (loaded by path, like `lan_common`) parses each platform's connection, byte and DNS output into one record shape. The three existing connection checks switch to it. `rescue/watch.py` runs repeated snapshots with an injected collector, clock and stop signal, and builds `network.connection_watch.*` findings; `rescue watch` prints them as a scan-shaped JSON document. The desktop spawns it, merges the result into the last scan, and shows it on the deck.

**Tech Stack:** Python 3.12 (click, pytest), Electron main (CommonJS), renderer game (ES modules), `node --test`.

**Spec:** `docs/superpowers/specs/2026-10-18-n3-level-1-network-scans-design.md` (parent: `docs/superpowers/specs/2026-10-18-network-analysis-training-design.md`)

## Global Constraints

- Read-only everywhere. No `sudo`, no elevation, no `--auto`/`--yes` paths.
- Every external command goes through `rescue.command.run` with an argument list and numeric flags (`-n`, `-P`) so nothing resolves names. Nothing is sent off the computer.
- "Couldn't run" ≠ "clean": a failed or missing command gives a couldn't-check finding (info) or `supported: False` with a reason; never an empty clean result.
- Finding codes are literal at each `Finding(...)` call and declared in `emits_codes` (or `WATCH_CODES`, Task 4). Existing codes keep their names and wording.
- Platform enum values: `Platform.DARWIN`, `Platform.LINUX`, `Platform.WIN32`.
- Watch bounds: `--minutes` 1–30 (default 5); `--interval` 2–60 s (default 5); at most 2,000 distinct (process, destination) pairs and 200 timestamps per pair.
- Desktop minute allowlist: `[1, 2, 5, 10, 15, 30]`.
- Every watch finding is severity `info`. No missions, no points, nothing written to the progress store.
- No time estimates in any doc or copy.
- Any task editing `rescue/*.py` runs `uv run python scripts/generate_integrity_manifest.py` and commits `rescue/security/integrity_manifest.json` with it.
- Copy is plain language; never tells anyone to kill a process.

## Review Focus

1. A watch stopped before its first snapshot finishes: still prints a valid document with `watch_incomplete` saying nothing was gathered (Task 4 test `test_stop_before_first_snapshot`).
2. A command missing on this machine (`ss` absent on an old Linux, PowerShell blocked): couldn't-check, not clean (Task 1 `test_missing_command_is_couldnt_check`, Task 2/3 module tests).
3. Desktop window closed or app quit mid-watch: the engine child is stopped, not orphaned (Task 7 `stops the watch when the app quits`).
4. Starting a watch while a scan or another watch is running: refused with `busy` (Task 7).
5. The same app holding many short connections to one CDN address: counted once per destination, timestamps capped at 200, memory bounded (Task 4 `test_caps_pairs_and_timestamps`).

---

## File Structure

| Path | Responsibility | Task |
|---|---|---|
| `modules/network/conn_common/__init__.py` | docstring only (data-only package, skipped by discovery) | 1 |
| `modules/network/conn_common/collect.py` | parsers, per-platform `snapshot()`, `dns_cache()`, expected-service rules | 1 |
| `tests/fixtures/conn/*` | captured output per platform (incl. clean-machine fixtures) | 1 |
| `tests/test_conn_common.py` | parser and snapshot tests | 1 |
| `modules/security/suspicious_connections/__init__.py`, `modules/security/open_ports_scan/__init__.py` | switch to collector, all platforms | 2 |
| `modules/security/network_connections_monitor/__init__.py` | switch to collector, all platforms | 3 |
| `rescue/watch.py` | watch loop, summarising, findings, `WATCH_CODES`, stand-in module | 4 |
| `rescue/cli.py` (`watch` command), `rescue/remediation.py`, `rescue/validate.py` | CLI and code registration | 5 |
| `guides/remediation/read_a_connection_watch.md`, `docs/cli.md`, `docs/commands.md`, `docs/REMEDIATION_CATALOG.md` | walkthrough and regenerated docs | 6 |
| `desktop/engine-runner.js`, `desktop/watch.js`, `desktop/main.js`, `desktop/preload.js`, `desktop/ask-about.js`, `desktop/ai-prompt.js`, `desktop/renderer/ask.js` | spawn, stop, merge, gate, nothing-sent | 7 |
| `desktop/renderer/game/views/watch.js`, `desktop/renderer/game/controller.js`, `desktop/renderer/game/game.css` | the deck instrument | 8 |

---

### Task 1: The shared collector

**Files:**
- Create: `modules/network/conn_common/__init__.py`, `modules/network/conn_common/collect.py`
- Create: `tests/fixtures/conn/` (`lsof_mac.txt`, `nettop_mac.csv`, `ss_tunap_linux.txt`, `ss_tunap_linux_nonroot.txt`, `ss_tni_linux.txt`, `win_tcp.json`, `win_udp.json`, `win_proc.json`, `win_dns.json`, `clean_win_listen.json`, `clean_linux_ss.txt`)
- Test: `tests/test_conn_common.py`

**Interfaces:**
- Produces (in `collect.py`, loaded with `load_content_module("modules/network/conn_common/collect.py", "rescue_conn_common_collect")`):
  - Record: `dict` with keys `proto` (`"tcp"|"udp"`), `state` (str|None, upper-case, e.g. `"ESTABLISHED"`, `"LISTEN"`), `local_addr`, `local_port` (int|None), `remote_addr` (str|None), `remote_port` (int|None), `pid` (int|None), `process` (str|None), `exe` (str|None, full path where known).
  - `parse_lsof(text) -> list[dict]`, `parse_ss(text) -> list[dict]`, `parse_win_connections(tcp_json, udp_json, proc_json) -> list[dict]`
  - `parse_nettop(text) -> dict[int, tuple[int, int]]` (pid → (bytes_in, bytes_out)), `parse_ss_bytes(text) -> dict[tuple, tuple[int, int]]` keyed by `(local_addr, local_port, remote_addr, remote_port)`
  - `parse_win_dns(json_text) -> list[dict]` with keys `name`, `type` (e.g. `"A"`, `"AAAA"`, `"CNAME"`)
  - `snapshot(platform: str, run=command.run) -> dict` = `{"records": [...], "bytes": dict|None, "limits": [str], "error": str|None}`. `limits` are plain sentences (e.g. `"Linux shows which program owns a connection only for your own programs unless the check runs as admin."`, `"Windows doesn't show how much data each connection carried without admin."`). `error` set (and `records` empty) when the connection command failed, timed out or is missing.
  - `dns_cache(platform: str, run=command.run) -> dict` = `{"names": [...]|None, "reason": str|None}`; `names` only on `"win32"`; elsewhere `None` with reason (mac: `"macOS doesn't show which names were looked up unless you're an admin."`; linux: `"Linux shows looked-up names only to admins (resolvectl monitor needs root)."`).
  - `is_expected_listener(platform: str, record: dict) -> bool`: Windows: `pid == 4` or `exe` under `%SystemRoot%\System32` (case-insensitive; default `C:\Windows\System32`), on port in `{135, 139, 445, 5040, 5357}` or `49664 <= port <= 49699`. Linux: `(process, port)` in `{("sshd", 22), ("systemd-resolve", 53), ("cupsd", 631), ("avahi-daemon", 5353), ("chronyd", 123), ("ntpd", 123)}`; port 53 only on `127.0.0.53`/`127.0.0.54`. darwin: always False (the modules keep their own Apple check).

Commands (exact argument lists):
- darwin: `["lsof", "-i", "-n", "-P"]`; bytes `["nettop", "-P", "-L", "1", "-n", "-x", "-J", "bytes_in,bytes_out"]` (nettop prints `name.pid` in the first column).
- linux: `["ss", "-tunapH"]`; bytes `["ss", "-tniH"]`.
- win32: `["powershell", "-NoProfile", "-NonInteractive", "-Command", <script>]` where script emits `Get-NetTCPConnection | Select-Object LocalAddress,LocalPort,RemoteAddress,RemotePort,State,OwningProcess | ConvertTo-Json -Compress`, likewise `Get-NetUDPEndpoint | Select LocalAddress,LocalPort,OwningProcess`, `Get-Process | Select Id,ProcessName,Path`, and DNS `Get-DnsClientCache | Select Entry,Type | ConvertTo-Json -Compress` (Type is numeric: 1→A, 5→CNAME, 28→AAAA, others `str(n)`). PowerShell's `ConvertTo-Json` of one object is an object, not a list: accept both. State is numeric in some Windows versions (2→LISTEN, 5→ESTABLISHED; map the documented `MSFT_NetTCPConnection` values) or a string.

- [ ] **Step 1: Write fixtures and failing tests**

Tests (each asserts on exact record fields from the fixture lines it names):
`test_parse_lsof_ipv4_ipv6_and_listen`, `test_parse_ss_with_and_without_process` (non-root fixture gives `pid None, process None`), `test_parse_win_connections_object_or_list_and_numeric_state`, `test_parse_nettop_name_dot_pid`, `test_parse_ss_bytes`, `test_parse_win_dns_types`, `test_garbage_lines_skipped` (each parser on `"garbage\n\n"` returns empty, never raises), `test_snapshot_uses_numeric_flags` (fake `run` records argv; every argv on darwin contains `-n`), `test_missing_command_is_couldnt_check` (fake `run` returns `error="not found"` → `error` set, `records == []`), `test_linux_nonroot_adds_limit`, `test_windows_bytes_none_with_limit`, `test_dns_cache_mac_and_linux_reason`, `test_expected_listeners_clean_windows` (every LISTEN record in `clean_win_listen.json` is expected), `test_expected_listeners_clean_linux`, `test_unexpected_listener` (`("python3", 8000)` on linux and a `C:\Users\…\app.exe` on 445 on win32 → False).

- [ ] **Step 2: Run them, expect failures**

Run: `.venv/bin/pytest tests/test_conn_common.py -q`
Expected: FAIL (collect.py missing).

- [ ] **Step 3: Implement `collect.py`** to the interfaces above. Parsers are pure; `snapshot` and `dns_cache` take `run` so tests inject output.

- [ ] **Step 4: Run tests, expect pass**, plus `.venv/bin/pytest tests/test_module_code_consistency.py -q` (discovery must still skip the package).

- [ ] **Step 5: Commit** `git commit -m "Network: one connection collector for macOS, Linux and Windows"`

---

### Task 2: suspicious_connections and open_ports_scan on all platforms

**Files:**
- Modify: `modules/security/suspicious_connections/__init__.py`, `modules/security/open_ports_scan/__init__.py`
- Test: `tests/test_module_suspicious_connections.py`, `tests/test_module_open_ports_scan.py`

**Interfaces:**
- Consumes: Task 1 `snapshot`, `is_expected_listener`.
- Produces: `suspicious_connections` exposes `def listening_verdict(self, platform: str, record: dict) -> str` returning `"expected"`, `"unnamed"` or `"flag"`. Task 4 uses it for `new_listener`.

- [ ] **Step 1: Failing tests**: `platforms` include all three; `test_linux_clean_machine_no_warnings` and `test_windows_clean_machine_no_warnings` (module `check()` on the clean fixtures yields no warning/critical); `test_unnamed_listener_is_info` (linux non-root fixture → finding severity info whose description contains "couldn't see which program"); `test_collector_error_is_couldnt_check` (no warnings, one info finding, not an empty result); `test_advice_names_platform_tool` (win32 finding text mentions "Task Manager" or "Resource Monitor", linux mentions "ss", none mentions "Activity Monitor"); existing mac tests still pass with fixtures fed through the collector's `run`.

- [ ] **Step 2: Run, expect failures.** `.venv/bin/pytest tests/test_module_suspicious_connections.py tests/test_module_open_ports_scan.py -q`

- [ ] **Step 3: Implement.** Replace `_run_lsof` + parsing with `snapshot(profile.platform.value)`; keep the Mac `codesign` Apple check (now via `command.run`) for darwin only; add `listening_verdict`; couldn't-check findings reuse an existing info code where one fits, else add `security.<module>.couldnt_check` (declared in `emits_codes`, mapped in an existing walkthrough's `remediates` so validate passes).

- [ ] **Step 4: Run the two test files plus `tests/test_module_code_consistency.py` and `.venv/bin/rescue validate`**; expect pass.

- [ ] **Step 5: Commit** `git commit -m "Connection checks: Linux and Windows, each platform's own services stay quiet"`

---

### Task 3: network_connections_monitor on all platforms

**Files:**
- Modify: `modules/security/network_connections_monitor/__init__.py`
- Test: `tests/test_module_network_connections_monitor.py`

- [ ] **Step 1: Failing tests**: all three platforms; `test_lsof_failure_is_couldnt_check` (today it's an empty clean result); clean Linux/Windows fixtures give no warning/critical; `fix()` text per platform (no `netstat -anp tcp`/Activity Monitor on win32/linux).
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement** with `snapshot()`; thresholds and codes unchanged; `BROWSER_PREFIXES` gain `"msedge.exe"`, `"chrome.exe"`, `"firefox.exe"` matching (compare on the name without `.exe`).
- [ ] **Step 4: Run tests + code consistency**; pass.
- [ ] **Step 5: Commit** `git commit -m "Connections monitor: Linux and Windows; a failed lsof is couldn't-check"`

---

### Task 4: The watch (`rescue/watch.py`)

**Files:**
- Create: `rescue/watch.py`
- Test: `tests/test_watch.py`

**Interfaces:**
- Consumes: Task 1 `snapshot`, `dns_cache`; Task 2 `listening_verdict` (via the discovered `suspicious_connections` module instance).
- Produces:
  - `WATCH_CODES: list[str]` = `["network.connection_watch.watch_summary", "network.connection_watch.regular_checkins", "network.connection_watch.new_listener", "network.connection_watch.upload_heavy", "network.connection_watch.dns_lookups", "network.connection_watch.dns_not_visible", "network.connection_watch.watch_incomplete"]`
  - `MAX_PAIRS = 2000`, `MAX_STAMPS = 200`, `MIN_MINUTES, MAX_MINUTES = 1, 30`, `MIN_INTERVAL, MAX_INTERVAL = 2, 60`
  - `run_watch(platform: str, minutes: int, interval: int, *, collect, dns, clock, sleep, should_stop, on_progress=None, verdict=None) -> CheckResult` (`module_name="connection_watch"`). `collect(platform)` and `dns(platform)` default to Task 1's; `sleep` waits up to the interval but returns early when `should_stop()` is true.
  - `WatchModule`: stand-in with `name = "connection_watch"`, `category = "network"`, `emits_codes = WATCH_CODES`, `platforms` all three, for `checks_to_json`.

Summarising rules (the spec's numbers):
- Pair key: `(process or "unknown", remote_addr, remote_port, proto)`; loopback remotes counted per process (`loopback_count`), not stored as pairs.
- A "new connection" is a pair+local_port not present in the previous snapshot.
- `regular_checkins`: same process to the same non-private remote with ≥ 4 new connections whose gaps vary less than 20% (max |gap − median| / median < 0.2). Confidence 0.5. Description includes "most apps do this to check for updates or messages".
- `upload_heavy`: bytes known and sent > 10 MB (10_000_000) and sent > 3× received over the watch.
- `new_listener`: a LISTEN record absent from the first snapshot; `data.next_checkup` = `verdict(platform, record)`.
- `watch_summary`: one per process, `data.target` = process name, `data.destinations` (sorted by snapshots seen, at most 50 listed, `data.more` count), `data.bytes_in/bytes_out` or null.
- `dns_lookups` (win32): one finding, `data.names` = list of `{name, type, first_seen_snapshot, snapshots}`; description says Windows doesn't record which program asked. `dns_not_visible` elsewhere, with Task 1's reason.
- `watch_incomplete`: whenever any `limits`, `stopped_early`, a cap was hit, or a snapshot errored; `data.reasons` list. Zero snapshots → only this finding (plus `dns_not_visible` where applicable), saying nothing was gathered.
- `CheckResult.data`-level facts go in each finding's `data`: `minutes`, `snapshots`, `stopped_early`.

- [ ] **Step 1: Failing tests** with a fake collector producing scripted snapshots and a fake clock: `test_bounds_refused` (minutes 0/31, interval 1/61 → `ValueError`), `test_summary_per_process_stable_target`, `test_regular_vs_jittery_vs_too_few`, `test_private_destination_never_regular`, `test_upload_heavy_needs_known_bytes`, `test_new_listener_uses_verdict`, `test_caps_pairs_and_timestamps` (3,000 pairs → 2,000 stored, `watch_incomplete` mentions the cap), `test_stop_before_first_snapshot`, `test_stop_midway_keeps_gathered`, `test_dns_windows_and_not_visible_elsewhere`, `test_all_findings_info_and_codes_in_watch_codes`, `test_loopback_counted_not_listed`.
- [ ] **Step 2: Run, expect failures.** `.venv/bin/pytest tests/test_watch.py -q`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run, pass.**
- [ ] **Step 5: Commit** `git commit -m "Connection watch: snapshots over time, summarised per app"`

---

### Task 5: `rescue watch` and code registration

**Files:**
- Modify: `rescue/cli.py`, `rescue/remediation.py:56`, `rescue/validate.py:327`, `rescue/cli.py:1170` (each place that collects `emits_codes` also includes `WATCH_CODES`)
- Test: `tests/test_cli_watch.py`

**Interfaces:**
- Consumes: Task 4.
- Produces: `rescue watch --minutes N --interval S --json --progress`. JSON on stdout = `checks_to_json([(WatchModule(), result)], platform, walkthroughs=...)` (walkthroughs attached like `scan`). With `--progress`, stderr lines `{"progress": {"phase": "watch", "elapsed": <s>, "total": <s>, "snapshots": <n>}}`. A stdin line `stop` (read on a daemon thread; EOF is ignored, not a stop) or SIGINT/SIGTERM sets the stop flag; the document is still printed with `stopped_early: true` in findings' data. Without `--json`, prints a short human summary.

- [ ] **Step 1: Failing tests** (click `CliRunner`, `run_watch` patched to a fast fake): minutes 0 and 31 exit 2 with a message; `--json` output parses and has `modules[0].name == "connection_watch"` and `schema_version`; progress lines parse as JSON; stdin `"stop\n"` ends early (fake loop checks `should_stop`); `rescue remediation-catalog` / validate know every `WATCH_CODES` entry (fails until Task 6 adds the guide — mark that one `xfail(strict=True)` here and remove the mark in Task 6).
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run** `tests/test_cli_watch.py`, `tests/test_module_code_consistency.py`; pass.
- [ ] **Step 5: Commit** `git commit -m "rescue watch: an opt-in, stoppable connection watch"`

---

### Task 6: Walkthrough and docs

**Files:**
- Create: `guides/remediation/read_a_connection_watch.md`
- Modify: `docs/cli.md` (the `watch` command), regenerate `docs/commands.md` (`python scripts/generate_command_catalog.py` as CI does) and `docs/REMEDIATION_CATALOG.md` (`.venv/bin/rescue remediation-catalog`)
- Test: remove Task 5's `xfail`

Guide front matter: `title: "Read a connection watch"`, `estimated_time: ""`, `platforms: [macos, windows, linux]`, `remediates:` all seven `WATCH_CODES`, `steps_for` giving each code a self-contained step list (steps aren't renumbered per code), `automatable_steps: []`, `human_only_steps` = all, `monitoring_risk: false`. Content teaches: what a destination, port and interval tell you; what encryption hides; why apps check in; reading bytes in vs out; why DNS names aren't tied to an app on Windows; that looking up an address is a later step and is a disclosure. Never "kill/end the process". Every claim sourced from the spec or existing walkthroughs.

- [ ] **Step 1: Write guide; run** `.venv/bin/rescue validate --strict`, `tests/test_network_codes.py`, `tests/test_cli_watch.py`; expect pass.
- [ ] **Step 2: Regenerate docs; run the docs freshness tests** (`.venv/bin/pytest tests -q -k "catalog or commands"`).
- [ ] **Step 3: Commit** `git commit -m "Walkthrough: reading a connection watch; docs for rescue watch"`

---

### Task 7: Desktop main process

**Files:**
- Create: `desktop/watch.js`
- Modify: `desktop/engine-runner.js`, `desktop/main.js`, `desktop/preload.js`, `desktop/ask-about.js`, `desktop/ai-prompt.js`, `desktop/renderer/ask.js`, `desktop/mark-policy.js` (export `NEVER_MARKABLE_MODULES` as `MONITORING_MODULES`)
- Test: `desktop/test/watch.test.js`, additions to `desktop/test/ask-about.test.js`, `desktop/test/ai-prompt.test.js`

**Interfaces:**
- Produces:
  - `engine-runner.js`: `runWatch(minutes, onEvent, spawnFn = spawn) -> { promise: Promise<doc>, stop: () => void }`; args `['watch', '--minutes', String(minutes), '--json', '--progress']`; `stop()` writes `"stop\n"` to stdin; timeout = `minutes * 60_000 + 120_000`, after which it writes stop, then kills after 15 s.
  - `watch.js`: `WATCH_MINUTES = [1, 2, 5, 10, 15, 30]`; `handleWatch(minutes, { getLastDoc, setLastDoc, runWatch, policies, isBusy, onEvent }) -> Promise<{ok:true, doc} | {ok:false, reason, message}>`. Reasons: `bad_minutes`, `no_scan` ("Run the checkup first."), `monitoring` (when any finding in the last doc comes from a module in `MONITORING_MODULES`; message: "The connection watch is off while this checkup has found possible monitoring software."), `busy`, `failed`. Merges with `mergeModuleResult` from `recheck.js`; calls `policy.remember(doc)` for each policy.
  - `main.js`: IPC `run-watch` (events forwarded on channel `watch-event`), `stop-watch`; a `busy` flag shared with `run-scan`; on `before-quit`, stop a running watch.
  - `preload.js`: `runWatch(minutes)`, `stopWatch()`, `onWatchEvent(cb)`.
  - `buildAskBody` returns null and `askButtonHtml` returns `''` for codes starting `network.connection_watch.`; `buildAiPrompt` drops those findings and, when it dropped any, adds the line `"[<n> connection-watch item(s) left out: they list the sites this computer talks to.]"`.
  - Test that `desktop/mark-policy.js` `MONITORING_MODULES` and `renderer/game/ledger.js` `MONITORING_MODULES` hold the same names (read ledger.js as text, like the router-link agreement test).

- [ ] **Step 1: Failing tests**: minute allowlist; no_scan; monitoring refusal; busy; merge replaces a previous `connection_watch` entry and keeps other modules; `runWatch` stop writes `stop\n` (fake spawn); timeout path; `stops the watch when the app quits` (main wiring test, as existing main tests do, or a unit on a `stopActiveWatch()` helper); Ask/Copy exclusions; list agreement.
- [ ] **Step 2: Run** `cd desktop && npm test`; expect the new tests to fail.
- [ ] **Step 3: Implement.**
- [ ] **Step 4: `npm test`** all pass.
- [ ] **Step 5: Commit** `git commit -m "Desktop: run and stop a connection watch, merged into the checkup; nothing from it is sent"`

---

### Task 8: The WATCH CONNECTIONS instrument

**Files:**
- Create: `desktop/renderer/game/views/watch.js`
- Modify: `desktop/renderer/game/controller.js` (a few lines: render the instrument into the deck's `instrumentsHtml`, handle its actions, subscribe to `onWatchEvent`), `desktop/renderer/game/game.css`, `desktop/MANUAL-QA.md` (a step for the watch)
- Test: `desktop/test/game-watch-view.test.js`, additions to `desktop/test/game-controller.test.js`

**Interfaces:**
- Consumes: Task 7 preload API.
- Produces: `renderWatch({ state, minutes, elapsed, total, snapshots, message }) -> string` (pure), `state` ∈ `"idle" | "running" | "done" | "refused" | "failed"`. Actions `data-act="watch-start"`, `data-act="watch-stop"`, `data-act="watch-minutes:<n>"`.

Copy (exact):
- Heading: `WATCH CONNECTIONS`
- Idle sentence: `Watches which apps on this computer connect where, for {N} minutes. Nothing leaves this computer, and you can keep using it while the watch runs. Results last until your next checkup.`
- Running: `Watching… {m} of {N} minutes, {k} snapshots.` plus a `STOP` button (stopping keeps what was gathered).
- Done: `Watch finished. What it saw is in INCOMING SIGNALS.`
- Refused/failed: the `message` from Task 7.
- Minute picker shows exactly `[1, 2, 5, 10, 15, 30]`, default 5.
- No instrument before a checkup has finished; none while the game is withdrawn by the monitoring gate.

- [ ] **Step 1: Failing tests**: each state's HTML contains its copy, escapes `message`, has a text progress line (no graph-only state), picker values; controller: start sends only the minutes, stop calls `stopWatch`, a returned doc goes through the same path as a re-check result (findings reach INCOMING SIGNALS), no points awarded for watch findings, instrument absent before a scan and when withdrawn.
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement.**
- [ ] **Step 4: `npm test`** all pass.
- [ ] **Step 5: Commit** `git commit -m "Game: a WATCH CONNECTIONS instrument on the deck"`

---

## After all tasks

Full suites: `.venv-with-ruff`/`uv run ruff check .`, `.venv/bin/pytest -q`, `.venv/bin/rescue validate --strict`, `cd desktop && npm test`. Editing `rescue/*.py` needs the integrity manifest regenerated: `uv run python scripts/generate_integrity_manifest.py`, committed with the change (Tasks 4 and 5, and any later task touching `rescue/`). Local pytest does not catch a stale manifest; CI does. Rebuild `desktop/engine/rescue` locally (PyInstaller, as in `release.yml`) so the dev app has `rescue watch`.
