# N4 first part: who's on the other end — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** After a connection watch, look up who runs each public destination automatically (reverse DNS, RIPEstat, RDAP), and show the watch in the game as one signal whose WHERE THEY WENT clue lists each app's destinations and owners.

**Architecture:** A stdlib-only `rescue/whois.py` does bounded, injected-network lookups; `rescue/watch.py` attaches results to each destination and `rescue watch` gains `--no-lookups`. The desktop passes a boolean lookups flag to main, groups `connection_watch` notes into one signal in `signals.js`, and renders the clue in `clues.js`.

**Tech Stack:** Python 3.12 stdlib (urllib, ssl, socket, concurrent.futures), pytest; Electron main (CommonJS), game ES modules, `node --test`.

**Spec:** `docs/superpowers/specs/2026-10-19-n4-who-is-on-the-other-end-design.md` (parent: `docs/superpowers/specs/2026-10-18-network-analysis-training-design.md`, N3: `docs/superpowers/specs/2026-10-18-n3-level-1-network-scans-design.md`)

## Global Constraints

- Only public addresses are looked up: never private (RFC1918, ULA), loopback, link-local, multicast, CGNAT 100.64/10, unspecified or reserved. Reuse `rescue/watch.py`'s `_is_public`.
- Services: reverse DNS via `socket.gethostbyaddr` (system resolver); `https://stat.ripe.net/data/prefix-overview/data.json?resource=<ip>&sourceapp=reclaim-city`; `https://rdap.org/ip/<ip>` (follows redirects to the registry).
- `User-Agent: ReclaimCity/<rescue.__version__>` on every HTTPS request.
- Bounds: at most 150 distinct addresses per watch (busiest first), 6 concurrent, 4 s per request, 60 s total for the lookup step.
- Nothing about destinations or lookups is written to disk (no cache file). In-memory for one run only.
- A lookup failure is couldn't-check for that field, never an error for the watch; `watch_incomplete` names failures, skips and "turned off".
- Registry and DNS text is untrusted: cap each string at 200 chars, strip control characters in the engine; escape everything in the renderer.
- Engine changes: regenerate `rescue/security/integrity_manifest.json` (`uv run python scripts/generate_integrity_manifest.py`) in the same commit.
- Product name in shipped copy is "Reclaim City" (`tests/test_product_name.py`); the CLI's own help keeps "Device Rescue".
- No time estimates in docs or copy. Never tell anyone to kill a process.
- Plain view is not changed (owner: it may be dropped).

## Review Focus

1. Offline computer: every lookup fails fast and the watch still returns, with `watch_incomplete` saying lookups couldn't run (Task 1 `test_offline_marks_every_field_couldnt_check`, Task 2 `test_watch_offline_lookups_still_returns`).
2. A registry answers with something hostile or huge (HTML error page, 5 MB body, `<script>` in a name): bounded read (64 KB), parsed as JSON or rejected, strings capped and escaped (Task 1 `test_hostile_bodies`, Task 3 `test_clue_escapes_registry_text`).
3. The frozen app can't verify TLS (empty CA path): couldn't-check, not a crash (Task 1 `test_tls_failure_is_couldnt_check`; release smoke step in Task 2).
4. Lookups turned off: no network call at all (Task 1 `test_no_calls_when_disabled`, Task 2 `test_no_lookups_flag`).
5. 1,000 destinations: only 150 looked up, total time bounded by the budget (Task 1 `test_limit_and_budget`).

---

### Task 1: `rescue/whois.py`

**Files:**
- Create: `rescue/whois.py`, `tests/test_whois.py`, `tests/fixtures/whois/` (`ripe_8.8.8.8.json`, `rdap_8.8.8.8.json`, `ripe_ripe_region.json`, `rdap_ripe_region.json`, `rdap_apnic.json`, `rdap_404.txt`, `garbage.html`) — capture real responses with curl (any public addresses of large providers; no personal data)

**Interfaces:**
- Produces:
  - `MAX_ADDRESSES = 150`, `WORKERS = 6`, `TIMEOUT = 4.0`, `BUDGET = 60.0`, `MAX_BODY = 65536`
  - `SOURCES = ["reverse DNS (your computer's own resolver)", "RIPE NCC (stat.ripe.net)", "rdap.org (the internet registries)"]`
  - `is_lookupable(ip: str) -> bool`
  - `parse_ripe(body: bytes) -> dict` → `{"asn": int|None, "as_name": str|None, "prefix": str|None}`
  - `parse_rdap(body: bytes) -> dict` → `{"network": str|None, "registrant": str|None, "country": str|None}` (registrant = first entity with role `registrant`, else `administrative`, vcard `fn`)
  - `default_fetch(url: str, timeout: float) -> bytes` (urllib, User-Agent, redirects followed, reads at most MAX_BODY+1 and raises if more, SSL context from `ssl_context()`)
  - `ssl_context() -> ssl.SSLContext`: darwin → system roots from `security find-certificate -a -p /System/Library/Keychains/SystemRootCertificates.keychain` via `rescue.command.run` as `cadata` (fall back to default context if that fails); elsewhere `ssl.create_default_context()`
  - `look_up(ip, *, fetch, resolve, timeout) -> dict` → `{"hostname", "asn", "as_name", "prefix", "network", "registrant", "country", "unavailable": [field-group names that failed]}`
  - `look_up_all(ips: list[str], *, fetch=default_fetch, resolve=socket.gethostbyaddr, limit=MAX_ADDRESSES, workers=WORKERS, timeout=TIMEOUT, budget=BUDGET, clock=time.monotonic) -> {"results": {ip: dict}, "skipped": int, "failed": int, "over_budget": bool}`; input order = priority; non-lookupable ips dropped silently; strings capped at 200 and control chars stripped.

- [ ] **Step 1: Failing tests** in `tests/test_whois.py`: `test_lookupable_ranges` (8.8.8.8 yes; 10.x, 172.16.x, 192.168.x, 127.0.0.1, 169.254.x, 100.64.x, 224.0.0.251, ::1, fe80::1, fc00::1, 0.0.0.0, 240.0.0.1 no; 2001:4860:4860::8888 yes), `test_parse_real_ripe_and_rdap` (8.8.8.8 → asn 15169, as_name contains "Google", registrant "Google LLC", network "GOGL"), `test_parse_ripe_region_and_apnic`, `test_rdap_404_and_garbage` (→ all None, no raise), `test_hostile_bodies` (oversized raises in fetch; `<script>` and control chars capped/stripped; 10 KB name capped at 200), `test_offline_marks_every_field_couldnt_check` (fetch/resolve raise OSError → `unavailable` lists dns, owner, registry; no raise), `test_tls_failure_is_couldnt_check` (fetch raises ssl.SSLError), `test_limit_and_budget` (1,000 ips, fake slow fetch, fake clock → ≤150 attempted, over_budget True, returns), `test_no_calls_when_disabled` (look_up_all with [] → no fetch calls), `test_user_agent_and_sourceapp` (default_fetch with a stub opener records headers; ripe URL has `sourceapp=reclaim-city`), `test_nothing_written_to_disk` (run look_up_all with fakes inside tmp cwd; no files created).
- [ ] **Step 2: Run, expect failures.** `.venv/bin/pytest tests/test_whois.py -q`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: Run; pass. Ruff. Regenerate integrity manifest.**
- [ ] **Step 5: Commit** `git commit -m "whois: look up who runs a public address (reverse DNS, RIPEstat, RDAP), bounded and offline-safe"`

---

### Task 2: Lookups in the watch, CLI and docs

**Files:**
- Modify: `rescue/watch.py`, `rescue/cli.py` (`watch` command), `guides/remediation/read_a_connection_watch.md`, `docs/cli.md`, `scripts/generate_command_catalog.py` (list the watch's network use) + regenerated `docs/commands.md`, `docs/REMEDIATION_CATALOG.md`, `.github/workflows/release.yml` (smoke: frozen engine fetches one RDAP record)
- Test: `tests/test_watch.py`, `tests/test_cli_watch.py`

**Interfaces:**
- Consumes: Task 1 `look_up_all`, `SOURCES`.
- Produces: `run_watch(..., lookups=None)` where `lookups` is a callable `(ips) -> look_up_all result` or None (= off). Each destination in `watch_summary` `data.destinations[]` gains `"who": {...}` (Task 1's dict) or `"who": null` when not looked up. `watch_summary` gains `data.lookup_sources` (= `SOURCES` when on, `[]` when off) and its description names the top owners: `"Mostly <owner1> and <owner2>."` where owner = registrant, else as_name, else hostname. `watch_incomplete` reasons gain: `"Looking up who runs each address was turned off."`, `"Couldn't look up <n> address(es) (offline or the service didn't answer)."`, `"Only the busiest 150 addresses were looked up."`, `"Looking up stopped after 60 seconds."`. CLI: `rescue watch --no-lookups`; default on. New `rescue lookup <ip>...` prints `{ip: who}` JSON for lookupable addresses (refuses others with a message), documented in docs/cli.md. Destination order for lookups = most snapshots seen first.

- [ ] **Step 1: Failing tests:** `test_watch_attaches_who` (fake lookups → destinations carry who; description says "Mostly Google LLC"), `test_no_lookups_flag` (CLI `--no-lookups` → run_watch gets lookups=None, lookup_sources [], incomplete says turned off), `test_watch_offline_lookups_still_returns`, `test_lookups_only_public_destinations`, `test_lookups_run_after_snapshots_and_count_toward_nothing_on_disk`.
- [ ] **Step 2: Run, expect failures.**
- [ ] **Step 3: Implement.** Walkthrough: a self-contained step (in each code view that needs it) explaining what the owner names mean (hosting/cloud companies run most of the internet; an owner name is who runs the address, not necessarily the app's maker), that lookups sent the addresses (not contents) to the named services, and how to turn them off. Release smoke step (bash, all OS): `dist/<engine> lookup 8.8.8.8` prints JSON containing `"asn": 15169` (proves the frozen engine can make HTTPS requests).
- [ ] **Step 4: Run tests, ruff, validate, regenerate manifest + docs.**
- [ ] **Step 5: Commit** `git commit -m "Connection watch: who runs each address, looked up automatically; --no-lookups"`

---

### Task 3: Desktop — the switch, one watch signal, WHERE THEY WENT

**Files:**
- Modify: `desktop/engine-runner.js` (`runWatch(minutes, onEvent, spawnFn, {lookups})` adds `--no-lookups` when false), `desktop/watch.js` (`handleWatch(minutes, opts)` validates `lookups` as boolean, default true), `desktop/main.js` + `desktop/preload.js` (`runWatch(minutes, lookups)`), `desktop/renderer/game/views/watch.js` (checkbox + copy), `desktop/renderer/game/controller.js` (pass the checkbox state; minimal lines), `desktop/renderer/game/signals.js` (group), `desktop/renderer/game/clues.js` (WHERE THEY WENT clue), `desktop/renderer/game/views/signal.js` if the clue needs a list layout, `desktop/MANUAL-QA.md`
- Test: `desktop/test/watch.test.js`, `desktop/test/game-watch-view.test.js`, `desktop/test/game-signals*.test.js` (whichever covers buildSignals), `desktop/test/game-clues*.test.js`

**Interfaces:**
- Consumes: Task 2 JSON (`data.destinations[].who`, `data.lookup_sources`, per-app `watch_summary`, `dns_lookups`, `watch_incomplete`).
- Produces:
  - Grouping: in `buildSignals`, all notes with `module === 'connection_watch'` become ONE signal: `id: 'connection_watch|group'`, `kind: 'real'`, `severity: 'info'`, `title: 'Connection watch: <A> app(s) talked to <P> place(s)'`, `finding: { module: 'connection_watch', code: 'network.connection_watch.group', watch: [the notes] }`, `fp` from the notes' fingerprints joined. `isWatchKey` must still be true for this id.
  - `cluesFor(finding)` for that grouped finding returns one clue `{kind: 'where', label: 'WHERE THEY WENT', lines, reading}`: line 1 rollup `"Talked to: Apple Inc. (9 apps), Google LLC (4), Cloudflare, Inc. (3)"` (top 5 owners by distinct apps); then per app (busiest first, max 25 apps): `"<app>: <owner or hostname or address> (<address>:<port>), …"` (max 8 destinations per app, then "and N more"); then any `watch_incomplete` reasons; then `"Looked up with: <sources>"` or `"Not looked up (turned off)."`. reading: `'Who runs an address is usually a hosting or cloud company, not the app’s maker. Lookups sent the addresses, not what was in them.'`
  - Watch view: checkbox `data-act="watch-lookups"`, label exactly: `Look up who runs each address (sends the addresses, not what was in them, to RIPE NCC and rdap.org)`; idle sentence when on: `Watches which apps on this computer connect where, for {N}, then looks up who runs each address. You can keep using the computer while the watch runs. Results last until your next checkup.`; when off, the N3 sentence (with "Nothing leaves this computer").
- [ ] **Step 1: Failing tests** for each Produces bullet; escaping test `test_clue_escapes_registry_text` (a registrant `<img src=x onerror=alert(1)>` renders escaped in the signal view); IPC: non-boolean lookups refused (`bad_lookups`) or treated as true — choose refuse; `--no-lookups` only when false.
- [ ] **Step 2: Run, expect failures.** `cd desktop && npm test`
- [ ] **Step 3: Implement.**
- [ ] **Step 4: `npm test` all pass.**
- [ ] **Step 5: Commit** `git commit -m "Game: one connection-watch signal, WHERE THEY WENT with who runs each address; lookups switch"`
