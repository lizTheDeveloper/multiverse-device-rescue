# N3: Level 1 network scans (this computer)

Piece N3 of the network analysis track. Parent spec:
`2026-10-18-network-analysis-training-design.md` (read its bright lines,
non-goals and anti-goals first; they bind here). Written from the parent spec
at the owner's request, without a separate question round, so every call
below not quoted from the parent is marked **(my call)**.

## Intent

Level 1 is "this computer": its connections and which app made them, its
listening ports, its DNS lookups, bytes in and out, and timing. Today the
engine sees a single moment of that, on a Mac only
(`suspicious_connections`, `network_connections_monitor`, `open_ports_scan`
are all `platforms = [Platform.DARWIN]`). A single moment can't show the
things the skill ladder teaches next: what an app talks to over time, how
often it checks in, how much it sends. N3 gives the scanner that view so the
later pieces (N4 dossier, N7 drills, N8 case files) have the person's own
traffic to work on.

## Goals

1. **Connection snapshots on all three platforms.** One shared collector
   returns the same record shape on macOS, Linux and Windows. The three
   existing connection/port checks use it and run on all three.
2. **Connection watch.** An opt-in, time-bounded, cancellable command that
   takes repeated snapshots and summarises, per app: where it connected, how
   many times, how regularly, and how much data where the OS says.
3. **DNS lookup observation**, where this computer lets an ordinary user see
   it, and an honest "couldn't see" everywhere else.
4. **Into the game.** Watch results arrive in the command center like any
   other scan result (INCOMING SIGNALS), so the existing monitoring gate,
   tags and ledger rules apply without new paths.

## Non-goals

- Packet capture or anything that needs admin/root (N10 covers the person's
  own captures). No `sudo`, no elevation prompts, no drivers.
- Other devices' traffic (that's level 2/3, N5/N6). Level 1 is only this
  computer's own sockets.
- Looking anything up about an address (reverse DNS, WHOIS, reputation). That
  is N4, per item, on the person's click. N3 sends nothing anywhere: every
  command runs with numeric output (`-n`) so the scan itself makes no lookups.
- Lessons and drills about the watch (N7), case files (N8).
- Judging traffic "bad". Level 1 shows patterns; the person learns to read
  them. Severity stays where the existing checks already put it.

## Anti-goals

- **A watch that runs by itself.** Never part of `rescue scan`, any profile,
  or `check()`. Only the explicit watch command starts it (memory: heavy work
  in `check()` froze a Mac).
- **A watch that can't be stopped or grows without bound.** Hard cap on
  duration and on stored records; stopping early keeps what was gathered.
- **Scaring people with normal traffic.** Apps poll constantly. A regular
  check-in is shown as a pattern to look at, never as "malware found".
- **Reading anyone else's traffic.** See non-goals.

## Constraints

- Read-only (AGENTS.md rule 1). External commands only through
  `rescue.command.run` (mandatory timeout, bounded output), numeric flags so
  nothing resolves names.
- "Couldn't run" ≠ "clean" (rule 3): every platform gap is a reported
  couldn't-check finding or `supported: false`, never silence.
- External commands go through `rescue.command.run`; the three existing
  checks call `subprocess.run` directly today and move over as part of N3.
- Finding codes `<category>.<module>.<slug>`, literal at the `Finding(...)`
  call, declared in `emits_codes`; `tests/test_module_code_consistency.py`
  enforces it. Existing codes keep their names.
- No time estimates in docs (owner's rule).
- Exports stay redacted (`rescue export`); destinations are the person's own
  browsing, so the watch's output is treated as sensitive in any export
  path (parent anti-goal "leaking the person's life").

## Design

### 1. The shared collector (`modules/network/conn_common`)

**(my call)** A helper package next to `lan_common`, loaded the same way.
One function per platform, one record shape:

```
{ "proto": "tcp"|"udp", "state": "ESTABLISHED"|"LISTEN"|…|None,
  "local_addr", "local_port", "remote_addr", "remote_port",
  "pid": int|None, "process": str|None }
```

| Platform | Connections | Process names | Bytes |
|---|---|---|---|
| macOS | `lsof -i -n -P` (as today) | yes, all processes the user can see | `nettop -P -L 1 -n -J bytes_in,bytes_out` per process |
| Linux | `ss -tunap` | own processes only without root; others `process: None` | `ss -tni` counters (`bytes_acked`, `bytes_received`) for own sockets |
| Windows | PowerShell `Get-NetTCPConnection` + `Get-NetUDPEndpoint`, PID → name via `Get-Process` | yes | not exposed per connection without admin: `None` |

Where a column isn't available the record says `None` and the result says
why, in one sentence the finding can quote ("Linux shows which program owns
a connection only for your own programs unless the check runs as admin").
Parsers are pure functions over captured text, tested on fixtures from each
platform.

### 2. Existing checks on all platforms

`suspicious_connections`, `network_connections_monitor` and `open_ports_scan`
switch to the collector and add `Platform.LINUX` and `Platform.WIN32`. Their
codes and wording stay. Two behaviours change:

- **Couldn't run is reported.** `network_connections_monitor` returns a clean,
  empty result today when `lsof` fails. With the collector, any platform whose
  command fails or is missing gives a couldn't-check finding (rule 3).
- **Each platform's own services don't raise warnings (my call).** The Mac
  path keeps its existing Apple path-and-signature check. Windows: a listener
  owned by PID 4 (System) or an executable under `%SystemRoot%\System32`, on
  a port in a fixed list (135, 139, 445, 5040, 5357, and 49664–49699, the RPC
  dynamic range), is expected, not flagged. No signature checking on Windows
  in N3. Linux: a fixed list (`sshd` 22, `systemd-resolved` 53 on
  127.0.0.53/54, `cupsd` 631, `avahi-daemon` 5353, `chronyd`/`ntpd` 123), and
  a listener whose owner the collector couldn't name is info ("couldn't see
  which program owns this without admin"), never a warning. A test runs each
  platform's fixture of a clean, freshly installed machine and expects no
  warnings.
Wording that names a Mac tool in its advice ("Activity Monitor", `lsof`)
gets a per-platform equivalent (Task Manager / Resource Monitor; System
Monitor / `ss`). **(my call)** A listening-port finding for a process the
collector couldn't name (Linux, someone else's process) says so instead of
guessing.

### 3. Connection watch (`rescue watch`)

**(my call)** A new CLI command, not a module, because a module's `check()`
must stay cheap and the orchestrator abandons it at 60 s:

```
rescue watch --minutes N [--interval S] --json [--progress]
```

- **Bounds.** `--minutes` 1–30, default 5. `--interval` 2–60 s, default 5.
  At most 2,000 distinct (process, destination) pairs and 200 timestamps per
  pair; beyond that it keeps counting but stops storing, and says so.
- **Stop.** The line `stop` on stdin (my call: works the same on Windows,
  where Node's `kill('SIGINT')` ends the process outright), or Ctrl-C/SIGTERM
  in a terminal, ends it early and still prints the result for what was
  gathered, marked `"stopped_early": true`.
- **Progress.** With `--progress`, one `{"progress": {"phase": "watch",
  "elapsed": s, "total": s, "snapshots": n}}` line per snapshot on stderr,
  in the same style as `scan --progress`.
- **Output.** One JSON document in the same shape as `rescue scan --json`
  (`schema_version`, `platform`, `modules: [...]`) with one module entry,
  `connection_watch`. The serializer (`checks_to_json`) expects a module
  object per result, so the watch passes a small stand-in carrying the name,
  category and `emits_codes`.
- **What it summarises, per process:** distinct remote destinations
  (address, port, protocol), how many snapshots each was seen in, first and
  last seen, new-connection timing (median gap and how regular it is), bytes
  in/out over the watch where the platform exposes them, listening ports that
  opened or closed during the watch. Loopback is counted, not listed.
- **Findings** (codes `network.connection_watch.*`, **(my call)**):
  - `watch_summary` (info): per process, its destinations and volume. The
    raw material for later lessons. One finding per process, `data.target`
    = process name, so cards are stable.
  - `regular_checkins` (info, confidence ≤ 0.5): a process opening new
    connections to the same non-private destination at a steady interval
    (at least 4 occurrences, gaps varying less than 20%). Worded as "a
    pattern worth knowing about: most apps do this to check for updates or
    messages". Never warning on its own.
  - `new_listener` (info): a port that started listening during the watch.
    Uses `suspicious_connections`' listening-port rules (including the
    per-platform expected services above) to say whether the next checkup
    would flag it, but stays info: the watch produces no missions (see 5).
  - `upload_heavy` (info): a process that sent noticeably more than it
    received (sent > 10 MB and > 3× received) where bytes are known. Info,
    because backups and video calls do this.
  - `watch_incomplete` (info, couldn't-check): which columns this platform
    couldn't see (bytes on Windows; other users' process names on Linux;
    stopped early; record cap hit).
- **Walkthrough.** One remediation guide, `read_a_connection_watch.md`,
  that teaches reading the summary (what a destination, port and interval
  tell you, what encryption hides) and points to the N4 dossier when it
  exists. It never tells anyone to kill a process.

### 4. DNS lookup observation

What an ordinary user can see, honestly:

| Platform | Source | Result |
|---|---|---|
| Windows | `Get-DnsClientCache` (no admin) | names looked up recently, with record type; polled during a watch, so lookups are timestamped to the snapshot that first saw them |
| macOS | none without admin: the unified log shows an ordinary user no lookup names (checked on macOS 26: `log show` for mDNSResponder returned nothing readable) | couldn't-check finding that says so and points to level 3 (DNS filter export, N6) |
| Linux | `resolvectl` monitor needs root; only counts without it | couldn't-check, same pointer |

**(my call)** Only inside a watch, never in the default scan or the plain
route: on Windows a `dns_lookups` info finding (per name: first seen, how many
snapshots, record type); on macOS and Linux a `dns_not_visible` couldn't-check
finding with the reason above.
Lookups aren't tied to an app: Windows doesn't record which program asked,
and the finding says that, because it's a real limit an analyst works around
by lining up times with the connection list.

### 5. Desktop and game

- **Main process.** `runWatch(minutes, onEvent)` in `engine-runner.js`
  spawns `rescue watch --minutes N --json --progress`; IPC `run-watch`
  (minutes validated against an allowlist `[1, 2, 5, 10, 15, 30]` in main),
  `stop-watch` writes `stop` to its stdin. One watch at a time. A new
  `handleWatch` (the re-check handler refuses modules that weren't in the
  last scan) merges the result into the last scan with `mergeModuleResult`.
  A watch needs a scan to merge into: no scan, no watch (`no_scan`).
- **Monitoring gate (my call).** Main refuses `run-watch` when the last scan
  has any finding from a monitoring module, using the same list the game's
  ledger uses (moved to a file both can load), not only the renderer hiding
  the instrument.
- **No missions, nothing kept (my call).** Every watch finding is info, so
  none becomes a mission, nothing is scored, and nothing about it reaches the
  progress store. A second watch replaces the first (merge by module name).
  A new full scan replaces the document, and the watch's results go with it;
  the instrument says "results last until your next checkup".
- **Nothing sent (my call).** "Ask about this" and "Copy for any AI" are not
  offered on `connection_watch` findings: their redaction strips private
  addresses but not public ones or domain names, and these findings are the
  person's own browsing. Network-aware redaction is N9's job; the buttons
  come back then.
- **Game.** **(my call)** A WATCH CONNECTIONS instrument on the deck:
  duration picker, a progress line from the progress events, a STOP button,
  and a sentence saying what it does ("watches which apps on this computer
  connect where, for N minutes; nothing leaves this computer; you can keep
  using the computer while it runs"). Results arrive as INCOMING SIGNALS
  through the existing deck reconcile. The instrument lives in its own view
  module so it doesn't collide with the player-profile work on the
  controller; its controller hook is a few lines.
- **Plain route.** **(my call)** Not offered there (parent: everything here
  lives in game mode).

## Testing

- Parser tests per platform on captured fixtures (including empty output,
  permission-limited output, IPv6, and garbage lines).
- Watch tests with a fake collector and fake clock: bounds, record cap,
  stop-early output, regular-check-in detection (steady vs jittery vs too
  few), upload ratio with unknown bytes, listener opened mid-watch.
- CLI test: `rescue watch --minutes 0` and `31` refused; `--json` document
  validates against the scan schema; SIGINT path prints a document.
- Code-consistency and remediation-catalog tests cover the new codes;
  `docs/commands.md` regenerated (new commands: `ss`, `nettop`, PowerShell
  cmdlets).
- Clean-machine fixtures for each platform produce no warnings from the
  three existing checks.
- Desktop: IPC allowlist, merge into the last scan, stop via stdin, refusal
  under the monitoring gate, no Ask/Copy buttons on watch findings, the
  instrument's HTML (pure) and its text equivalents.

## Left to the builder

Exact parser regexes, the PowerShell output format (prefer
`ConvertTo-Json`), file layout inside `conn_common`, the deck instrument's
styling, and how the progress line words elapsed time.
