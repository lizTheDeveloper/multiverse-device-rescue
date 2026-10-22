# AI agent audit: HackMyAgent's shadow-AI detect, fetched automatically

Owner's request (2026-10-21): "https://github.com/opena2a-org/hackmyagent can
you also add this", then, asked whether to use it only when installed or to
fetch it: **"fetch it automatically"**. Calls marked **(my call)** are mine.

## What it adds

HackMyAgent (OpenA2A, Apache-2.0) has a `detect` command that inventories the
AI tools on a machine (Claude Code, Cursor, Copilot, Claude Desktop, LM
Studio…), the MCP servers they are wired to, AI config files holding
credentials or broad permissions, and governance files. Reclaim City today only
matches MCP servers against a known-bad list (`ai_worm_iocs`). On the owner's
Mac, `detect` found a real credential in `~/.claude/settings.json`, a database
MCP server, and 16 MCP servers across three tools.

## What runs, exactly

- A new module `ai_agent_audit` (category security) runs
  `node <install>/node_modules/hackmyagent/dist/cli.js detect <home> --json --depth 0`.
  **(my call)** `--depth 0`: the machine-wide inventory (running assistants,
  machine-wide MCP and AI configs) in about a second; the default 4-level walk
  of a home folder took 268 s on the owner's Mac and added only per-project
  rows. The finding text says how to check one project folder.
- Only `detect`. Never `secure --fix`, `rollback`, `attack`, `red-team`,
  `--deep`, `--nanomind`, `--contribute`, `--publish`, `init-mcp`. A test
  asserts the argv.
- Environment: `OPENA2A_TELEMETRY=off` (its usage reporting is on by default)
  and `OPENA2A_HOME=<a fresh temp dir, deleted afterwards>` so it writes
  nothing into the person's home folder (verified: without it, it creates
  `~/.opena2a/config.json`). **(my call)**
- Bounded with `rescue.command.run`: 60 s timeout, output cap.
- Exit codes: 0 and 1 are measured (1 = it found critical/high); 2 = not
  measured → couldn't-check; 3 = its own integrity check failed → couldn't-check
  with that reason; anything else or unparseable JSON → couldn't-check.

## Fetching it

**The owner's decision: fetch automatically.** **(my call, how):** not `npx`,
which resolves floating dependency ranges at run time. Instead:

- The repo vendors `vendor/hackmyagent/package.json` and
  `package-lock.json` pinning `hackmyagent@0.33.2` (published 2026-09-18) and
  every transitive dependency with its integrity hash, plus an override that
  replaces `onnxruntime-node` with a 2-file local stub (`stub/`). That drops
  the fetch from ~490 MB to ~51 MB; `detect` does not use the AI runtime
  (verified: identical output). The stub throws if anything loads it.
- First run: `npm ci --ignore-scripts --no-audit --no-fund
  --registry=https://registry.npmjs.org/` in a temp dir next to the install
  dir, then an atomic rename to the install dir
  (`<user cache>/ReclaimCity/hackmyagent-0.33.2`; macOS `~/Library/Caches`,
  Linux `$XDG_CACHE_HOME` or `~/.cache`, Windows `%LOCALAPPDATA%`). Later runs
  reuse it after checking the installed `hackmyagent/package.json` says
  0.33.2. `--ignore-scripts` means no package's install script runs.
- npm's own cache is pointed at a temp dir (`--cache`) that is deleted
  afterwards, so nothing lands in `~/.npm`.
- 180 s timeout for the fetch. A failed or partial fetch leaves no install dir
  (the temp dir is removed) and is couldn't-check, never an error.
- Needs Node.js 18+ and npm. Found on `PATH`, then in the usual places a
  desktop app's PATH misses (`/opt/homebrew/bin`, `/usr/local/bin`,
  `~/.local/bin`, `~/.volta/bin`, the newest `~/.nvm/versions/node/*/bin`;
  Windows `%ProgramFiles%\nodejs`). Missing → couldn't-check: "needs Node.js",
  with where to get it. **(my call)** We never install Node.
- Off switch: `rescue scan --no-downloads` (and env `RESCUE_NO_DOWNLOADS=1`)
  → the module reports couldn't-check "turned off" without touching the
  network. An already-fetched copy still runs (no network).

## Findings

Codes `security.ai_agent_audit.*`:

| Code | When | Severity |
|---|---|---|
| `credentials_in_ai_config` | `aiConfigs[]` with risk critical, or a finding of category `config` about credentials | warning |
| `risky_mcp_server` | an MCP server with risk high or critical (e.g. database, filesystem `/`) | warning |
| `ai_inventory` | one info note: the AI tools found (running/installed) and their MCP servers by tool | info |
| `could_not_check` | Node missing, fetch failed/off, timeout, exit 2/3, bad JSON | info, `supported` stays true, data.reason |

**(my call)** HackMyAgent's governance findings ("agents without governance",
"SOUL.md", identity status) are dropped: they grade against OpenA2A's own
governance model and mean nothing to a person checking their computer. Its
`remediation` lines name OpenA2A products (`opena2a protect`); they are not
copied. Each finding gets plain-English text and a walkthrough in
`guides/remediation/`. Evidence: file path and line, the variable *name*
(e.g. `PIXELLAB_API_KEY`), never the value; HackMyAgent already masks values
and we never read the file ourselves. Paths are home-relative (`~/…`).

## Where it runs

- Default `rescue scan` (that is what "automatically" means) and the
  `ai_worm_response` profile. Platforms: darwin, linux, win32.
- **check() stays light** (memory: heavy scans froze the Mac): detect is ~1 s
  and ~100 MB; the fetch is network-bound with a timeout; neither is a
  forensic scan.

## Docs

`docs/privacy.md` (short version and "What leaves the machine" gain the fetch
from registry.npmjs.org: what is sent is a normal package download; the
registry sees the computer's IP; nothing about the computer is sent; it is
turned off with `--no-downloads`), `docs/trust-and-safety.md`,
`docs/commands.md` (node/npm commands), `docs/cli.md` (`--no-downloads`),
`THIRD_PARTY` / credits (Apache-2.0 notice). Desktop: no new UI in this part
**(my call)**; findings reach the city through the existing scan path.

## Non-goals

- `secure`, `attack` or any other HackMyAgent command; per-project walks.
- Installing Node.js; bundling HackMyAgent in the app.
- Updating the pinned version automatically (a new version is a reviewed
  change to the lockfile).

## Testing

Engine, with node/npm faked by injected runners: argv and env exactly as
above; fetch path (temp dir, rename, cleanup on failure, version check,
`--ignore-scripts`, registry, cache dir); Node discovery; every exit code;
parsing a saved real `detect --json` (owner's Mac, values already masked,
paths rewritten to a fake home) into the four codes; governance dropped;
`--no-downloads`; nothing written to home. One opt-in live test
(`RESCUE_LIVE_HMA=1`) does the real fetch and run. CI release smoke is not
extended (runners differ in Node).
