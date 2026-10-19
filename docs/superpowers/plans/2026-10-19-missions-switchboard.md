# The Switchboard (network lines) mini-game Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One mini-game module for the `switchboard` type: every network finding becomes a traced line
(this computer → port / process / service → where it goes), and the person decides **Expected** /
**Odd — close it** / **Look closer** for each one. It teaches itself with a three-item practice round.

**Architecture:** A pure ES module, `desktop/renderer/missions/games/switchboard.js`, default export per the
mini-game contract (`desktop/renderer/missions/contract.js`) plus `covers`. Internally:

- `lineKind(finding)` → one of `port`, `conn`, `firewall`, `dns`, `profile`, `hosts`, `proxy`, `sharing`, `wifi`,
  `router`, `vpn` (by module, narrowed by finding code).
- `linesOf(finding, ctx)` → `{ kind, dir, lines: [{ via, to, odd }], more }`, read from the engine's real `data`
  fields per module (port strings from `open_ports_scan`, `{ip, hostname}` hosts entries, `servers` lists,
  `http_server`/`pac_url` proxies, `service` / `tool` / `share` sharing, `network`/`security` Wi-Fi...), falling back
  to the short list of string values when a shape is unknown.
- `KINDS[kind]` → words (standard/city), the settings pane per platform (`darwin` / `win32`), the lesson concept,
  the look-closer checklist and the manual close steps.
- Decisions: Expected → `mark` when the finding carries a valid `markable` block (sharing services, proxies, the
  DNS profile), else `keep`; Odd — close it → `fix` when the engine attached `fixable`, else `settings` with the
  kind's pane, else `odd` with manual steps (hosts file, router, connections); Look closer → `closer` with the
  kind's checklist. Never a removing decision first.
- DNS filtering profile (`security.dns_poisoning_check.dns_filtering_profile`): the profile owner question in the
  card, labels "It's my profile" / "Not mine — undo" / "Look closer", Expected → mark (`dns_profile`).
- Render: escaped HTML only; city mode never prints the finding's own title or description (the DNS profile
  description carries hotline text), only game words plus the traced values.

**Tech Stack:** plain JS ES modules, `node --test` (Node 22), no DOM in the game.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `switchboard`,
"Each mini-game" entry), common brief `.superpowers/sdd/missions-common.md`.

## Global Constraints

- Own only: `desktop/renderer/missions/games/switchboard.js`, `games/switchboard.css`,
  `desktop/test/missions-switchboard.test.js`, `desktop/test/fixtures/missions/switchboard-*.json` (synthetic).
- `runContractChecks(game, items)` returns `[]` for fixture + practice items.
- 2–3 decisions, labels ≤ 4 words, first is the safe default; removal-alert items never get `fix` first.
- Games are pure: no DOM, storage, globals, network, clipboard. Link intents only (settings / lookup / lesson).
- Firewall split: `firewall_audit` and the on/off/unknown/stealth codes of `firewall_rules_audit` belong to
  Lock Run; this game claims only `firewall_rules_audit.{allow_signed_enabled, too_many_apps, firewall_summary}`
  and the Windows rules module `win_firewall_rules_audit`. `win_firewall` (profile off) stays with Lock Run.
- Mac AND Windows: `win_firewall_rules_audit`, `win_hosts_file`, `win_hosts_file_check`, `win_proxy_detect`,
  `win_rdp_check`, `win_remote_access_audit`, `win_network_shares_audit`, `win_dns_config`; Windows words
  ("This PC") and Windows panes (`windows-firewall`, `windows-apps`).
- City mode: game words only (CITY_FORBIDDEN), never "all clear", "This check didn't finish" when it didn't.
- Fixtures synthetic: documentation IP ranges (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24), `.example`
  names, `~` paths, no MACs, serials or SSIDs from a real machine.
- No time words.

## Review Focus

- Every `data` field read exists in the module source (grep `data={` in `modules/**/<module>/__init__.py`).
- Escaping: every scan value goes through `ctx.esc` (which applies `visible`).
- No raw finding prose in city mode.
- `covers` never claims a firewall on/off code.

## Task 1: Synthetic fixtures and failing tests

**Files:** create `desktop/test/fixtures/missions/switchboard-items.json`, `desktop/test/missions-switchboard.test.js`.

- [ ] Fixture: one synthetic finding per line kind, macOS and Windows, each with `expect.kind` and (where it
  matters) `expect.odd` (the effect kind Odd should produce) and `expect.expected` (mark/keep).
- [ ] Tests (fail: module missing):

```js
test('passes every contract check on fixtures and practice items', async () => {
  const { C, game, items } = await load();
  assert.deepStrictEqual(C.runContractChecks(game, items), []);
});
test('each fixture finding is traced as its kind', ...);       // lineKind
test('Expected marks only when markable; Odd fixes, opens settings or gives steps', ...);
test('covers: spec modules + Windows equivalents; never firewall on/off codes', ...);
test('DNS filtering profile asks whose profile it is, and city mode drops the finding prose', ...);
test('port lines: loopback reads only this computer; 0.0.0.0 reads open to the network and is odd', ...);
test('hostile values inside entries, ports and servers render inert', ...);
test('research: pane per platform, lesson, look-up intent, didn\'t-finish line', ...);
test('practice: printer port, unknown listener, hosts redirect; script expects real decision ids', ...);
test('summary counts decisions and never says all clear', ...);
```

- [ ] Run `cd desktop && node --test test/missions-switchboard.test.js` → fails (module not found). Commit.

## Task 2: The kind table, line tracing and covers

**Files:** create `desktop/renderer/missions/games/switchboard.js`.

- [ ] `MODULE_KIND` + `CODE_KIND` overrides (`unusual_listening_port` → `port`, `dns_filtering_profile` → `profile`,
  `vpn_leak_check.dns_leak` → `dns`).
- [ ] `linesOf` readers per kind (port string parser `^(?:Port\s+)?(\d+)\s*\(([^)]*)\)\s*(?:-\s*(.+?)\s+on\s+(\S+)|listening on\s+(\S+))`,
  connection string parser `^(.+?) \(PID (\d+)\) -> (.+):(\d+)$`, hosts `{ip, hostname}`, servers lists, proxy
  fields, sharing `service`/`tool`/`share`, Wi-Fi `network`/`networks`, router `gateway_ip`/`port`/`service`).
- [ ] `covers` list. Run tests for kinds and covers → pass. Commit.

## Task 3: Decisions, research, render, summary, practice

- [ ] `decisions(item, ctx)`, `research(item, ctx)`, `render(view, ctx)`, `summary(results, ctx)`,
  `practice` (cupsd on port 631 loopback → Expected; unknown `syncagentd` listening on 4444 → Look closer;
  `mybank.example` → 203.0.113.7 hosts redirect → Odd — close it).
- [ ] All tests pass. Commit.

## Task 4: Styles and visual check

**Files:** create `desktop/renderer/missions/games/switchboard.css`.

- [ ] Line diagram: three nodes joined by wires (CSS borders), odd node highlighted, wraps to a column under
  560px; uses the game's CSS variables with fallbacks.
- [ ] Preview HTML in the scratch folder rendering practice + fixture items in standard and city; screenshot.
- [ ] `cd desktop && npm test && npm run check-game-files` green. Commit.
