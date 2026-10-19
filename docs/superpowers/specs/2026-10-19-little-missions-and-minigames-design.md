# Little missions and mini-games — design

Status: decisions made by the owner on the decisions page (2026-10-19); approved to plan and build in parallel.
Builds on: teach-once proposal (`2026-10-18-teach-once-and-checklists-proposal.md`, "a lot of little missions"),
the player profile (`2026-10-18-player-profile-and-irt` plan), the UX rounds (`.superpowers/sdd/ux-audit-*.md`).

## Why

A real scan of the owner's Mac gives 94 things to act on across ~40 checks, plus 394 good-to-know notes.
As a list that is 80+ cards. The owner: "The average person only has like a 47 second attention span, so your
computer's checkup is like… a lot of little missions." And: "each decision is clear, easy to do, the research is
as easy as possible / done for the user wherever possible (with links)."

## Decisions made with the owner

1. **Missions by area.** Findings are grouped by the type of thing they are about (table below), not by check.
2. **Every item gets its own decision.** A mission is a small set of same-type items; inside it each item is
   decided one at a time.
3. **Each type has its own mini-game**, and each mini-game **teaches itself**: the first time a person meets it,
   a short guided practice round on a made-up example shows the moves and what to look at.
4. **Plain view is retired** (owner's pick on the decisions page). Everyone plays the city. The display mode still
   decides the words and safety notes: `standard` (plain words allowed, safety notes per the safety question) or
   `city` (stealth: game words only, help district). The city's LIST tab stays as a read-only literal list built
   from `NotChecked.displayItems` (the owner chose "keep the list literal" in stealth). Mini-games have ONE skin,
   the game skin; text inside them follows the display mode.
5. **Research is done for the person.** Every item arrives with what is already known and the links needed to
   check it; the person never has to go searching. **In stealth mode, look-up searches are shown as text to search
   on another device, never as links** (browser history on a watched computer); settings-pane links still open.
6. Built in parallel: one foundation plan, one plan per mini-game, and one plan to retire Plain view, all at once
   against the contract below ("contract-first").

### Picks from the decisions page (2026-10-19)

| Decision | Pick |
|---|---|
| Plain view | Retire it |
| Look-up links in stealth | Text to search elsewhere |
| Items per mission | **Up to 4** (bigger sets split into "part 1 of N") |
| Mission order | Most important first (critical, then warnings; removal-warning or fixable first) |
| Practice round | First time per game, skippable, re-offered on gaps — **and on request** (a "Practice" button on every mission) |
| Look closer | Evidence + checklist; the item stays open until Mine / Not mine |
| Good-to-know notes | Optional batches — **incentivized** (points per batch, a streak/bonus for clearing an area's notes) |
| Points | Per decided item + a mission bonus; **confirmed fixes pay more** (the existing CONFIRMED award raised); held never pays |
| Remember answers | Until the evidence changes (path, signer, settings) |
| Unmapped checks | Fall back to Odd Jobs |
| Windows / Linux | **Map Windows now**: every game also covers its Windows equivalents (win_* modules); Linux falls back |
| Firewall | Split: "firewall off" → Lock Run; rules/ports → Switchboard |
| Build | All at once against the contract; foundation merges first, then games |

## Types and mini-games

| Type id | Area (standard title / stealth title) | Covers (engine modules, macOS first) | Mini-game | Decision per item | Trains |
|---|---|---|---|---|---|
| `door` | Things that start on their own / The Door | launch_agent_audit, launchd_persistence_audit, login_items_cleanup, login_items, scheduled_tasks_audit, cron_jobs_audit, startup_optimizer, startup_auditor, security_baseline_diff (persistence items), ai_worm_persistence, crypto_miner_persistence, kext_audit, kernel_extensions_audit, system_extensions_check | Each entry knocks: path, signer + verified, hidden folder?, when it appeared, what the program is. | **Mine** / **Look closer** / **Not mine** | Reading path and signer |
| `keyring` | Apps with powerful access / The Keyring | app_permissions, privacy_permissions_audit, accessibility_permissions, keylogger_indicators (non-held), screen_time_audit, location_services | Each app holds keys (keyboard, screen, camera, mic, accessibility, full disk). Hand back keys it doesn't need. | per key: **Keep** / **Hand back** | Least privilege |
| `loadout` | Browser add-ons / The Loadout | chrome_extensions, safari_extensions, browser_extension_audit, browser_hijack_check, browser_cryptojacking_check | Each extension's powers laid out. | **Keep** / **Trim** (open its settings) / **Remove** | What extension permissions mean |
| `seal` | App seals / Seal Check | code_signature_audit, gatekeeper_quarantine_check, suspicious_processes (unsigned apps), certificate_audit, certificate_trust_audit | Compare the seal on the app with the maker's. | **Reinstall from the maker** / **Mine, I know why** / **Look closer** | Tampered vs old format vs unknown maker |
| `switchboard` | Network lines / The Switchboard | firewall_audit, firewall_rules_audit, open_ports_scan, network_connections_monitor, suspicious_connections, dns_config, dns_poisoning_check (incl. DNS profile), hosts_file_check, network_proxy, network_proxy_check, network_proxy_detect, remote_login_check, sharing_preferences_audit, router_security_audit, wifi_security_audit, vpn_leak_check, airdrop_config | Trace each line to where it goes. | **Expected** / **Odd — close it** / **Look closer** | Ports, DNS profiles, redirects, sharing |
| `locker` | Suspicious files / The Evidence Locker | ai_worm_filesystem, ai_worm_iocs, ai_worm_git_ssh, ai_worm_lateral, ai_worm_network, ai_threat_indicators, malware_scan_indicators, clamav_scanner, cryptojacking_iocs, crypto_miner_detect, rootkit_check, temp_file_scanner (flagged items) | Tag each file. | **Mine** / **Quarantine** / **Look closer** | Reading file evidence |
| `locks` | Settings and locks / Lock Run | automatic_updates, update_checker, encryption_check, filevault_recovery, firewall_audit (on/off), screen_lock_check, lock_screen_check, find_my_mac_check, guest_account_check, firmware_password, login_password_policy, antivirus_status, macos_version_support, macos_eol_check, backup_status, time_machine_check, session_revocation_scan, appleid_security_check | One switch per item, with the exact settings pane. | **Turn it on** (opens the pane) / **Done** / **Not now** | Where the switches live |
| `junkyard` | Storage and clutter / The Junkyard | storage_cleanup, large_files_finder, library_cache_cleanup, browser_cache_cleanup, trash_cleanup, docker_cleanup, xcode_cleanup, mail_attachment_cleanup, crash_log_analyzer, app_crash_analyzer, energy_saver_check, energy_settings, resource_hog_identifier, system_log_errors, process_scanner (bloat), win_* cleanup | Swipe-style sort. | **Keep** / **Clear** (fix flow) / **Later** | What's safe to clean |
| `notes` | Good to know / Signal or Noise | every `info` finding not claimed above | Batches of 5 from the existing Signal or Noise game. | **Normal** / **Odd** (odd → becomes a mission of its type) | Telling normal from odd |
| `simple` | Other / Odd Jobs | anything unmapped | One item at a time with the finding's own actions. | the finding's actions | — |

The mapping lives in one table (`missions/types.js`); a module can map to a type for some finding codes only
(e.g. `security_baseline_diff` persistence items → `door`). A test fails if a module that produces critical or
warning findings on macOS is unmapped (it would land in `simple` — allowed only if listed).

## The foundation

### Missions

`groupMissions(doc, { mode }) -> Mission[]` built from `NotChecked.displayItems` (so counts stay identical to
`scanCounts`):

```
Mission = { id, type, district, severity /* highest item */, items: Item[], title: {standard, city} }
Item    = the displayItems item ({ key, severity, finding, findings, seen_in, marked, held }) + { removal_alert }
```

- One mission = one type within one district, at most **4 items**; bigger sets split into "part 1 of N".
- Order: critical first, then warnings; within a level, missions with a `removal_alert` item or a fix first.
- Held items (city mode) never enter a mission; they stay in the help district. In standard mode there is no held.
- `info` items go to the `notes` mission only.
- Marked-as-yours items don't appear unless stale (`mark_stale`), then as a normal item.

### Mini-game contract

Every game is one ES module, `desktop/renderer/missions/games/<type>.js`, default export:

```js
export default {
  type: 'door',
  title: { standard: 'Things that start on their own', city: 'The Door' },
  concepts: ['where-it-lives', 'who-made-it'],        // existing profile concept ids it trains
  decisions(item, ctx) -> Decision[],                  // 2–3, first is the safe/default one
  research(item, ctx) -> { rows, what, links },        // rows from Evidence.evidenceRows; links from Research
  practice: { items: Item[], script: Step[] },         // made-up items + guided steps (see below)
  render(view, ctx) -> string,                         // HTML for ONE item; must escape all scan data
  summary(results, ctx) -> string,                     // end-of-mission recap
}
Decision = { id, label: {standard, city}, effect: Effect, hint?: string }
Effect   = { kind: 'mark' | 'fix' | 'settings' | 'link' | 'closer' | 'later' | 'note' | 'odd', ...args }
ctx      = { mode: 'standard'|'city', practice: bool, platform, districtName }   // one game skin; mode picks the words
view     = { item, research, decisions, index, total, practice, step? }
```

Rules every game obeys (tested in the foundation's contract test, run against every registered game):

- **Games never touch the computer or storage.** They return Effects; the runner carries them out through the
  existing flows: `mark` → MarkFlow (its own confirm), `fix` → FixFlow (warning first, confirm), `settings` →
  the existing open-settings path, `link` → allowlisted external link, `closer` → evidence + "what to check"
  checklist, `later` / `note` / `odd` → mission state only.
- **Safety:** when an item has `removal_alert` or `safety_note`, the runner shows the removal warning line above
  the decisions and inside any `fix` confirm; games cannot suppress it. A `fix`/remove decision is never the
  first (default) decision for such items.
- **Honesty:** an item from a check that didn't finish shows "This check didn't finish" in its research; a
  mission never says "all clear".
- **Stealth (city):** game words only; no clipboard for monitoring-module evidence; no non-game words in
  `render`/`summary` output in city mode (FORBIDDEN word test over every game's city output, practice included).
- **Escaping:** all scan data goes through the shared escaping/`visible-text` helpers; contract test feeds
  hostile strings (HTML, markdown, shell, newlines, bidi) through every game.
- **One decision per item**, 2–3 buttons, labels ≤ 4 words.
- No time estimates; plain calm wording in standard mode, game words in city mode.

### Research

`missions/research.js` builds, per item, from data the engine already has:

- `rows`: `Evidence.evidenceRows(finding, {mode})` (already per-subject, already safe).
- `what`: the known-program description (`made_by[].what`) when the identity was verified, else "Unknown maker".
- `links` (only from allowlisted templates; values URL-encoded; never a raw URL from scan data):
  - **Settings pane**: `x-apple.systempreferences:` URLs per type (Login Items, Privacy panes by permission,
    Network/Firewall, Sharing, General > Software Update, FileVault, Storage); Windows `ms-settings:` equivalents.
  - **Look it up**: the maker's site only when the maker is a verified known program with a site in
    `program_descriptions.json`; Chrome Web Store by extension id; Apple support search for a bundle id or
    label; otherwise a web search for the exact quoted name.
  - **Lesson**: the type's lesson (existing lessons/concepts).

### Practice rounds (self-teaching)

- First time a person opens a mission of a type (per profile), the game runs `practice`: 2–3 made-up items with
  `script` steps that point at the part to look at ("See the path? It's in a hidden folder.") and let the person
  make the move. Practice answers are recorded as profile evidence on the game's `concepts` (via the existing
  profile API), so the IRT measure learns from play. Practice is skippable ("I know this" → recorded as skipped,
  re-offered when gaps show, as today).
- Practice items are synthetic and contain no real data.

### Runner and screens

- **City only.** A district shows its missions as rows (checkbox, title, count, severity, "part 1 of N");
  "Investigate next" on the deck opens the most important unfinished mission. A mission screen: title, progress
  "item 2 of 4", one item at a time (research → decisions), then the summary and "Next mission". A "Practice"
  button on every mission runs the game's practice round on request.
- **Points:** per decided item, a bonus when a mission is finished, a larger CONFIRMED award when a re-check proves
  a fix, points per notes batch and a bonus for clearing an area's notes. Held never pays; removal of
  monitoring-capable software never pays more than leaving it.
- **Remembering:** answers are kept per item key with an evidence fingerprint (path, signer, settings hash from
  the finding's data); an answered item stays answered on the next scan until the fingerprint changes. Stored in
  the recipe-box profile with innocuous keys (stealth FORBIDDEN-word test applies).
- **Fallback:** a type without its game module yet uses `simple`.
- **Skin:** one game skin; copy inside follows the display mode (`standard` plain words / `city` game words).

### Files (foundation)

- `desktop/renderer/missions/types.js` — mapping + `groupMissions`.
- `desktop/renderer/missions/contract.js` — game registry, validation, the hostile-input and stealth checks.
- `desktop/renderer/missions/research.js` — links + research assembly.
- `desktop/renderer/missions/runner.js` — state machine, effects dispatch, persistence hooks, practice gating.
- `desktop/renderer/missions/missions.css` — shared mission chrome using the game's CSS variables.
- `desktop/renderer/missions/games/simple.js` — fallback game (reference implementation of the contract).
- City wiring in `game/controller.js`, `game/views/district.js`, `game/views/deck.js`, `game/ledger.js`.

## Retiring Plain view (its own plan)

- The welcome flow goes worry → safety question → checkup → the city. No "Plain view" route or toggle.
- `standard` mode is the city with plain words allowed and safety notes as today; `city` mode is stealth.
- The LIST tab stays: a read-only literal list (from `displayItems`, with evidence blocks, no fix/mark controls;
  in stealth, held items as the help district shows them) so a person can always see everything.
- Plain-only code (results cards, clear-list, Plain fix/mark panels, plain-panel "Your progress", Plain copy-for-AI)
  is removed or folded into the city; the fix and mark FLOWS (FixFlow, MarkFlow, main-process gates) stay — the
  runner uses them. The Your-progress dialog is replaced by YOUR FILE.
- Tests for removed screens are deleted with them; tests for kept behaviour (safety warning, honesty, stealth,
  gating, step-fill, evidence) are moved to the city equivalents, never dropped.

## Each mini-game (one plan each)

Each game plan touches only `missions/games/<type>.js`, `missions/games/<type>.css`, its test
`desktop/test/missions-<type>.test.js`, and practice fixtures under `desktop/test/fixtures/missions/` (synthetic
only — never real scan data; the fixture-privacy test covers this folder). Each must: implement the contract;
give per-item research and 2–3 decisions with the effects above; a practice round of 2–3 synthetic items with a
script; a summary; output in both display modes (standard words / city game words); cover the **Windows**
equivalents of its macOS modules (win_* modules and `ms-settings:` panes); pass the contract test.

- **door** — knock card: name/label, "Runs" path (hidden folder highlighted), signer + verified, "appeared on",
  what the program is; decisions Mine (mark) / Look closer (closer: checklist "Is it in Login Items? Do you
  recognise the maker? Search the label") / Not mine (fix, with warning). Practice: a verified Apple agent, an
  unsigned agent in `~/.hidden`, a developer tool you installed.
- **keyring** — one app at a time with its keys as chips; each key: Keep / Hand back (settings link to that
  privacy pane). Practice: a screen recorder with Screen Recording (keep), a game with Accessibility (hand back).
- **loadout** — extension card with permissions translated ("Read and change all your data on all websites");
  Keep / Trim (opens chrome://extensions/?id=… via instructions, since chrome:// can't be linked) / Remove.
- **seal** — side-by-side "what the maker signed" vs "what's on disk", plain verdict (tampered / old format /
  unknown maker / unsigned); Reinstall from the maker (link) / Mine, I know why (mark) / Look closer.
- **switchboard** — a line diagram: this Mac → port/process → where it goes (DNS server, proxy, hosts redirect,
  sharing service); Expected (mark where markable) / Odd — close it (fix or settings) / Look closer. DNS
  filtering profile shows the profile owner question.
- **locker** — file tag: path, size, when, what matched, maker; Mine (mark) / Quarantine (fix where the engine
  offers it, else move-aside instructions) / Look closer.
- **locks** — a row of locks; each: what it protects, its state, Turn it on (settings link) / Done (recheck) /
  Not now. Uses the existing "I did this" recheck.
- **junkyard** — size-first cards; Keep / Clear (fix flow; storage fixes already exist) / Later. Shows freed
  space total in the summary.
- **notes** — Signal or Noise in batches of 5 notes from one area; Normal / Odd; odd turns the note into an item
  of its type in a new mission. Batches are optional and resumable, and incentivized: points per batch, a bonus
  for clearing an area; progress shows "120 of 394 sorted".

## Testing

- Foundation: grouping (counts equal `scanCounts.todo`; ≤6 per mission; held excluded in city; unmapped list),
  runner (effects dispatch to stubs; warning always injected; practice gating; persistence), research (link
  allowlist; encoding; hostile values), contract test over every registered game.
- Each game: decisions/research/practice/summary unit tests; contract test; screenshots in standard and city mode at
  default and 800px via the replay harness (synthetic or local-only replays; never commit real scan data).

## Out of scope

Windows-specific mini-game polish (fallback to `simple` where a Windows module isn't mapped); new engine checks;
publishing.
