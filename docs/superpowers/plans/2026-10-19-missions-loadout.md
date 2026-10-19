# The Loadout (browser add-ons) mini-game — implementation plan

> For agentic workers: implement task by task, test first. Each task: write the failing test, run it, implement,
> run it green, commit.

**Goal:** `desktop/renderer/missions/games/loadout.js`, the `loadout` mini-game: each browser add-on (and each
browser hijack / in-browser mining finding) gets one card with its powers in plain words and one decision —
**Keep** / **Trim** / **Remove** for extensions, adapted moves for the other kinds.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (types table row `loadout`,
"Each mini-game: loadout"). **Contract:** `desktop/renderer/missions/contract.js`.

**Files (this track owns only these):**
- `desktop/renderer/missions/games/loadout.js`
- `desktop/renderer/missions/games/loadout.css`
- `desktop/test/missions-loadout.test.js`
- `desktop/test/fixtures/missions/loadout-*.json` (synthetic)

## Global constraints

- Pure module: no DOM, storage, globals, network, clipboard. Only `ctx` (`esc`, `visible`, `evidenceRows`, `mode`,
  `platform`, `practice`).
- Every scan value goes through `ctx.esc`. An extension id only appears in typed instructions when it matches
  `^[a-p]{32}$` (the Chrome/Edge id alphabet); otherwise the instruction names the page without it.
- Links are intents only: `lookup` (`chrome-web-store` by validated id; `web` by quoted name otherwise),
  `settings` (`profiles` for a managed browser on macOS), `lesson` (`browser-add-ons`, `wifi-and-mining`).
  Practice items get no look-ups (their ids are made up).
- `chrome://`, `edge://`, `about:` pages cannot be linked: the card says what to type, and which key to press
  (Return on a Mac, Enter on Windows).
- Removal is instructions (the engine has no app fix for extensions); an effect is `fix` only when the finding
  carries an engine `fixable` block, and never first on an item with a removal warning. Keep is `mark` when the
  engine offers `markable`, else `keep`.
- 2–3 decisions, labels ≤ 4 words, first is the safe default. City mode: game words, no CITY_FORBIDDEN words.
- macOS and Windows: Chrome, Edge, Brave, Vivaldi, Chromium, Firefox, Safari. `browser_cryptojacking_check` and
  `security_baseline_diff` run on Windows; there is no `win_*` browser-extension module (noted for the report).
- No time words, calm plain copy, teach once (practice + lesson link).

## Review focus

- Escaping of names, ids, permissions, homepages, hostnames (contract hostile test plus our own).
- The removal warning: Remove is never the first decision; no copy suppresses the runner's warning.
- City output: no forbidden words in render, summary, practice script, effect steps.
- Browser detection on Windows: the cryptojacking check names Chromium browsers by the profile root's folder,
  which is `User Data` on Windows, so the game reads the browser from the path.

## Covers

| module | codes |
|---|---|
| chrome_extensions | all |
| safari_extensions | all |
| browser_extension_audit | all |
| browser_hijack_check | all |
| browser_cryptojacking_check | all (its findings have no code) |
| security_baseline_diff | `security.security_baseline_diff.new_browser_extension` |

## Item kinds (from `code`, else `data.check`)

| kind | source | decisions |
|---|---|---|
| extension | chrome_extensions.broad_permissions, browser_extension_audit.excessive_permissions | Keep it / Trim access / Remove it |
| known-bad | browser_extension_audit.malicious_extension, adware_extension | Look closer / Remove it / Keep it |
| miner | cryptojacking `mining_extension` | Look closer / Remove it / Keep it |
| mining-page | cryptojacking `mining_startup_page` | Look closer / Reset startup page |
| mining-hosts | cryptojacking `mining_hosts_entry` | Look closer / Remove the line |
| hijack | browser_hijack_check *_homepage_suspicious, *_search_engine_suspicious | I chose this / Reset it / Look closer |
| managed | browser_hijack_check.chrome_managed_by_policy | Work or school / Look closer |
| many | *.extension_bloat | Keep them all / Trim the list |
| legacy | safari_extensions.legacy_extensions | Keep them / Remove them |
| blockers-off | safari_extensions.content_blockers_disabled | Leave it off / Turn one on |
| new-ext | security_baseline_diff.new_browser_extension | I added these / Look closer / Remove them |
| list | anything else (inventories) | Looks right / Look closer |

## Tasks

### Task 1: fixtures and the contract

- `desktop/test/fixtures/missions/loadout-findings.json`: synthetic findings for every kind, macOS and Windows
  (home `/Users/example`, `C:\Users\example`, made-up names and ids).
- Test: `runContractChecks(game, items)` returns `[]` for the fixture items; `covers` lists the six modules.
- Implement the module skeleton: type, titles, concepts `['browser-add-ons']`, covers, classify, minimal
  decisions/research/render/summary, practice (3 items, script).

### Task 2: permissions in plain words and the card

- Test: `<all_urls>` → "Read and change all your data on all websites"; `cookies`, `tabs`, `webRequestBlocking`,
  `scripting`, a host pattern, an unknown permission (shown escaped as itself); an empty list → "Asks for no special
  access"; the card shows name, browser, powers ordered high first; hostile names/permissions are inert.
- Implement `powers(perms, mode)` and `render`.

### Task 3: decisions and browser steps

- Test: per kind, the decision ids and order above; Remove is never first when `removal_alert`; `mark` only with
  `markable`; `fix` only with `fixable`. Trim/Remove steps: Chrome (`chrome://extensions/?id=<id>`), Edge
  (`edge://extensions/?id=<id>`), Brave, Firefox (`about:addons`), Safari (Settings > Extensions), Return vs Enter
  by platform; a hostile id never reaches the steps; Windows cryptojacking `User Data` paths resolve to Edge/Chrome.
- Implement `browserOf`, `trimSteps`, `removeSteps`, `resetSteps`, the hosts-file steps (macOS / Windows).

### Task 4: research

- Test: rows come from `ctx.evidenceRows`; `what` for a known password-manager id; verified `made_by[].what` is
  used; unknown maker otherwise; Chrome Web Store look-up only for a valid id on a Chromium browser that installs
  from that store; web look-up by quoted name otherwise; practice has no look-ups; lesson link per kind;
  "This check didn't finish" when the item is unfinished.

### Task 5: practice, summary, CSS

- Test: practice has 3 synthetic items (password manager → keep, coupon add-on → remove, theme → keep), every
  `expect` is a decision id of its item; city script and summary pass the forbidden-word check; summary counts
  kept/trimmed/removed and never says "all clear".
- `loadout.css`: card, power chips by level, steps, using the game's CSS variables.

### Task 6: visual check and report

- Preview HTML in the scratch folder rendering practice + fixture items in standard and city; screenshot.
- Full desktop suite + `check-game-files`; report.
