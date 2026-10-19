# Lock Run (missions: settings and locks) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The `locks` mini-game. A mission of up to four settings items is shown as a row of locks; each lock says what it protects, its state, and exactly where its switch lives, on macOS and Windows. Each item gets one decision: **Turn it on** (opens that settings pane), **Done** (re-check that check), **Not now**.

**Architecture:** One pure ES module, `desktop/renderer/missions/games/locks.js`, default export per `desktop/renderer/missions/contract.js` plus `covers`. A `LOCKS` table holds, per lock, its name (standard / city), what it protects, the lesson concept, and per platform (`mac`, `win`) the "where" sentence, a `SETTINGS_PANES` id (or `null`), the steps when there is no pane, and a fixed look-up. `lockOf(finding)` maps module + `data.check` / `code` to a lock. `couldntCheck(item)` decides "Not checked". The game returns Effects and link intents only; the runner acts. `games/locks.css` styles it with the game skin's tokens.

**Tech Stack:** plain JavaScript ES modules, `node --test` (Node 22). No new dependencies.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `locks`; "Each mini-game" → locks). Brief: `.superpowers/sdd/missions-common.md`.

## Global Constraints

- Files owned (and the only ones touched): `desktop/renderer/missions/games/locks.js`, `desktop/renderer/missions/games/locks.css`, `desktop/test/missions-locks.test.js`, `desktop/test/fixtures/missions/locks-*.json` (synthetic only).
- `runContractChecks(game, items)` returns `[]`.
- Decisions: 2–3, labels ≤ 4 words, the first is the safe default; never a `fix` first (the saved-keys item carries `removal_alert`).
- Never ask for a password, a one-time code or a recovery key; no input fields. Recovery-key locks (FileVault, BitLocker) say never to paste the key anywhere, in both modes.
- "Couldn't check" never reads as fine: state "Not checked", the line "This check didn’t finish…", decisions "Check it myself" / "Check again" / "Not now".
- Firewall: only "firewall off" (`security.firewall_audit.global_state*`); rules/ports and stealth mode stay with the switchboard.
- City mode: game words only (`CITY_FORBIDDEN`). Look-ups are intents; the runner shows them as text in city mode.
- Copy: plain, calm, no time words; teach once (one line + lesson intent).
- Mac and Windows: Windows Update, BitLocker, Defender / antivirus, Windows Firewall, UAC, accounts, password policy, System Restore.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

1. **Honesty on a check that couldn't look.** `update_checker` "Couldn't check for macOS updates", `time_machine_check` `no_backup_date`, `win_update_history` `service_check_failed`, any `*_unknown` code, and an item the runner flags `incomplete`. None may show "Off"-as-known or anything like "on/fine".
2. **Recovery keys.** No field, no "paste it here"; the never-paste line on every recovery-key lock.
3. **Windows items on a Windows machine show no Mac words** (and Windows panes where they exist: `windows-update`, `windows-security`, `windows-firewall`; otherwise "Show me how" with steps).
4. **Past locks in the row are "visited", never drawn shut**: a decision isn't proof; only a re-check is.

## Decisions made while planning

- Locks with no pane to open (firmware password, a third-party antivirus, Homebrew, saved SSH keys, BitLocker, UAC, Windows accounts and password policy, System Restore) get **Show me how** (`closer` with a checklist) instead of Turn it on; still 3 decisions.
- Off-switches that should be *off* (automatic login, guest access) say **Turn it off**.
- Practice items are Mac items (the contract's `practice` is static). Their words are generic enough on Windows; a per-platform practice set needs the runner to pick by platform (noted for the foundation).
- `summary(results)` accepts `[{ item, decision }]` with `decision` an id or a Decision object.

---

### Task 1: Fixtures and the failing test file

**Files:** Create `desktop/test/fixtures/missions/locks-mac.json`, `desktop/test/fixtures/missions/locks-win.json`, `desktop/test/missions-locks.test.js`.

- [ ] **Step 1: Write synthetic fixtures.** `{ note, platform, findings: [...] }`; each finding copies a real engine shape (module, code, severity, title, data keys from the module source). Mac: automatic_updates critical_update; update_checker os_updates and brew_outdated; time_machine_check no_backup_date (couldn't check); encryption_check filevault_disabled; filevault_recovery no_recovery_key; firewall_audit global_state; screen_lock_check screen_lock_required; login_password_policy auto_login; find_my_mac_check find_my_mac_disabled; guest_account_check guest_smb_access; firmware_password firmware_password_not_set; antivirus_status av_not_running; macos_eol_check; backup_status timemachine_disabled; session_revocation_scan ssh_authorized_keys (`removal_alert: true`); appleid_security_check icloud_keychain. Windows: win_windows_update_status updates_paused; win_update_history service_check_failed; win_bitlocker_check os_drive_not_encrypted; win_bitlocker no_recovery_key; win_defender realtime_protection; win_firewall public_profile_disabled; win_uac_check uac_never_notify; win_user_accounts guest_account_enabled; win_credential_guard password_min_length_below_threshold; win_restore_points restore_disabled. Names like `example`, `ExampleAV`, `macOS Example 99.1`.

- [ ] **Step 2: Write the tests** (the file as committed): contract checks over both fixtures; every item maps to a lock; decisions `['on','done','later']` with `{kind:'settings', pane:'software-update'}` / `{kind:'recheck', module}` / `{kind:'later'}`; each Mac lock's pane (`filevault`, `firewall`, `lock-screen`, `users-groups`, `apple-id`, `sharing`, `time-machine`, `software-update`); Windows panes or `closer` + checklist, and no Mac words on Windows locks; Mac no-pane locks are `closer`; couldn't-check items read "Not checked" + "didn’t finish" + Check it myself / Check again, `incomplete: true` counts; recovery-key never-paste line in both modes and no input field anywhere; saved-keys lock never `fix`; research what/where/links (allowlisted, fixed look-up queries); evidence rows escaped; render's row of pips (current marked, none drawn shut); city words; practice (updates off, FileVault off, screen lock never; `expect` ids exist; coach line); summary counts and never "all clear"; no time words; `covers` includes the spec row + Windows, firewall narrowed to `security.firewall_audit.global_state`, no duplicates; every covered module exists in `modules/**` and narrowed codes appear in its source; purity (no DOM/storage/network/clipboard, no URLs).

- [ ] **Step 3: Run and see it fail.** `cd desktop && node --test test/missions-locks.test.js` → fails: `games/locks.js` not found.

### Task 2: The game module

**Files:** Create `desktop/renderer/missions/games/locks.js`.

- [ ] **Step 1: The lock table and mapping.** `LOCKS` ids: `updates`, `os-support`, `app-updates`, `encryption`, `recovery-key`, `firewall`, `screen-lock`, `auto-login`, `guest`, `guest-share`, `find-my`, `location`, `firmware`, `password`, `antivirus`, `uac`, `backups`, `sessions`, `apple-id`. `BY_CHECK` (module → fn(check, code)) for modules whose items split (update_checker, filevault_recovery, disk_encryption_recovery, screen_lock_check, guest_account_check, find_my_mac_check, login_password_policy, appleid_security_check, win_bitlocker*, win_user_accounts); `BY_MODULE` for the rest. Export `lockOf`, `couldntCheck`, `LOCK_IDS`, `covers`.

```js
export function couldntCheck(item) {
  const f = (item && item.finding) || {};
  const d = dataOf(f);
  if (item && (item.incomplete === true || item.complete === false)) return true;
  if (COULDNT_TITLE.test(String(f.title || ''))) return true;
  if (COULDNT_CHECKS.has(String(d.check || ''))) return true;
  if (COULDNT_CODE.test(String(f.code || ''))) return true;
  return f.module === 'macos_eol_check' && 'error' in d;
}
```

- [ ] **Step 2: decisions / research.**

```js
export function decisions(item, ctx) {
  const { lock, place } = lockFor(item, ctx);
  const unknown = couldntCheck(item);
  const mods = modules(item);
  const recheck = { kind: 'recheck', module: mods[0] || null, modules: mods };
  const later = { id: 'later', label: { standard: 'Not now', city: 'Not now' }, effect: { kind: 'later' } };
  const on = place.pane
    ? { id: 'on', label: unknown ? { standard: 'Check it myself', city: 'Check it myself' } : (lock.on || { standard: 'Turn it on', city: 'Lock it' }), effect: { kind: 'settings', pane: place.pane } }
    : { id: 'on', label: { standard: 'Show me how', city: 'Show me how' }, effect: { kind: 'closer', checklist: place.how.slice() } };
  const done = { id: 'done', label: unknown ? { standard: 'Check again', city: 'Check again' } : { standard: 'Done', city: 'Check the lock' }, effect: recheck };
  return [on, done, later];
}
```

`research` returns `{ rows: ctx.evidenceRows(f, {mode}), what: lock.protects, links: [settings?, lookup?, lesson?], lock, where, steps, notChecked, neverPaste }`.

- [ ] **Step 3: render / summary / practice.** `render` draws the pip row (`view.index`, `view.total`), the coach line for `view.step`, the card (kicker, name, state badge Off/Unlocked or Not checked/In the fog, the finding's title, Protects/Guards, Where/Switch, the not-checked line, the never-paste line, the steps, the evidence rows in a fold). Every value through `ctx.esc`. `summary` counts on/done/later and the not-checked ones and ends "Locks lower the odds of a problem. They don’t rule one out." Practice: three synthetic Mac items (updates off, FileVault off, screen lock never) and four steps (`expect: 'on'`, `'on'`, `'done'`).

- [ ] **Step 4: Run.** `cd desktop && node --test test/missions-locks.test.js` → all pass. Commit `Lock Run: the settings-and-locks game, Mac and Windows`.

### Task 3: The skin

**Files:** Create `desktop/renderer/missions/games/locks.css`.

- [ ] **Step 1:** Classes `.lk`, `.lk-row`, `.lk-pip(--here|--past)`, `.lk-coach`, `.lk-card`, `.lk-head`, `.lk-state(--open|--unknown)`, `.lk-facts`, `.lk-note(--fog|--key)`, `.lk-steps`, `.lk-ev`, `.lk-sum`; tokens from game.css `:host`; a ≤560px layout.
- [ ] **Step 2:** Commit `Lock Run: its skin`.

### Task 4: Verify

- [ ] **Step 1:** `cd desktop && npm test && npm run check-game-files` → green.
- [ ] **Step 2:** Preview HTML in the scratch folder (`missions-locks/`) loading `game.css` tokens + `locks.css`, rendering practice items and fixture items in standard and city modes, at default width and 800px; screenshot and look.
- [ ] **Step 3:** Report at `.superpowers/sdd/missions-locks-report.md` (main checkout).
