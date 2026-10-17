# Game mode B: one city

**Status:** draft, written 2026-10-16. Its direction ("one combined journey") was
chosen in brainstorming, but the details below weren't discussed section by
section. Review section 9 first.
**Part of:** [Consumer security game: overview](2026-10-16-consumer-security-game-overview.md)
**Depends on:** [Spec A: device missions](2026-10-16-game-mode-device-missions-design.md)
**Goal:** one map holds both the computer and the person's accounts. The device
districts come from the real scan, and Reclaim City's own districts (email,
finance, social, the Perimeter, the Grid…) come from the vendored game data. Where
a scan check can confirm one of the game's own missions, the game says so.

## Changes made during planning (2026-10-16)

Reading privacy-the-game at `317e61c` and this repo's modules showed that parts of
this draft were wrong. Where this section and the sections below disagree, this
section wins.

1. **The "Confirmed by your computer" table is smaller** (section 4).
   - `device_security-reclaim-app-permissions` has only phone steps (iPhone and
     Android), so a scan of this computer can't confirm any of them. That row is
     dropped.
   - `smart_network-reclaim-dns` has steps for phones, browsers and routers, plus
     a check on a website. The scan reads this computer's system DNS, and that
     matches none of those steps. That row is dropped.
   - `smart_network-recon-router` is narrowed to its "Disable UPnP" step only.
     `router_security_audit` never logs in to the router, so it can't see the
     admin password, WPS or firmware.
   - Rows map **steps**, not whole missions. Each step names the platforms it
     applies to, so the Windows BitLocker steps show "For Windows computers" on a
     Mac, never "confirmed".
   - The network modules emit findings with no `code`, so a row matches by
     module, optionally narrowed by `data.check` (`upnp_enabled`), and not by code.
2. **The link allowlist is built when the code is built, not when the app
   starts.** `desktop/scripts/build-mission-links.mjs` writes
   `desktop/mission-links.json`, which holds every `https://` URL found under a
   `url` key in `MISSIONS`, plus every account's `securityUrl`. A test fails if
   the file is out of date. `main.js` requires the JSON, so it never imports the
   game's ES modules from inside the asar. One step URL, `about:preferences#privacy`,
   isn't https. It's never allowed, and it's shown as text to copy.
3. **The game's HUD is swapped out.** Every vendored screen draws
   `components/hud.js`, and that file carries the Stripe and Patreon links. The
   `app://` protocol serves `rc/components/hud.js` from
   `renderer/game/rc-overrides/hud.js`, which draws nothing. Device Rescue's own
   HUD shows the two counts instead.
4. **Finishing a mission from the scan uses a normal answer.** The game's
   `debriefRecord` rejects values it doesn't know, so a `confirmed_by_scan` answer
   would be thrown away. Instead, the mission is filed with the mission's own
   "completed" option, and Device Rescue records that the scan confirmed it under
   its own key, `device-rescue.game.scan-confirmed.v1`. The counts read that key
   and check that the current scan still confirms it.
5. **Account content uses the vendored screens and a reimplementation of the
   game's click handling.**
   - Without the game's `app.js`, Device Rescue handles its `data-action`s itself
     (`renderer/game/rc-actions.js`), along with its `#/…` links and its debrief
     form.
   - Routes this spec doesn't include (garage, timeline, quizzes, Quick Quest,
     stats, ghost, city-together) go to the one-city map.
   - The milestone's share card is removed after rendering.
6. **The reachable game code is exactly 48 files**, listed in
   `desktop/rc-files.json`.
   - None of them calls `fetch`, `sendBeacon`, `XMLHttpRequest`, `WebSocket` or
     `new Image`, and none uses dynamic `import()`.
   - `Sentry` appears only in `utils/errors.js`, behind a
     `typeof Sentry === 'undefined'` guard, so it does nothing when the global
     isn't loaded.
   - Payment links appear only in `components/hud.js`.
   - A test walks the graph and keeps all of this true when the submodule is
     bumped.

## 1. Overview

Spec A gives a city made only of device districts. This spec loads Reclaim City's
real content (`DISTRICTS`, `ACCOUNTS`, `MISSIONS` from
`desktop/vendor/reclaim-city/src/data/`) into the same map. So someone who started
with "my computer is acting weird" can carry on into "and now lock down my email",
without leaving the app or sending anything anywhere.

There are two kinds of mission on one map, and they always look different:

| | Device missions (Spec A) | Account missions (Reclaim City) |
| --- | --- | --- |
| Source | The scan | Vendored game data |
| Done when | A re-check confirms it | The person files the debrief |
| Shown as | **"Confirmed by your computer"** | **"You reported this"** |

### Non-goals

- No changes to Reclaim City's mission content. It's shown exactly as the game
  ships it.
- No sync or import from the hosted game's save. The decision to confirm is in
  section 9.
- Not included: ghost mode, city-together, the collective stats, share cards, the
  garage and timeline screens, and the Stripe/Patreon links.

## 2. The map

- Device districts (Spec A) sit together as the first ring, **"Your computer"**.
- Reclaim City's districts follow in their own `chapter` order.
- The game's own unlocking and survey flow is used as it is. For example, a
  district with a `surveyQuestion` asks "Do you have a Gmail account?" before
  showing that building.
- The worry the person picked sets where the camera starts, using the same mapping
  as `LEARN_MORE` in `desktop/renderer/app.js`:
  - `hacked` → Master Keys
  - `identity` → Reclamation
  - anything else → "Your computer"

  Nothing is locked behind anything else.

## 3. Account missions

- They are rendered with the vendored `briefing.js` and `debrief.js`, using each
  mission's own `steps`, `debriefQs` and `scoutDialog`.
- State uses the vendored `state.js` (`loadState`, `updateMission`,
  `markMissionStarted`, `toggleAccount`) under its own key, `reclaim-city-state`.
  The vendored progress helpers (`calcDistrictProgress`, `calcIntegrity`) then work
  unchanged. `state.js` imports `utils/errors.js`, and that does nothing without
  the `Sentry` global (Spec A, section 8).
- **Links in steps.** A mission step's `url` (and an account's `securityUrl`) opens
  in the person's own browser through a new IPC channel, `open-mission-link`. The
  main process allows a URL only if it appears **exactly** in the vendored mission
  or account data at the pinned commit. At startup the main process builds that
  set with a dynamic `import()` of the data modules. The renderer can't open
  anything else, which matches how `setting-urls.js` uses exact allowlists today.
- "GO DO IT" / "I DID IT" behaves as it does in the hosted game. Completion is
  self-reported, and is labeled that way everywhere it's counted.

## 4. Confirmed by your computer

Some Reclaim City missions are about the computer itself. A mapping table,
`desktop/renderer/game/verified-missions.js`, links them to scan checks:

| Game mission | Steps the scan can confirm | Checks |
| --- | --- | --- |
| `device_security-fortify-computer` (Harden Your Computer) | disk encryption; password on wake; Find My | `encryption_check`, `filevault_recovery`, `win_bitlocker_check`, `linux_disk_encryption_check`; `screen_lock_check`, `lock_screen_check`; `find_my_mac_check` |
| `device_security-reclaim-app-permissions` (App Permission Audit) | apps with camera, microphone or screen access on this computer | `privacy_permissions_audit`, `app_permissions`, `accessibility_permissions` |
| `smart_network-recon-router` (the Grid's router mission) | router settings visible from this computer | `router_security_audit`, `wifi_security_audit` |
| `smart_network-reclaim-dns` (encrypted DNS) | encrypted DNS on this computer | `dns_over_https_check`, `dns_config`, `win_dns_config` |

The plan confirms each module name and finding code against `modules/` and the
remediation catalog, and drops any row it can't back up.

**Rules:**

1. A step is **confirmed** only when its checks ran (`supported: true`,
   `status: "ok"`) and reported no warning or critical finding for the mapped
   codes. A check that couldn't run leaves the step unconfirmed, labeled "Couldn't
   check this one", never shown as confirmed.
2. When a mapped check finds a problem, the game mission's briefing shows it and
   links to the matching device mission ("Your computer says disk encryption is
   off. Fix it here →").
3. Steps the scan can't see, such as the phone steps in "Harden Your Computer",
   stay self-reported. The briefing marks each step as confirmed, a problem found,
   or yours to check.
4. **The person's answer is never overwritten.** If they filed "Done" and the scan
   disagrees, both are shown: "You reported this done. Your computer still shows:
   FileVault is off." The mission's status in the game state stays theirs. The
   building gets a "check again" marker.
5. A mission whose every step is confirmed can be finished from the confirmation
   alone. It is filed with a single debrief answer, `confirmed_by_scan`, which is
   kept separate from the game's own answer values.

## 5. Counting progress honestly

- The HUD shows two counts, never one: **"Confirmed: 7"** and **"You reported:
  12"**.
- A district milestone needs every device mission reclaimed or yours, and every
  account mission filed.
- The milestone screen lists the confirmed missions separately from the reported
  ones.
- `yours` (Spec A) is still never counted as fixed.

## 6. Safety

- The same gate as Spec A. Account missions change account settings, and that can
  alert someone who is watching. That's the reason `learnMoreFor` already
  withholds the game, and this spec keeps it.
- The gate is checked again on every full scan. If a later scan finds monitoring
  software, the city closes. The person sees the list view with its safety note,
  and their saved progress is kept but not shown.

## 7. Error handling

| Failure | Behaviour |
| --- | --- |
| A vendored data module fails to import | Show the device districts only, with "Your accounts' districts couldn't load." |
| `open-mission-link` refused | Nothing opens. The step shows its URL as text the person can copy. Logged to the console. |
| `reclaim-city-state` is corrupt | The vendored `loadState` already rebuilds from defaults. Device progress (`device-rescue.game.v1`) isn't affected. |
| A mapping row names a module that's missing on this platform | That step is labeled "yours to check", never confirmed. |

## 8. Testing

- `game-verified-missions.test.js`:
  - every mapped mission id exists in the vendored `MISSIONS`
  - every mapped module exists in `modules/`
  - every mapped code exists in the remediation catalog index
  - confirmed only when every check ran and found nothing
  - `supported: false` never confirms
  - a disagreement shows both answers and never changes the game state
- `game-mission-links.test.js`: the allowlist is built from vendored data. An exact
  URL is allowed. These are refused: a look-alike host, an extra path, a query
  string that's been added, and the `javascript:` and `file:` schemes.
- `game-progress-counts.test.js`: confirmed and reported are counted separately,
  `yours` is excluded, and the milestone needs both kinds complete.
- `game-gate.test.js`, extended: the city closes when a later scan finds monitoring
  software.
- The Spec A vendor contract test is extended to render a district from the
  vendored data, with a survey question and a facility district.

## 9. Decisions to confirm

1. **"Your computer" as the first ring.** The alternative is to put the device
   districts inside the Perimeter, next to "Harden Your Computer".
2. **No import from the hosted game.** People who already play on the web start
   fresh in the app. A later spec could add a local file export/import, using the
   game's existing restore format.
3. **The mapping table lives in Device Rescue, not the game.** That keeps the game
   untouched. The cost is that renaming a mission upstream breaks a row, and the
   test catches it when the submodule is bumped.
4. **Including the phishing quiz and Quick Quests.** They're local and cheap to
   include. This draft leaves them to Spec C.
