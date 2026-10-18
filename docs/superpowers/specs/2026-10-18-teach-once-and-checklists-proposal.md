# Teach once, and checklists everywhere: proposal

Status: proposal, read-only survey. Nothing here is built. Written 2026-10-18
from `main` (63bb48d) plus the two branches about to merge: `command-center`
(`.worktrees/cc`, d0cee2f) and `reclaim-city` (`.worktrees/rc`, e146625; rc-t4 merged since as 06f2664, so **[rc]** line numbers may drift).
File and line references are to `main` unless marked **[cc]** or **[rc]**.

## The feedback

> "There is a lot of text. Most of that text belongs in a lesson so that people
> can learn the stuff and not have to repeat it, and so that the UI is not just
> plastered with text. Also basically everywhere there's a list, there should be
> checkboxes and things should be individually addressable."

Two changes follow from it:

1. **Teach once.** An explanation the person has already read, or one that
   repeats on card after card, becomes one short line with a way into a lesson.
   The engine's long text stays reachable behind "More". Evidence and the
   monitoring-software warning are never shortened.
2. **Checklists.** Every list whose items can be acted on gets real checkboxes,
   a count, select all / none, and one action button that says what it will do
   and to how many items. Each item can also be acted on alone. The engine
   gets per-item marks so "these 3 of 7 apps are mine" is possible.

---

## Part 1: text that belongs in lessons

### 1.1 How much text a real scan produces

One full `rescue scan --json` on the owner's Mac (196 checks, 5 couldn't run):

| | Cards | Description words | Notes |
|---|---|---|---|
| Critical + warning | 108 (7 + 101) | 7,954 (avg 74) | first paragraph 3,938; "What to do:" paragraphs 3,088; other paragraphs 528; hotline paragraphs 400 |
| Info ("Good to know") | 382 | 9,155 (avg 24) | rendered as full cards, open, today |
| Walkthrough steps on crit/warn cards | 44 cards | titles 396, bodies 7,241 | bodies sit behind "Show me how" |
| `safety_note` on crit/warn cards | 21 | 45 each = 945 | `rescue/serialize.py:31` |
| "Made by" lines (evidence) | 17 cards | 538 | plus an 84-word explainer per card, collapsed |
| "What to do:" paragraph **and** walkthrough steps on the same card | 44 | 1,285 | the same advice twice |

The most repeated paragraph in the whole scan is the advocate sentence ("If you
think someone close to you set this up to monitor you, removing it can alert
them…"), 11 times. The scan comes from a developer machine, so it has more
than most; the per-card numbers are what carry over.

### 1.2 Inventory of surfaces that explain things

Word counts are visible words without opening anything, unless the row says
"when opened".

| Surface | Where | Explanatory text | Words |
|---|---|---|---|
| Welcome | `desktop/renderer/index.html:31-58` | intro, "Read-only by default", two route cards | ~95 |
| Worry screen | `app.js:29-54` (`SITUATIONS`), `index.html:66` | 8 titles + sub-lines | ~110 |
| The one question **[rc]** | `first-question.js:12-48` | question + note | ~45 |
| Scan screen | `index.html:86-91`; tips `permissions-content.json` via `app.js:579-609` | "look-around" intro; macOS pop-up tips (4 shown) | ~40 + ~190 |
| Results header | `index.html:123-127`; `clear-list.js:63-100` | "guidance, not action"; summary; progress detail ("Answer each card below as you go…") | ~28 + ~15 + 24 |
| Severity groups | `app.js:18-22`, `app.js:757-767` | one description per group | ~10 each |
| Finding card: description | `app.js:174-187`, `app.js:721` | engine text; first paragraph, middle paragraphs, "What to do:" | avg 74 (crit/warn), 24 (info) |
| Finding card: made by | `app.js:151-163` | evidence lines (keep) + "What does this mean?" explainer | 538 total + 84 per card when opened |
| Finding card: safety note | `app.js:322-326` from `serialize.py:31-36`; **[rc]** replaced by `quiet-notes.js:21-22,149` | advocate + hotline | 45 per card (main); **[rc]** only on monitoring findings, as one line |
| Finding card: "I did this" hint | `clear-list.js:141-144` | "For this checkup only. Nothing is changed or saved." | 9 × 108 cards |
| Finding card: What to do | `app.js:729-733` | walkthrough step titles | 396 total |
| Finding card: step by step | `app.js:735-745` | full walkthrough bodies (`guides/remediation/*.md`) | 7,241 total, when opened |
| Finding card: Open in System Settings | `setting-panes.js` | "You make the change there." | ~10 |
| Fix panel | `fix-flow.js:55-82` | engine `will_change` (~25), `how_to_undo` (~35), "Nothing else…" (8), city-mode warning (24) | ~70-95 when opened |
| Fix result | `fix-flow.js:86-141` | headline + detail + undo list again | ~15-60 |
| "It's mine" panel | `mark-flow.js:251-274`; engine `known_items.py:88-104,1048-1056` | what you are saying is yours (evidence), `will_change` (~55), covers line (15), undo (~25), `ONLY_IF_YOURS` (18), `COULD_WATCH` (18), `LIST_REASON` (16), `NOT_SURE_LIST` (11), "Nothing on your computer is changed" (9) | ~150-170 when opened |
| "It's mine" result | `mark-flow.js:289-342` | "This is remembered: from your next checkup…" + undo | ~19-45 |
| Marked finding (next scan) | `known_items.py:1133-1143` | `marked_description`: 60 words **plus the whole original description again** | 60 + original |
| Mark changed since | `known_items.py:1146-1157` | `stale_sentence` | ~35 |
| Cleared section | `clear-list.js:147-156`, notes `103-109` | intro + one note per cleared card | 28 + 16-19 each |
| What to do next | `index.html:137-144` | guide link text; **[rc]** reminder line removed | ~20 |
| Couldn't check these | `index.html:146-150`, `app.js:811-824` | why it isn't a clean bill of health | ~25 + one line per check |
| Ask your own AI / Copy for any AI | `index.html:153-157`; `copy-ai.js:5-8`; `ask.js:6-19` | what is blanked out, read it first | ~30; 46 / ~40 when opened |
| Learn properly (web game) | `app.js:215-225`, `index.html:160-164` | per-worry pitch | ~45 |
| Technical report | `index.html:167-171` | "Nothing is blanked out here…" | ~25 |
| Game: sweep (boss) | `game/views/boss.js:27-51` | Scout line + the same pop-up tips | ~25 + ~190 |
| Game: map / district | `game/scout-lines.js:4-7`, `game/views/district.js:34-38` | Scout line, district line, "That doesn't mean it's safe." | ~20-40 |
| Game: briefing | `game/views/briefing.js:4-35` | full description, every step **with its full body**, safety note, Scout line, "learned" link | description + step bodies (often 200+) |
| Game: outcome / verification | `game/views/outcome.js`, `game/views/verification.js:37-65` | Scout lines, per-step "couldn't check" | ~15-40 |
| Game: lesson | `game/views/lesson.js` | the lesson itself | (this is where text belongs) |
| **[cc]** Signal or Noise | `game/views/signal.js:7-66`; `game/clues.js:55-73` | per opened clue a "How to read this:" line (20-30 words, up to 4 per signal); `TAG_NOTE` (11); MARKED / CHANGED notes (~15 each); "OPTIONAL: TELL DEVICE RESCUE TOO" (35); Scout's read (~30) | ~80-200 per signal |
| **[cc]** Deck | `game/views/deck.js:64-94` | clear board (30), nothing checked (20), low-priority notes (~25), threat-board note (12), ops log empty (10) | ~20-100 |
| **[cc]** Drill range | `game/views/signal.js:23-24,63,77` | DRILL banner, practice notes | ~20 |

### 1.3 Concepts that repeat

Each row is one idea that is explained in more than one place. "Lesson" says
whether a lesson in `desktop/renderer/game/lessons/` already teaches it.

| # | Concept | Where it appears today | Words repeated | Lesson today |
|---|---|---|---|---|
| C1 | **Who made it: verified signature vs unknown maker** | made-by explainer `app.js:159-162` (84, once per card with a maker); `MADE_BY_REASON` `app.js:101-112` (short, evidence-like); **[cc]** `clues.js:56-61` `READING.verified/unverified/apple` (~25 per maker clue); `mark-flow.js:189-192` | ~84 per card + ~25 per clue | Partly: `starts-on-its-own` Q2 ("tells you who made it, not that you wanted it"). Missing: "unknown maker isn't proof", "part of macOS". |
| C2 | **Where it lives: temporary / hidden / Downloads folders** | engine `location_note` (`rescue/attribution.py`) on made-by lines; **[cc]** `clues.js:13-53` place notes + `READING.place` (~30); `launch_agent_audit` / `launchd_persistence_audit` descriptions | ~30 per clue, plus inside descriptions | Yes: `starts-on-its-own` Q1. |
| C3 | **Things that start on their own** (launch agents/daemons, login items, autoruns, cron) | descriptions of `launch_agent_audit`, `launchd_persistence_audit`, `startup_optimizer`, `login_items_cleanup`, `cron_jobs_audit`, `win_autoruns_audit`; walkthrough intros (`review_launch_persistence.md`) | 30-60 per card | Yes: `starts-on-its-own`. |
| C4 | **Removing monitoring software can alert whoever installed it** | `serialize.py:31-36` `SAFETY_NOTE` (45, 21 cards here; 33 walkthroughs set `monitoring_risk: true`); advocate paragraphs inside 34 modules' descriptions (~40 each); `index.html:77-84` scan banner and `index.html:140-142` reminder (main; removed **[rc]**); `fix-flow.js:18` `WATCHED_WARNING` (24); `mark-flow.js:20-21`; **[rc]** `quiet-notes.js:21-22` | 45 per card on main; **[rc]** one line on monitoring findings only | No lesson, and see the hard rule: it is **never** shortened. `whos-on-wifi` Q4 touches it ("Cutting off someone's access tells them"). |
| C5 | **What "marked as yours" does** (still listed, warning comes back if it changes, undo) | engine `will_change` `known_items.py:88-95` and `1048-1056` (~55 each open); `MARK_HOW_TO_UNDO` `:100-103` (~25); `marked_description` `:1133-1143` (60 + whole original); `stale_sentence` `:1146-1157` (~35); `mark-flow.js:289-342` result texts (19-25); `clear-list.js:105-106,152` (16-28); **[cc]** `signal.js:26,47-48` (15 + 35); `scout-lines.js:18` | ~130-200 per marked item across its life | None. |
| C6 | **Three ways to clear a card** ("I did this" is this checkup only; "It's mine" is remembered; "Fixed" was changed and checked again) | `clear-list.js:84` progress detail (24), `:143` hint (9 × every card), `:152` Cleared intro (28), `:103-109` notes | ~1,000 per results screen (hint alone: 972 here) | None. |
| C7 | **Looking changes nothing; a change only happens when you say yes** | `index.html:40-41` (17), `:87-90` (25), `:125-127` (28); `fix-flow.js:74` (8); `mark-flow.js:267` (9); `clear-list.js:143`; `scout-lines.js:12`; **[cc]** `signal.js:7,63` (11), `deck.js:85` (12), drill notes (~10) | ~150 per session, 8-12 per panel | None (true everywhere; short). |
| C8 | **How a fix works and how undo works** (moved to quarantine, nothing deleted, Undo button, manual undo) | `rescue/app_fixes.json` `will_change` + `how_to_undo` (~60, shown in the panel and again in the result); `fix-flow.js:93,112,148`; `scout-lines.js:21` | ~60-120 per fix | Partly: `starts-on-its-own` Q3 feedback (quarantine, undo). |
| C9 | **"Couldn't check" doesn't mean clean** | `index.html:148`; `clear-list.js:65-67`; `district.js:36`; `outcome.js:50`; `verification.js:38`; `scout-lines.js:6,15`; **[cc]** `clues.js:73`, `signal.js:33`, `deck.js:67` | 15-25 each, 5-9 places | Yes: `couldnt-check` Q1. |
| C10 | **A clean result lowers the odds; it can't rule a problem out** | `clear-list.js:76`; `scout-lines.js:4,6`; **[cc]** `deck.js:71` | ~12-30 each | Yes: `couldnt-check` Q2. |
| C11 | **What a proxy is** | `network_proxy`, `network_proxy_detect` descriptions; `remove_unwanted_proxy.md`; `mark-flow.js:21` `COULD_WATCH` | ~40-60 per card | None. |
| C12 | **FileVault / BitLocker (disk encryption) and the recovery key** | `encryption_check`, `filevault_recovery`, `win_bitlocker_check` descriptions; `secure_filevault_recovery.md` | ~40-60 per card | Yes: `locked-door` Q3-Q4. |
| C13 | **Automatic updates** | `automatic_updates`, `update_checker` descriptions | ~30-50 per card (6 codes) | Yes: `locked-door` Q1-Q2. |
| C14 | **Lock screen delay** | `lock_screen_check`, `screen_lock_check` | ~30 per card (6 codes) | Yes: `locked-door` Q5. |
| C15 | **Browser extensions and their permissions** | `browser_extension_audit`, `chrome_extensions`, `safari_extensions`; four repeated "What to do: Go to chrome://extensions…" paragraphs in this scan | ~40-60 per extension card | Yes: `browser-add-ons`. |
| C16 | **App permission lists** (Accessibility, Screen Recording, Camera, Microphone, Full Disk Access) | `app_permissions`, `privacy_permissions_audit`, `accessibility_permissions` descriptions; `mark-flow.js:21-24` (`COULD_WATCH`, `LIST_REASON`, `NOT_SURE_LIST`); `review_app_permissions.md`, `review_accessibility_grants.md` | ~60-90 per card | None. |
| C17 | **Sharing and remote login** (Screen Sharing, Remote Login, remote-login keys) | `sharing_services`, `sharing_preferences_audit`, `remote_login_check`, `session_revocation_scan`, `ssh_key_audit`; `review_sharing_services.md` | ~40-60 per card | Partly: `password-asker` covers Windows remote-access tools only. |
| C18 | **What gets blanked out before you share** (Copy for any AI, Ask about this, technical report) | `copy-ai.js:5-8` (46), `ask.js:7-10` (~40), `index.html:154,168` (~55) | ~140 per session | None. Consent text: see open questions. |
| C19 | **Pop-ups during the checkup; this app never asks for a password** | `permissions-content.json` (macOS ~190, Windows ~150); shown on the scan screen and the sweep | ~190 each time a scan runs | Partly: `password-asker` Q2 (admin prompt). |
| C20 | **[cc] Game tags only sort the game** | `signal.js:7,63`, `deck.js:85`, `signal.js:47-48` | ~11-35 per signal | None (game-only). |
| C21 | **[cc] How to read a clue** | `clues.js:55-70` `READING.*`, one per opened clue | 20-30 × up to 4 per signal | Spread over C1, C2. |
| C22 | Who's on your Wi-Fi, crypto mining | `lan_device_inventory`, `crypto_miner_detect`, router checks | ~40 per card | Yes: `whos-on-wifi`. |
| C23 | Poisoned developer packages | `ai_worm_*` modules | ~40-80 per card | Yes: `poisoned-packages`. |

Concepts the lessons already cover: C2, C3, C9, C10, C12-C15, C22, C23, and
part of C1, C8, C17, C19. Concepts with no lesson: C5, C6, C7, C11, C16, C18,
C20, C21, and C4, which is deliberately not a teach-once concept.

### 1.4 The teach-once pattern

#### One registry, both modes

A new plain script, `desktop/renderer/concepts.js` (global `Concepts`, also on
`window` for the game's ES modules, the way `FixFlow` and `QuietNotes` are
exposed). Each entry:

```js
{
  id: 'who-made-it',          // disk-safe: must not match FORBIDDEN_ON_DISK (desktop/test/disk-words.js)
  short: 'A verified signature tells you who made it, not that you wanted it.',
  lesson: 'who-made-it',      // a lesson id in game/lessons/, or null
  sources: ['desktop/renderer/app.js'],   // the short line is checked like lesson text
  applies: { codes: [...], modules: [...], madeBy: true, markKinds: [...], clue: 'maker' },
  remember: true,             // false: learned state lives in memory only (see stealth)
  neverShorten: false,        // true for C4: the pattern does not apply at all
}
```

`Concepts.forFinding(finding)` returns the concept ids that apply to a card,
from its `code`, `module`, `made_by`, `markable.kind` and `fixable`. The match
lives in the renderer first (no engine change). Later the engine can emit
`concepts: [...]` itself (section 1.6).

#### What a card shows

| State of the concept | On the first card it applies to, this screen | On later cards, this screen |
|---|---|---|
| Not learned | the short line, then **Learn this (2 questions)**, then **More** (the engine's long paragraph for this card) | a small **?** that opens the same short line, Learn this, and More |
| Learned | the short line with a small **?** (opens the lesson again) and **More** | the **?** only |

- "More" is a `<details>` holding the description paragraphs the card no
  longer shows inline, word for word. Nothing the engine wrote is deleted.
- **Label wording.** The ask was "Learn this (1 min)". The lesson accuracy gate
  (`desktop/test/game-lessons.test.js:105-114`, `training.js:25`
  `TIME_WORDS`) bans time words in lessons, and the project avoids time
  promises. Proposal: say the size instead, "Learn this (2 questions)". Owner
  decides (open question 1).
- **One per screen.** A concept is spelled out at most once per rendered
  results list, briefing or signal. The "?" carries it everywhere else.
- **Panels too.** The fix and "It's mine" panels keep everything that is
  specific to this item (what you are saying is yours, this fix's
  `will_change`, the first undo step) and replace the generic sentences with a
  concept line: C5 in the mark panel, C8 in the fix panel, C16 or C17 for the
  "why we ask" lines. The second undo step and the general rules go under
  "More".
- **Game mode.** The same entries render in the game's style: in a briefing,
  a "WHAT IT IS" panel gets the short line plus `LEARN ▶` / `?`; in **[cc]**
  Signal or Noise, each clue's "How to read this:" line is the concept's short
  line the first time that clue kind is opened this session and a `?` after
  that, or right away if the lesson is done. The briefing already links a
  finished lesson (`briefing.js:23`, `training.js:55-57`
  `lessonForModule`); this generalises that link.
- **Plain view gets lessons.** Today only game mode can open a lesson. Add a
  small lesson host for plain view (`desktop/renderer/lesson-host.js`) that
  loads the same lesson file with `import()` and shows it in a dialog with
  plain-view styling, reusing `game/views/lesson.js` markup rules. Finishing it
  calls the same `setLessonDone`.

#### What is never hidden or shortened

1. **The monitoring-software line.** On a finding from `stalkerware_scan`,
   `mvt_spyware_scan` or `keylogger_indicators`, **"Removing this can alert
   whoever installed it. Read this first."** (`quiet-notes.js:21` **[rc]**)
   always shows in full, in every mode, with the full note behind it, however
   many times the person has seen it. C4 has `neverShorten: true`; the
   registry test fails if any rule ever turns it into a "?". In city (stealth)
   mode the same holds wherever a monitoring finding appears.
2. **Evidence.** Titles, names, paths, counts, versions, the made-by line
   itself ("Made by Google LLC (verified signature)"), "What you are saying is
   yours" rows, and the `data.marked_by_user` / `mark_stale` notes. Teach-once
   only moves *explanations*.
3. **Consent text that is specific to this item.** A fix's `will_change`, a
   mark's own target, and the first way to undo stay in the panel. The strong
   confirmation `ONLY_IF_YOURS` stays whenever `needsStrongConfirm` is true
   (`mark-flow.js:128-132`). The city-mode fix warning (`fix-flow.js:18`)
   stays.
4. **Severity and status.** Chips, "couldn't check" names, the progress count,
   the critical "a mark does not quiet it" sentence (`known_items.py:1246-1252`).
5. **The text the person is about to send** in Copy for any AI and Ask about
   this. The intro sentence may shrink (C18); the preview never does.
6. **[cc]** The DRILL stamp ("Practice. This isn't on your computer.").

#### Where "learned" lives

- **Done = lesson done.** A concept counts as learned when its lesson is done:
  `lessonDone(progress, lessonId)` (`game/progress.js:117-119`), stored in
  the existing progress store (`device-rescue.game.v1`, `lessons[id] =
  {completedAt}`). No new field: `base()` in `progress.js` (v2 on main,
  v3 **[cc]** `progress.js:120-127`) rebuilds the document from known fields
  only, so a new top-level field would be dropped on the next save. Every
  concept that should be "learnable" therefore gets a lesson, even a
  one-question one.
- **"I know this already."** A second button next to Learn this marks the
  lesson done without the quiz: `lessons[id] = {completedAt, how: 'skipped'}`.
  `validLessons` checks only `completedAt`, so this loads on main and **[cc]**.
- **One writer.** Plain view (`app.js`, a classic script) needs to read and
  write the same key. Move `loadProgress` / `saveProgress` / `setLessonDone`
  behind one tiny classic-script module (`desktop/renderer/learned.js`) that
  both the game's `progress.js` and `app.js` call, so the two never write
  different shapes. It must do read-modify-write of the whole document through
  `migrate()`, so plain view never drops the game's missions or deck.
- **Per-screen "shown already"** (which card got the spelled-out line) is
  render-local and never stored.

#### Stealth mode

**[rc]** stealth mode is the `city` display preference. Nothing on disk may
reveal safety-related learning (`desktop/test/disk-words.js`,
`FORBIDDEN_ON_DISK`).

- Concept and lesson ids that are written must not match
  `FORBIDDEN_ON_DISK` (`partner|safety|stealth|safe|stalk|watch|abuse|violence|advocate|hotline|monitor|spy|…`).
  For example `app-permission-lists`, not `apps-that-can-watch`. A registry test
  runs every `remember: true` id and every lesson id through
  `FORBIDDEN_ON_DISK`.
- Concepts that are about safety (C4, and anything taught inside the help
  district **[rc spec §4]**) are `remember: false`. Their learned state is a
  `Set` in memory, like `monitoringSeen` (`app.js:493-495`), gone when the
  app closes. A test drives every safety concept through Learn this and
  "I know this" with a recording store and asserts zero writes
  (`recordingStore` / `forbiddenWrites` in `disk-words.js`).
- C4 is `neverShorten`, so its "learned" state changes nothing anyway; the
  memory-only rule is there so a future edit can't start storing it.
- `whos-on-wifi` already contains a safety teach (Q4). Its id is neutral and
  only `{completedAt}` is stored, which is fine; the help-district lessons
  should follow the same rule: neutral id, or memory only.

#### Lessons stay accurate

Every new lesson goes through the existing gate
(`desktop/test/game-lessons.test.js`): sources that exist, UI paths and
backticked text word for word in a source, no diagnosis phrases, no time
words, 1-5 questions with exactly one right answer and feedback on every
option, a district when it teaches modules. The registry's `short` lines get
the same `unsourced()` check (extend the test, or export `unsourced` and
reuse it in `desktop/test/concepts.test.js`).

New lessons this needs (each 1-3 questions):

| Lesson id | Concepts | Sources to cite |
|---|---|---|
| `who-made-it` (or extend `starts-on-its-own`) | C1, C21 (maker) | `desktop/renderer/app.js`, `rescue/attribution.py` |
| `its-mine` | C5, C6 | `rescue/known_items.py`, `desktop/renderer/mark-flow.js`, `desktop/renderer/clear-list.js` |
| `fix-and-undo` | C7, C8 | `rescue/app_fixes.json`, `desktop/renderer/fix-flow.js` |
| `app-permission-lists` | C16 | `guides/remediation/review_app_permissions.md`, `review_accessibility_grants.md` |
| `sharing-and-remote-login` | C17 | `guides/remediation/review_sharing_services.md`, `harden_ssh_keys.md` |
| `proxies` | C11 | `guides/remediation/remove_unwanted_proxy.md` |
| `before-you-share` | C18 | `desktop/renderer/copy-ai.js`, `desktop/ask-about.js`, `docs/trust-and-safety.md` |
| `reading-the-deck` **[cc]** | C20, C21 | `desktop/renderer/game/clues.js`, `views/signal.js` |

C19 (pop-ups) stays as a list on the scan screen, collapsed after the first
scan of the session; `password-asker` already teaches the important half.

### 1.5 Word reduction on a typical results screen

Visible words on the results screen without opening anything, for the scan
above. "Typical" here means this scan; a family laptop has fewer cards, but
the per-card numbers drive the ratio.

| Part | Before (main) | Before (**[rc]**, standard) | After |
|---|---|---|---|
| Crit/warn first paragraphs (evidence + some explanation) | 3,938 | 3,938 | 3,938 now; ~2,600 once the engine has `summary` (1.6) |
| "What to do:" paragraphs on cards that also have walkthrough steps | 1,285 | 1,285 | 0 (behind More; the step titles say it) |
| "What to do:" paragraphs on cards without steps | 1,803 | 1,803 | 1,803 |
| Other explanatory paragraphs | 528 | 528 | 0 (behind More) |
| Advocate paragraphs and `safety_note` | 400 + 945 | ~0 (monitoring line only) | ~0 (monitoring line only) |
| "I did this" hint on every card | 972 | 972 | ~10 (once, at the top) |
| Step titles ("What to do" list) | 396 | 396 | 396 |
| Made-by lines | 538 | 538 | 538 |
| Concept short lines | 0 | 0 | ~200 first visit; ~0 once learned |
| Info cards (382, open, full text) | 9,155 | 9,155 | ~10 ("382 good-to-know notes", a collapsed checklist of titles) |
| Page chrome and per-card button labels | ~1,700 | ~1,650 | ~700 |
| **Total** | **~21,700** | **~20,300** | **~7,600 now, ~6,300 with engine summaries** |

About a 65-70% cut. Most of it is not new writing: collapsing info, dropping
the duplicated "What to do:" paragraph, and saying the clearing rules once.
The concept lines do the rest.

### 1.6 Engine changes for Part 1 (optional, later)

The renderer can do everything above alone. Two engine additions make it
better, one module at a time:

- `Finding.summary` (optional): one sentence with the evidence ("3 apps have
  Accessibility access: …"). The card shows `summary` and puts the full
  description under More. Without it, the first paragraph is used, as today.
  Each module edited needs the integrity manifest regenerated, or CI fails.
- `concepts: [ids]` in the JSON, from a code→concept table next to
  `rescue/remediation.py`, so `rescue scan --json`, `rescue export` and AI
  assistants (AGENTS.md) can say "see the lesson on X" too. The renderer
  registry then only checks that the ids exist.

Neither changes `marked_description` on its own; that one should stop
repeating the whole original description inline (`known_items.py:1142`) and
keep it under a heading the app can put behind More. That changes text in
`rescue export`, so it's an owner call (open question 6).

---

## Part 2: checkboxes and individually addressable items

### 2.1 Inventory of lists

| # | List | Where | Each item on its own today? | Per-item actions that make sense | Bulk (checkbox) actions that make sense |
|---|---|---|---|---|---|
| L1 | Findings, "Needs attention now" / "Worth a look" | `app.js:696-767` | Yes: I did this, It's mine, Fix it for me, Ask, Copy for any AI, step by step | all of those | **I've looked at these** (warnings only; criticals with no steps can't be cleared by a look, `clear-list.js:129-136`); **Copy selected for any AI**; **Fix selected** only where every ticked card has the same engine action (today: `disable_launch_agent`), each with its own confirmation row and Undo |
| L2 | Findings, "Good to know" (info) | `app.js:696-767` | Ask, Copy only | look closer (open the card), copy | **Copy selected for any AI**; nothing else (they're not on the list) |
| L3 | Cleared | `clear-list.js:147-156` | Undo per card | undo, show details | **Put selected back** (rare; low priority) |
| L4 | Couldn't check these | `index.html:146-150`, `app.js:811-824` | No | open the setting it needs (e.g. Full Disk Access, `setting-panes.js:34`), check this one again | **Check selected again** (`recheck-module` IPC already exists, `desktop/main.js:66`, `desktop/recheck.js`) |
| L5 | Made-by lines on a card | `app.js:151-163` | No | copy the path | none |
| L6 | "It's mine" app list (apps with a permission) | `mark-flow.js:203-223` | **No: the whole list or nothing** (`NOT_SURE_LIST`: "Not sure about one? Leave the whole list as it is.") | mark one app as mine; open the permission page | **Mark the ticked apps as mine** (needs engine per-item marks, 2.3) |
| L7 | Lists inside a finding's `data` | shown only as JSON in Technical details (`app.js:748-751`) | No | depends on the list, below | depends on the list, below |
| L7a | apps per permission (`app_permissions`, `privacy_permissions_audit`, `accessibility_permissions`; 14, 11, 7 apps on warnings here) | engine `data.apps` | via L6 only, whole list | mark mine, open the permission page | mark ticked as mine |
| L7b | startup items (`startup_optimizer` 32 on a warning; `login_items_cleanup` 5 on a warning, 40 on info) | `data.items` (startup_optimizer items carry `plist`, `program`, `label`) | No | **turn this one off** (per-item `disable_launch_agent` is possible: items carry `plist`), mark mine, open Login Items | **Turn off ticked**; mark ticked as mine |
| L7c | browser extensions | one finding per extension already | yes (per card) | mark mine, open the browser's extension page | via L1 |
| L7d | proxies (`data.proxy_servers` on one interface) | `network_proxy` | whole setting | mark mine (the setting), open Network | none: one setting |
| L7e | remote-login keys (`session_revocation_scan`: count + hash only; `ssh_key_audit` lists 8 keys on info) | `data.key_count`, `data.list_sha256` | whole list | mark one key as mine | mark ticked as mine (needs per-key fingerprints, 2.3) |
| L7f | packages to update (`update_checker` 199), Wi-Fi networks (197), devices, ports, connections | `data.*` | No | copy | copy selected; nothing that changes the computer |
| L8 | "What to do" step titles and step-by-step walkthrough | `app.js:729-745`; game `briefing.js:5-7` | No | **tick a step as done** (this checkup only, like "I did this") | when every step is ticked, the card offers "I did this" as the next button |
| L9 | Fix and mark undo steps | `fix-flow.js:40-42`, `mark-flow.js:150-152` | n/a (instructions) | none | none: keep as a numbered list |
| L10 | Pop-ups you might see | `app.js:579-609`; game `boss.js:36-38` | Open setting button | open the setting | none |
| L11 | Worries | `app.js:611-641` | single choice | pick one | none (it's a choice, not a checklist; see open question 8) |
| L12 | Game: district missions | `game/views/district.js:12-26` | opens briefing | open, later | **Later for ticked** (low priority) |
| L13 | Game: district notes, fog, "also reported as" | `district.js:27-37`, `briefing.js:8-9` | No | open the note | none |
| L14 | Game: verification steps | `game/views/verification.js:33-45` | per-step status | report a step done | none (the computer vouches, or the person does per step) |
| L15 | **[cc]** Incoming signals | `views/deck.js:22-34,101-103` | opens Signal or Noise | investigate | none: sorting one at a time is the game |
| L16 | **[cc]** Low-priority signals | `views/deck.js:74-81`; `controller.js:409-419` `batchFine` | **all or nothing** ("THESE ARE ALL FINE") | open | **Sort ticked as fine** (default all ticked; unticked stay in the queue). Still no points |
| L17 | **[cc]** Threat board | `views/deck.js:82-85` | next move per item | see the fix / steps | **Copy selected for any AI** |
| L18 | **[cc]** Known and noted | `views/deck.js:86-89` | opens signal | open | **Put ticked back in the queue** (clears the game tag, never an engine mark) |
| L19 | **[cc]** Ops log | `views/deck.js:90-94` | No | none | none |
| L20 | Training lessons list | `game/views/training.js` | open | open | none |
| L21 | Whole-report copy and technical report | `index.html:152-171` | whole report only | n/a | replaced by "Copy selected for any AI" on L1/L2; the whole-report buttons stay |

### 2.2 Per-item versus bulk: the rules

- **Selection never changes anything.** Ticking is in memory only, never
  stored (so stealth mode has nothing to leak), and the primary button only
  opens a confirmation.
- **A bulk confirmation lists every ticked item**, with its evidence, and says
  what will happen to each. It is one answer about named items, not a blanket
  "yes to all". Items that need the strong confirmation
  (`needsStrongConfirm`) show `ONLY_IF_YOURS` once at the top.
- **Bulk "It's mine" stays inside one finding's list** (apps under one
  permission, keys in one file, startup items in one finding). Across findings
  it's one card at a time, as today. Monitoring checks never offer it
  (`NEVER_MARKABLE_MODULES`, in three places already).
- **Bulk fix** runs one engine call per item, in order, each confirmed by the
  engine checking again, each with its own Undo. The status says "Turned off
  4 of 5. One didn't go through: …". The main process keeps allowing only
  action+target pairs the scan offered (`fix-policy.js:44-73`).
- **Game tags are not engine marks.** Bulk tagging stays game-only and
  pointless for points, as `batchFine` already is.

### 2.3 Engine support for marking a subset

#### What exists

- `rescue known add --code C --expect-id ID [--code C2 --expect-id ID2 …]`
  for settings and installed items (`rescue/cli.py:696-718, 821-919`), and
  `--label/--program/--plist` for background tasks. The id is a 12-hex hash of
  the kind and identity (`known_items.py:136-139`).
- A list of apps is one item: `_app_list_identity` pins `apps_sha256` (hash of
  the whole sorted list) and `app_count` (`known_items.py:691-696`, kind spec
  `:815-827`). Remote-login keys likewise pin `list_sha256` + `key_count`
  (`:699-705`). Any change to the list makes the mark stale and the whole
  warning comes back (`apply_marks`, `:1160-1270`).
- The app sends only the mark id; main looks up the target it stored from its
  own scan (`desktop/mark-policy.js:44-60,85-153`) and calls the engine with
  `--i-understand` after the app's own confirmation
  (`desktop/engine-runner.js:145-174`).
- Consent: without `--i-understand` the CLI refuses unless stdin is a
  terminal, and then asks the person (`cli.py:883-903`, prompt at `:900`). AI assistants never
  pass `--i-understand` (AGENTS.md rule 1); the desktop app passes it only
  after its own panel, which is the existing, intended exception.

#### What a subset mark needs

1. **Per-item identity for list kinds.** New kinds alongside the list kinds,
   not replacing them (existing marks keep working):
   - `app_permission_entry`: keys `(code, app)`, where `app` is the bundle id
     or path from `data.apps`; evidence key `signer` (the team id or signing
     identity from `made_by` for that subject, `"unsigned"` when none), so an
     app swapped for one from another maker makes that one mark stale.
   - `ssh_authorized_key`: keys `(code, key_sha256)`, from a new per-key
     `data.keys: [{sha256, type, comment}]` that `session_revocation_scan`
     must start emitting (today it emits only the count and the list hash,
     `modules/security/session_revocation_scan`, around line 468). Comments can
     hold email addresses, so `rescue export` must redact them.
   - `startup_item`: keys `(code, label, plist, program)` from
     `startup_optimizer`'s `data.items`; content pinned the way
     background tasks are (`content_sha256`), or simply reuse
     `background_task` identity per item.
2. **The `markable` block grows `items`.** For a list finding:
   `markable.items = [{key, id, label, shows, monitoring}]`, one per entry,
   each `id = item_id(kind, identity)`. The existing whole-list `id` stays, so
   "Yes, these are all mine" still works and old app versions are unaffected.
3. **Applying partial marks.** In `apply_item_marks`, for a list finding,
   check each entry against the per-item marks:
   - all entries marked: downgrade exactly as today (`marked_by_user`, info,
     retitled);
   - some marked: **the finding stays a warning**, retitled from the engine's
     own count ("2 of 7 apps with Accessibility access aren't marked as
     yours"); `data.marked_items = [ids]`, `data.unmarked = [entries]`;
     the description lists the unmarked entries first; the marked entries stay
     listed as "marked as yours", never dropped;
   - a marked entry whose `signer` (or content) changed: `data.stale_items`,
     shown again with `stale_sentence`;
   - a new entry: simply unmarked, so the warning is about that one entry. This
     is a better version of today's `LIST_REASON` ("if a new app appears,
     you'll hear about it"): the person hears about the new one, not all seven.
   - critical findings are never downgraded, as today.
4. **Retiring.** `marks_gone` / `retire_marks` (`:988-1020`) retire a per-item
   mark when its entry is no longer in a list that ran cleanly. Same rule as
   today: a scan only ever removes entries.
5. **CLI shape.** Keep the existing pairing and add `--item`:

   ```
   rescue known add --code security.app_permissions.accessibility_access \
       --expect-id <finding's list id> --item <item id> --item <item id> [--json]
   ```

   - `--expect-id` still names the finding as the checkup showed it; each
     `--item` is an item id from `markable.items`. The check runs again now
     (`find_item`, `:1103-1130`); every `--item` must be present in the fresh
     finding, or nothing is saved ("This has changed since the checkup…").
     All-or-none in one `add_many` write.
   - In a terminal, the prompt lists each item by name and id and asks once,
     default No. Without a terminal and without `--i-understand`, it refuses.
     An AI assistant never passes `--i-understand`; the person answers.
   - With the list id but no `--item`, behaviour is today's whole-list mark.
6. **Undo per item.** `rescue known remove <item id> [<item id> …]` already
   removes by id (`cli.py:922-954`). `rescue known list` prints one line per
   item mark. In the app, each ticked-and-marked row gets its own "Stop
   treating this as mine", and the Cleared note for a partly marked card says
   "2 of 7 marked as yours".
7. **Desktop plumbing.** `mark-policy.js` `remember()` stores
   `markable.items` per finding id; the renderer sends `(findingId,
   [itemIds])`, never names or paths; main checks each item id was offered in
   its own scan and builds `--item` args in `engine-runner.js` `markArgs`.
   `MarkFlow.appRowsOf` keeps its "never drop a row" rule
   (`mark-flow.js:172-179`): if items and rows disagree, no checkboxes, the
   whole raw list, as today.
8. **Tests.** Engine: partial marks keep the warning, a new entry warns about
   only that entry, a signer change makes only that entry stale, `--item` not
   in the fresh check refuses everything, no TTY refuses, monitoring modules
   refuse. App: a forged item id over IPC is refused; the confirmation lists
   exactly the ticked rows.

#### Fixes that act on lists

There is one engine action today, `disable_launch_agent`
(`rescue/app_fixes.json`), with one target per finding
(`rescue/actions/launch_agent.py:113-143`, `offer_target`). No module-level
fix is enabled. So "turn off one login item vs all" doesn't exist yet. The
smallest step:

- Add `startup_optimizer` to the action's `modules`, and let the serializer
  offer **one `fixable` per item** in `data.items` whose `plist` passes
  `validate()`: `fixable.items = [{target, label, will_change}]`. Each runs as
  its own `rescue fix --action disable_launch_agent --target <plist>`, with
  its own quarantine id and Undo. The policy allows exactly the offered pairs.
- `login_items_cleanup` items are names only (strings), and macOS login items
  (Background Task Management) aren't safely switchable from a script. For
  those, per-item "Open Login Items" plus "I turned this off" (this checkup
  only) is the honest option.

### 2.4 One checklist component

New classic script `desktop/renderer/checklist.js` (global `Checklist`, also
on `window` for the game), with its styles in a new
`desktop/renderer/checklist.css` so it doesn't collide with `styles.css`
**[rc]** or `game.css` **[cc]**.

```js
Checklist.html({
  id: 'apps-3f2a',                    // unique on the page
  legend: 'Apps with Accessibility access',
  items: [{ key, label, detail, evidenceHtml, checked: false, disabled: false, note }],
  actions: [{ id: 'mark', verb: 'Mark', noun: ['app', 'apps'], suffix: 'as mine', min: 1 }],
  selectAll: true,                    // show "Select all" / "Select none"
  theme: 'plain' | 'game',
})
Checklist.attach(root, { onAction(listId, actionId, keys) {} })
```

Markup and behaviour:

- `<fieldset>` with a `<legend>`; one `<input type="checkbox">` per item with
  a real `<label for>`; the label holds the evidence (name, then id/path in
  `<code>`, then maker). Item text is escaped and passed through `visible()`
  so control characters can't hide or reorder (`mark-flow.js:156-158`).
- "Select all" and "Select none" are buttons, not a tri-state master box, so
  screen readers announce them plainly. Disabled rows are skipped.
- A live count, `<p aria-live="polite">3 of 7 selected</p>`.
- The primary button names the action and the number: **"Mark 3 apps as
  mine"**, **"Turn off 2 startup items"**, **"Check 4 again"**, **"Copy 5 for
  any AI"**. Disabled, and saying "Select at least one", at zero. Never "Apply"
  or "OK".
- Keyboard: Tab to the list, Space toggles, arrow keys move between rows,
  Home/End jump; Escape closes an open confirmation as the panels do today.
- Pressing the button opens the existing confirmation panel (fix or mark) with
  exactly the ticked rows. Nothing is sent before "Yes".
- Selection is memory only and resets on every render.
- Long lists: show 50, then "Show all 199" (the deck's `LOW_SHOWN` pattern,
  `deck.js:13`); select all always means all, and the count says so.

Where it replaces current UI:

| Replaces | Where |
|---|---|
| The whole-list app panel (L6) | `mark-flow.js:203-223` `appsHtml`, and `NOT_SURE_LIST` goes away |
| Per-card answer buttons on long result lists (L1/L2): a checkbox per card plus a sticky action bar ("I've looked at 4", "Copy 4 for any AI") | `app.js:696-767`; per-card buttons stay for one-off use |
| Info group (L2): a collapsed checklist of titles, open a row to see the card | `app.js:757-767` for severity `info` |
| Couldn't check (L4) with "Check selected again" | `index.html:146-150`, `app.js:811-824` |
| Step lists (L8): tick steps done | `app.js:729-745`, `game/views/briefing.js:5-7` |
| Startup items (L7b) inside their card | new, from `data.items` |
| **[cc]** Low-priority signals (L16), Known and noted (L18), Threat board copy (L17) | `game/views/deck.js:74-89`, `controller.js:409-419` |

---

## Build order

The two branches touch the same files this work needs: **[rc]** rewrites the
card in `app.js` (QuietNotes) and adds `display-mode.js`; **[cc]** grows
`controller.js`, `progress.js` (v3), `views/deck.js`, `views/signal.js` and
`clues.js`. So: new files now, edits to shared files after both merge.

### Phase 1: in parallel, now (new files or engine only)

| Track | Files | Depends on |
|---|---|---|
| 1a. Concept registry + its test | new `desktop/renderer/concepts.js`, new `desktop/test/concepts.test.js` (sources, `unsourced()`, `FORBIDDEN_ON_DISK` on ids, C4 `neverShorten`) | nothing |
| 1b. New lessons | new files in `desktop/renderer/game/lessons/`; `game/training.js` `LESSON_FILES` (not touched by either branch); `desktop/test/game-lessons.test.js` counts | nothing |
| 1c. Checklist component | new `desktop/renderer/checklist.js`, `checklist.css`, `desktop/test/checklist.test.js` (keyboard, counts, labels, escape, select all) | nothing |
| 1d. Engine per-item marks | `rescue/known_items.py`, `rescue/cli.py`, `rescue/serialize.py`, `modules/security/session_revocation_scan`, `tests/`, integrity manifest regen, `docs/cli.md` | nothing (no desktop branch touches the engine) |
| 1e. Shared "learned" reader/writer | new `desktop/renderer/learned.js` + test against both v2 and v3 documents | nothing; wired in Phase 2 |

### Phase 2: after `reclaim-city` and `command-center` merge (sequential where noted)

| Track | Files | Depends on |
|---|---|---|
| 2a. Results cards: concept lines, More, info collapsed, hint once | `desktop/renderer/app.js` (`renderSeverityGroup`, on top of QuietNotes), `clear-list.js` | 1a, 1e, rc merged |
| 2b. Plain-view lesson host | new `desktop/renderer/lesson-host.js`, `index.html` (script tag), `app.js` | 1b, 1e; after 2a (same file) |
| 2c. Fix and mark panels: concept lines; app list as checklist | `fix-flow.js`, `mark-flow.js`, `desktop/mark-policy.js`, `desktop/engine-runner.js` | 1a, 1c, 1d |
| 2d. Game: briefing and Signal or Noise concept lines | `game/views/briefing.js`, `game/views/signal.js`, `game/clues.js`, `game/controller.js` | 1a, 1e, cc merged; parallel with 2a |
| 2e. Deck checklists (low priority, known, threat copy) | `game/views/deck.js`, `game/controller.js` | 1c, cc merged; after 2d (same controller) |
| 2f. Couldn't-check list with "Check selected again" | `app.js`, `index.html`, maybe `desktop/main.js` (`recheck-module` exists) | 1c; after 2a |
| 2g. Step checklists (plain and game) | `app.js`, `game/views/briefing.js` | 1c; after 2a and 2d |

2c and 2d can run alongside 2a; 2b, 2f, 2g queue behind 2a because they edit
`app.js`; 2e queues behind 2d because both edit `controller.js`.

### Phase 3: engine text, module by module

| Track | Files | Depends on |
|---|---|---|
| 3a. `summary` and `concepts` in the JSON | `rescue/models.py`, `rescue/serialize.py`, a code→concept table, then modules in batches (manifest regen each time) | 1a ids final |
| 3b. Per-item startup-item fix | `rescue/app_fixes.json`, `rescue/serialize.py`, `rescue/actions/launch_agent.py` (offer per item), `desktop/fix-policy.js`, `fix-flow.js` | 1c, 2c |
| 3c. `marked_description` without the repeated original | `rescue/known_items.py` | owner's answer to question 6 |

## Open questions for the owner

1. **"Learn this (1 min)" vs "Learn this (2 questions)".** Lessons may not
   use time words (`training.js:25`). Size by questions instead?
2. **"I know this already"** without doing the quiz: allowed for every
   concept, or only after the person has seen the short line a few times?
3. **Consent intros (C18).** The Copy for any AI and Ask about this intros
   explain redaction every time. Can they shrink to one line plus "?" once
   `before-you-share` is done, given the preview text itself always shows?
4. **Info findings collapsed by default.** 382 notes become one line. Fine for
   plain view? The helper role ("anyone helping you can see it") still gets
   them in exports.
5. **Bulk "It's mine" for monitoring-capable kinds** (app permission lists,
   remote-login keys): allow ticking several in one confirmation (as proposed,
   inside one finding only), or keep strong-confirm kinds one at a time?
6. **`marked_description` repeats the whole original description.** Move it
   under a heading the app can fold? That changes `rescue export` text too.
7. **Defaults for checkboxes.** Proposed: unticked for anything that marks or
   fixes (the person picks), ticked for game-only sorting (low-priority
   signals) and for copy. Agree?
8. **More than one worry.** The worry screen is a single choice. Should it be
   a checklist too ("hacked" and "Wi-Fi")? That changes which profile runs.
9. **Per-step ticks.** Session-only like "I did this", or remembered in the
   game store for missions (the game already keeps "later")?
10. **Stealth and lessons.** Should any lesson finished in city mode be
    memory-only, not just the safety ones, so the store looks identical
    whichever mode is used?

## Owner decisions (2026-10-18)

1. **Lesson link label:** "Learn this (2 questions)". Size by question count; no time words.
2. **Info findings are not just collapsed: they're worked through as a mini-game.** "We do need to work through them, so we need to mini-game it." The 382 low-priority notes become a quick sorting game (built on Signal or Noise's batch sorting and the low-priority signals row), in both the plain checkup and game mode, rather than a hidden fold.
3. **Checkbox defaults: everything starts unticked**, including game-only sorting and copy. The person picks every item.
4. **The checkup is a lot of little missions.** "The average person only has like a 47 second attention span, so your computer's checkup is like… a lot of little missions." Every step is short and self-contained: one finding, or one small group of the same kind, is one mission with one decision. Long lists and long explanations are split into missions the person can finish quickly and come back to. This applies to the plain results screen too, not only the game.

Open questions 2, 3, 5, 6, 8, 9, 10 above still need answers before building.
