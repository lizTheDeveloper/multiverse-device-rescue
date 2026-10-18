# A clearer player profile, modelled on MVProfile: proposal

Status: proposal, for the owner. Nothing here is built.
Asked for: "we need a clearer… profile. Take a look at MVProfile."
Builds on: `desktop/renderer/game/progress.js` (store v3), `desktop/renderer/game/ledger.js`,
the stealth spec (`2026-10-18-reclaim-city-rename-and-stealth-mode-design.md`) and the
teach-once proposal (`2026-10-18-teach-once-and-checklists-proposal.md`, "Where learned
lives" and "More owner decisions" 5 and 8).

## Why

A tester answered every lesson question and the app kept sending them back into quizzes.
The immediate bug is fixed on main (`0949c63`: answering the last question now records the
lesson; a DONE district opens no quiz). The underlying problem is that the store has no
clear idea of what a lesson is worth remembering. Today a lesson is either
`{completedAt}` or absent (`progress.js:173-181`). The store doesn't record which
questions were answered, has no "skipped", and doesn't connect lessons to drills. The
rank, drill stats and missions sit in three different places with three different
validity rules. When one part fails, the migration throws away the whole of it: one bad
lesson record costs every lesson, and one bad tag costs the whole deck, points and rank
included (`progress.js:79-86`).

MVProfile in The Multiverse School solved the same problem for about forty browser
workbooks. Its shape is worth copying, but its publishing is mostly not.

---

## 1. What MVProfile is

MVProfile is the school's **shared, local-only student profile**. It holds canonical facts
that more than one workbook needs, so workbooks can compose without reading each other's
private state. It is a plain script that puts `window.MVProfile` over one localStorage key.

All paths below are in `~/src/themultiverse.school`.

### The contract

- **Key and shape.** `mv.profile.v1` (`tools/shared/profile.js:31`). `SHAPE`
  (`profile.js:36-118`) is a fixed list of groups and fields: `money`, `capacity`,
  `situation`, `who`, `network`, `social`, `campaign`, `offer`, `project`, `page`,
  `creative`, `market`, `citizen`, `builder`, `play`, `community` and `security`. A write
  to a field not in `SHAPE` throws (`profile.js:357-371`).
- **Provenance on every fact.** A record is `{ by: { <workbook>: { value, at, seq } } }`.
  A workbook writes only into its own slot, and it must name itself
  (`set(group, field, value, by)`). When two workbooks disagree, both values survive.
  `disagreement()` (`profile.js:379`) puts both on screen, because "the contradiction is
  the teaching". A plain `get()` returns the newest value, with `seq` breaking ties.
- **Three rules** (`profile.js:16-27`): a workbook never *requires* the profile; every
  write carries provenance; and the profile is local only, with no network call in the
  file.
- **Migrations that never lose data.** Each record migrates from the old single-slot
  shape and is never discarded (`profile.js:126-170`). The file also has numbered,
  forward-only schema migrations (`SCHEMA_MIGRATIONS`, `profile.js:196`). They are
  deterministic, keep an audit log in `_migrations`, and the student can inspect them
  ("Data history" in the viewer).
- **Export and import.** `toJSON()` returns the raw stored document, with provenance.
  `fromJSON()` *replaces* the whole profile and refuses anything that doesn't parse
  (`profile.js:446-462`).

### Identity, skills, evidence, badges, levels

- **Identity is minimal.** There's no name, email or account in the profile. `who` holds
  only `persona` and `archetype`. A signed-in identity exists only server-side, and only
  when the student shares.
- **Skills and evidence live in the design, not the code.**
  `docs/superpowers/specs/2026-08-18-portable-evidence-design.md` (status: design, not
  approved) describes them. A capability ontology (157 capabilities, `cap.*` slugs) has
  depths `introduced | practiced | assessed`. Evidence is **always an artifact**, never a
  number in a form. A workbook proposes claims, the student confirms them, a packet asserts
  at most `practiced`, and only an instructor writes `assessed`.
- **No badges, levels or ranks.** The closest thing is the `play` group, "game scores
  that measure real skill without gamification pressure" (`profile.js:97-102`). For
  example, `tools/semantle/src/profile-publish.js` publishes a rolling average and a
  games-won count, deliberately "not streaks, not play time".
- **Progress is expressed as readings.** `templates/path_dashboard.html:3589-3610` reads
  profile values as *readings* (bench outputs) and keeps leads and lags server-side. It
  warns that treating readings as progress "teaches students that re-running a
  calculator is the work".

### How a tool publishes

Every `tools/*/src/profile-publish.js` follows the same pattern:

1. Bail out if `window.WB` or `window.MVProfile` is missing. The profile is optional.
2. On `WB.onChange` and once on load, publish **only when the bench is complete**, and
   **never from the worked example** (`s.meta.example`). The propaganda bench says why:
   the example would put "a stranger's campaign" into the student's profile
   (`tools/propaganda_bench/src/profile-bridge.js`).
3. Write a few named fields under the bench's own `by` id, skipping unchanged values. The
   header comment names exactly what is published and lists what is *not*.

The defender benches go furthest. `tools/device_rescue/src/profile-publish.js` (the web
workbook that shares this project's name) is "STANDALONE — too sensitive for
cross-bench sharing". It publishes one fact, `security.devices_audited`: a count of
completed audits, keyed by an opaque run id, with "no device details, no findings". Even
the risk level stays private. `tools/password_health/src/profile-publish.js` publishes a
tier and a score, and lists six kinds of fact it never publishes.
`docs/specs/defender-bench-suite-spec.md:5` states the rule: "Lead measures are ACTIVITY
measures (did you do the thing?), never CONTENT measures (what did the bench find?)."

### What leaves the device, and how

- **Nothing, by default.** The profile is a browser-local key.
- **Device sync** (`sync_relay/`, `tools/shared/sync.js`, `tools/profile_viewer/src/pair.js`):
  a Cloudflare Worker and Durable Object (`mvprofile-sync-relay`, route
  `sync.themultiverse.school/*`). The relay holds at most two WebSocket peers per channel
  and forwards opaque frames up to 256 KB. It never stores or inspects them
  (`sync_relay/src/relay.js`). Pairing uses a QR code. The AES-256-GCM key travels in the
  URL fragment, so it never reaches a server. The two sides swap the whole
  `MVProfile.toJSON()` and merge per workbook, with later `at` winning
  (`sync.js:64`, `mergeProfiles`). The relay needs no authentication; the channel id and
  the key are the only secrets.
- **Voluntary sharing** (`profile_sharing.py`, `tools/profile_viewer/src/sharing.js`,
  `schema/2026-08-29_student_profile_shares.sql`): this needs a signed-in student. The
  student picks a tier (`anonymous`, `named` or `research`), ticks individual fields and
  sees a live preview ("What the school will see"). The selected `{value, by, at}`
  entries are then POSTed. Revoking deletes the share. Cohort aggregates need at least 5
  students and omit min and max.
- **Evidence packets** (portable-evidence spec, not built): a "Share with instructors"
  sheet shows the exact payload with every box unticked. Each field gets a sharing class:
  `derived` (may be offered), `sensitive` (warned, never pre-ticked) or `never` (absent
  from the UI, and refused by both the export builder and the server). An unclassified
  field is treated as `never`.

### How a learner views it

The Profile Viewer at `/tools/profile` (`profile_viewer.py`, built to
`static/tools/profile-viewer.html`, tested by `tests/python/test_profile_viewer.py`)
reads `MVProfile.SHAPE` and renders every group with labels and icons. It shows where
each value came from, any disagreements, migration history, export and import, the
sharing panel and the pairing page. The path dashboard (`templates/path_dashboard.html`)
reads the same key to fill its metric cells, its bench rail (for example
`security.devices_audited` marks the device-rescue bench as done, line 5023) and its
threat-tier content filter.

### Things worth knowing before anyone connects to it

These are read-only observations about the school repo. Nothing there was changed.

- `tools/shared/profile.contract.yml`, and the `sharing` classes that enforce `never`,
  don't exist yet. Today `sharing.js` lets the student tick **any** field, `security.*`
  included, and the server checks only the group name (`profile_sharing.py`,
  `VALID_GROUPS`).
- `fromJSON()` replaces the whole profile. Importing a partial document through the
  viewer would wipe everything else. A merge import (the `mergeProfiles` rule) would be
  needed for anything this app hands over.
- `pair.js:31` sets `RELAY_HOST = "192.168.0.159:8765"` over `ws://`: a LAN address, not
  the `sync.themultiverse.school` route in `wrangler.toml`.

### What to copy, and what not to

| Copy | Don't copy |
|---|---|
| One versioned record with a fixed shape; unknown fields refused | A shared key that other tools can read (this app is a separate Electron origin anyway) |
| Provenance on every fact, with disagreements kept so they can be shown | Device sync of the whole document |
| Forward-only, logged migrations that salvage rather than discard | Any upload by default |
| Readings vs evidence; depth as a claim (`introduced`, `practiced`) | Rank as an outward-facing number |
| "Activity, never content"; `never` means absent from the UI | |

---

## 2. The proposed local player profile

One record, one writer, one shape for both views. It replaces the three loosely related
parts of the v3 store. **It never leaves the computer** unless section 3's single,
consented path is used.

### Where it lives

- A new classic-script module, `desktop/renderer/player-profile.js` (global
  `PlayerProfile`, also exported for the game's ES modules and for Node tests). This is
  the teach-once proposal's planned `learned.js`, grown into the whole profile. It is
  the **only** code that reads or writes the store. `progress.js` and `ledger.js` keep
  their pure transforms (`reconcile`, `award`, `recordSweep` and so on) and hand the
  result to `PlayerProfile.save`. Plain view (`app.js`) uses the same module, so the two
  views can't write different shapes.
- Storage key: see section 4 (new key `device-rescue.player.v1`; the old key kept frozen
  as a backup).

### Shape (version 4)

```jsonc
{
  "version": 4,
  "since": "2026-10-18T…",              // first save. No name, account, email or machine id.
  "migrations": [{ "v": 4, "from": 3, "changes": ["lessons: 3 kept", "deck: kept"] }],

  // One record per lesson, MVProfile-style: a slot per SOURCE, each with its own time.
  // "Not yet" is the absence of a record.
  "lessons": {
    "locked-door": {
      "by": {
        "quiz": {                        // the person took the lesson
          "at": "…",                     // when the last question was answered
          "of": 5,                       // how many questions the lesson had then
          "asked": {                     // evidence: one entry per question key
            "software-update-where": { "first": "right", "at": "…" },
            "security-responses":    { "first": "wrong", "at": "…" }
            // …
          }
        },
        "self":  { "value": "knows", "at": "…" },        // "I know this"
        "drill": { "right": 2, "tried": 3, "at": "…" },  // practice on this lesson's modules
        "gaps":  { "n": 1, "at": "…", "kinds": { "drill": 1 } } // signals since `self`
      },
      "offered": { "at": null, "declined": 0 }           // re-ask bookkeeping
    }
  },

  // Drill calibration: invented findings only, so nothing here is about this computer.
  "drills": {
    "right": 9, "tried": 12,                              // as today (deck.drills)
    "calls": { "threat": { "threat": 3, "mine": 1, "closer": 0 },   // [truth][picked]
               "mine":   { "threat": 2, "mine": 4, "closer": 0 },
               "closer": { "threat": 1, "mine": 0, "closer": 1 } },
    "recent": [1, 1, 0, 1, 1, 1, 0, 1, 1, 1]              // last 10, newest last
  },

  "rank":  { "points": 340, "index": 2 },                 // deck.points / deck.rank; never drops
  "deck":  { "tags": {}, "confirmed": {}, "once": {}, "sweep": {}, "sweeps": [] },  // as v3
  "missions": { }                                         // as v3 (reconcile owns it)
}
```

The question `key`s are new. Today questions have no ids. Each question in
`game/lessons/*.js` gets a stable `key` (`locked-door` already has `setting:` hints to
start from). Spot-the-fake keys come from the message id (`msg-1`, `msg-4`, `msg-5`).
`game-lessons.test.js` checks that keys are unique within a lesson, that they pass
`FORBIDDEN_ON_DISK`, and that a key is never reused for a different question.

### State is derived, never stored

Like MVProfile's `get()`, the state shown on screen is computed from the slots. Two
sources that disagree ("I know this" against a wrong drill) both stay on disk, and the
disagreement is what triggers a re-ask.

| Derived state | Rule |
|---|---|
| **learned** | `by.quiz` exists and has an `asked` entry for **every question key the lesson has now**. |
| **started** ("2 of 5") | `by.quiz.asked` covers some keys but not all. |
| **skipped** | `by.self.value === "knows"` and not learned. |
| **skipped, worth a look** | skipped, and `by.gaps.at` is later than `by.self.at`. |
| **not yet** | no record, or a record with no `quiz`, `self` or `drill` slot. |

**"Answered every question" maps to "learned".** Each answer writes `asked[key]` at the
moment of the pick, recording only `first: right|wrong`, because the lesson view allows
one pick per question. When the last key fills in, the lesson is learned, whether or not
FINISH is pressed. This matches what `0949c63` now does, but per question, so leaving
part-way keeps the questions already answered ("started 3 of 5") instead of recording
nothing. Getting a question wrong doesn't block "learned": the feedback is the teaching.
The right-first-time count is shown as evidence ("5 of 5 answered, 4 right first time").

**A lesson that gains a question** stays learned. The profile screen shows "1 new
question" and offers it on its own. It is never demoted, and never sends the person
through the whole quiz again. A question that is removed just stops counting.

**Learned outranks skipped.** If a skipped lesson is later taken in full, it's learned,
and the `self` slot stays as history.

### "I know this" (skipped) and when it's asked again

The owner's decision 5: skipped is not learned, and later signals offer the lesson again.

- **Writing it.** "I know this" writes `by.self = {value: "knows", at}`. It earns no
  points (nothing in the ledger pays for lessons, so this holds already) and doesn't
  count as learned anywhere, including section 3.
- **Gap signals**, each one incrementing `by.gaps` for the lesson it touches:
  1. **A wrong drill.** The drill's `modules` overlap the lesson's `modules`. Drills
     already list `modules`, and many cite the lesson file in `sources`.
  2. **A Signal or Noise call Scout disagrees with,** on a real finding whose module is in
     the lesson. Only the lesson id, the kind (`call`) and a time are stored, never the
     finding, its id or its module.
  3. **A re-opened "?"** for one of the lesson's concepts (teach-once registry). This is
     the weakest signal, so it counts only after the second re-open in the same sweep.
- **The offer.** For a lesson that is skipped and worth a look, show **one** line where the
  signal happened (the drill result, or the clue panel): "Want the 2 questions on this?"
  with **Yes** and **Still know it**. Saying yes opens the lesson. "Still know it" sets
  `offered.at`, increments `declined` and resets `gaps.n` to 0.
- **No nagging.** At most one offer per lesson per sweep. After two declines, stop
  offering until a *drill* is answered wrong again (signal 1 is the only one that reopens
  it).
- **Learned lessons get gentler treatment.** A wrong drill on a learned lesson offers
  "REVIEW ONE?" (one question, the one the drill was about, when one maps) and never
  changes the state.
- **Monitoring is excluded.** Drills are never about monitoring software (`drills.js`,
  `MONITORING_WORDS`), and `ledger.js` already refuses to score anything in
  `MONITORING_MODULES`. Gap signals follow the same rule: no signal is ever taken from
  `stalkerware_scan`, `mvt_spyware_scan` or `keylogger_indicators`.

### Skills: a view over lessons and drills, in MVProfile's depths

Skills aren't stored. A static map in `desktop/renderer/game/skills.js` groups lessons
(and teach-once concepts C1-C23) into a handful of skills. Each skill's depth is computed
the way the portable-evidence spec describes capability depth:

| Skill (working names) | Lessons | Concepts |
|---|---|---|
| Reading who made it and where it lives | `starts-on-its-own` | C1, C2, C21 |
| Things that start on their own | `starts-on-its-own` | C3, C8 |
| Locks and updates | `locked-door` | C12, C13, C14 |
| Browser add-ons | `browser-add-ons` | C15 |
| Your network | `whos-on-wifi` | C11, C22 |
| Spotting a scam | `spot-the-fake`, `password-asker` | C17 (part), C19 |
| Developer packages | `poisoned-packages` | C23 |
| Honest results | `couldnt-check` | C9, C10 |

- **introduced**: at least one of the skill's lessons is learned or skipped.
- **practiced**: one is learned, *and* the drills on its modules show at least 2 right
  with a right-to-tried ratio of 2/3 or better.
- `assessed` doesn't exist here. In MVProfile it belongs to an instructor, and this app
  has none.

### Drill calibration

`deck.drills {right, tried}` is too thin to say anything useful. The `calls` matrix
records what the person picked against the right answer, for invented drills only. That
lets the profile say something kind and specific, such as "You call things threats more
often than they are", which matters for a frightened person. `recent` gives a "last 10"
figure that isn't dragged down by early tries. Like Semantle's published stats, there
are no streaks and nothing timed.

### Rank and missions

- **Rank.** `points` and `index` come from the deck exactly as `ledger.js` computes them
  (`RANKS` at line 15; `rankOf` at line 45, which never drops). They move up a level in
  the record so the profile screen and plain view read one place. `award()` is unchanged.
- **Missions.** Unchanged and owned by `reconcile`. They hold finding titles and ids that
  can name programs and paths (the comment on the `reclaim-city` branch's `progress.js`
  says so). That is the main reason the profile must stay local. When `reclaim-city`
  merges, its `HELD_MODULES` rule (monitoring missions never recorded, older ones
  dropped) applies here too.

---

## 3. Publishing to MVProfile: off, and almost nothing can go

**Default: local only. No network code in `player-profile.js`, ever** (MVProfile's rule
3). This is a safety app, so what it learns about the person's computer stays on it.

### What could ever leave, with explicit consent, in standard mode only

| MVProfile field (needs a `SHAPE` addition in the school repo) | Value | Sharing class |
|---|---|---|
| `security.city_lessons_learned` | count of lessons in the **learned** state (skipped doesn't count) | derived |
| `play.city_drills_right` | `drills.right` | derived |
| `play.city_drills_tried` | `drills.tried` | derived |

These three are the whole list. They are **activity**, not content: how much the person
practised on invented material. Like the school's own device-rescue bench, they say
nothing about what the computer has.

### Never, by any path (absent from the UI, refused by the builder)

Rank and points (they are earned from real findings: clues opened, fixes confirmed,
clean sweeps), lesson ids and their states (`recommendedFor` ties lessons to worries:
`whos-on-wifi` is recommended only for the Wi-Fi worry), question answers, gap signals,
`drills.calls` and `recent`, missions, tags, confirmed fixes, sweeps and their counts,
the display mode, the city seed, the worry, anything from the help district, and
`security.devices_audited`. This app never adds to that count; it would say a checkup
happened.

### How, if the owner wants it at all

- **A "Add to my school profile" control** on the profile screen. It opens a sheet with
  the exact payload (the three fields, every box **unticked**), a line naming what can't
  be shared ("Your checkup results, missions and rank stay on this computer"), and two
  ways to hand it over: **Save a file** or **Copy**. The person imports it in the Profile
  Viewer. The app makes no network call, doesn't join the sync relay and doesn't open a
  URL carrying the data, because a URL lands in browser history.
- **The payload** is an MVProfile fragment with `by: "reclaim-city"`, so it lands in its
  own provenance slot. It needs a **merge** import in the viewer (the `mergeProfiles`
  rule), not `fromJSON`, which would wipe the student's profile.
- **School-repo changes** (not this repo, and only on the owner's say-so): add the three
  fields to `SHAPE`, add a merge import, and, once `profile.contract.yml` exists, classify
  them as `derived` with everything else from `reclaim-city` treated as `never`.

### Stealth (city) mode

**Nothing is ever published.** The control is **absent**, not disabled. So are its sheet,
its help text and the export file. If the mode changes to city while a payload is on
screen, the sheet closes. A test drives every city-mode route and asserts that no code
path builds a payload.

### The local record in city mode: disguised (owner decision 8)

"Save progress, but disguised… recipe-like data the code maps back. Nothing literal on
disk."

- **A codec, `desktop/renderer/game/recipe-box.js`.** `PlayerProfile.save` passes
  everything through it in city mode. It maps each lesson id, question key, skill, state
  word and help-district item to a cooking identity. The mapping is a permutation of a
  large recipe vocabulary, seeded by the per-install `device-rescue.city-seed` (already
  written by `display-mode.js` on `reclaim-city`). So:
  - `locked-door` might be stored as `plum-galette` on one install and `leek-tart` on
    another. There is no fixed string to search for.
  - the states learned, started, skipped and "worth a look" become `baked`, `in the
    oven`, `bookmarked` and `try again`. Question answers become ingredients ticked
    (`first: right` → `"fresh"`, `wrong` → `"swapped"`). Counts become servings, and
    times stay as times ("made on").
  - help-district progress (the Six Roses steps visited) is saved the same way, as a
    recipe's steps. This supersedes the teach-once proposal's "memory only" rule for
    safety concepts. It is still never shown outside the help district, and the panic
    key behaves as before.
- **Finding identities are hashed.** Mission ids, tag keys, `confirmed` keys and
  `once` keys are built from `module|code|…` and can name paths. In city mode they are
  stored as a salted hash (seeded the same way). Lookups hash before comparing, so
  `reconcile`, `award` and `reconcileDeck` keep working.
- **Mission titles aren't stored in city mode.** A reclaimed mission shows the existing
  fallback, "Something that's gone now" (`progress.js`, `reclaimedIn`).
- **Switching modes** re-encodes once, in place. City to standard decodes, and standard
  to city encodes. The frozen v3 backup (section 4) is deleted on the switch to city.
- **Tests.** `forbiddenWrites` over every write in both modes. A "looks like a recipe
  box" test checks that no stored key or value in city mode contains a lesson id,
  question key, district id, module name or `RANKS` name. A round-trip test confirms
  that decode(encode(p)) equals p for generated profiles. Another test confirms that two
  installs with different seeds encode the same profile differently.

---

## 4. Migration from `device-rescue.game.v1` v3

The goal is that nobody loses progress, including someone who later downgrades.

1. **A new key: `device-rescue.player.v1`.** On first load, if it is missing, read
   `device-rescue.game.v1` through today's `migrate()` and then convert to v4. **Leave the
   old key untouched.** An older build that is reopened still finds its own v3 document.
   Today, an older build that met a `version: 4` document under the old key would fall
   to `emptyProgress()` and overwrite it on the next save (`progress.js:79-86`). The
   rename spec's promise ("the storage key keeps its name so progress survives") is kept
   in substance: the old key is read and its progress carried forward.
2. **Salvage per record, not per section.** The v4 reader validates each lesson record,
   each mission, each tag and each sweep separately, and drops only the bad one. A bad
   tag no longer zeroes points and rank. Points and rank are kept whenever they are
   non-negative integers, and rank is never lowered.
3. **The mapping:**

   | v3 | v4 |
   |---|---|
   | `missions` | `missions`, unchanged |
   | `lessons[id] = {completedAt}` | `lessons[id].by.quiz = {at: completedAt, of: null, asked: {}, migrated: true}`. It derives as **learned**: a migrated quiz with no `asked` counts as complete, because the person finished it under the old rule. |
   | `lessons[id] = {completedAt, how: 'skipped'}` (if a teach-once build wrote one) | `lessons[id].by.self = {value: 'knows', at: completedAt}` |
   | `deck.points`, `deck.rank` | `rank.points`, `rank.index` |
   | `deck.drills {right, tried}` | `drills.right`, `drills.tried`; `calls` and `recent` start empty (the screen says "from now on" until there's data) |
   | `deck.tags`, `confirmed`, `once`, `sweep`, `sweeps` | `deck.*`, unchanged |
   | (nothing) | `since` = the earliest `completedAt` or mission `updatedAt`, else now |

4. **Log it** in `migrations`, MVProfile-style. The profile screen's "Data history" line
   reads it.
5. **Retire the old key** in a later release, after v4 has been loaded and saved
   successfully: delete `device-rescue.game.v1` and `device-rescue.game.scan-confirmed.v1`,
   which folds into `missions` the same way. In city mode, delete it as soon as the
   encoded v4 has been written, because the v3 document is literal.
6. **Tests:** every stored v1, v2 and v3 fixture in `desktop/test/` migrates with
   identical missions, lesson count, points and rank. The same holds for a v3 document
   with a single corrupt tag or lesson. The old key is unchanged after migration
   (standard mode) and gone after the switch to city mode.

---

## 5. The profile screen

### Game mode: **YOUR FILE**, from the deck's header

It opens from a rank chip in the command deck's header (for example
`NETRUNNER · 340`). It uses the same panel and stamp style as the deck. There's one
column on narrow windows and two on wide ones.

- **Rank.** The name, points and "60 to SYSOP". Rank never drops, so there's no
  red-arrow state.
- **Training.** One row per lesson, with a stamp:
  - `LEARNED`: "5 of 5 answered, 4 right first time · 18 Oct"
  - `2 OF 5`: **CONTINUE**
  - `YOU KNEW THIS`: when it's worth a look, a small "a drill suggests a refresher" and
    **2 QUESTIONS**
  - `NOT YET`: **START**
  - `1 NEW QUESTION`: **ANSWER IT**

  Rows are sorted unfinished first, then in the worry's recommended order.
- **Skills.** A short list with a three-step meter (not yet, introduced, practiced) and
  one line on what moves it ("2 more right drills in The Gatehouse").
- **Drills.** "9 of 12 right · last 10: 8". It shows the calibration line only when it is
  true and has at least 3 calls behind it, for example "You flag things as threats more
  often than they are (3 times)". Its opposite is worded as gently: "A few threats got
  past you as 'mine' (2)".
- **City.** Missions reclaimed, set aside for later, and marked as yours, plus the last
  sweep's percentage. It shows counts only, never finding names. This is also what makes
  it safe to show over someone's shoulder.
- **Footer.** **Data history** (the migration log), **Save a copy** (standard mode
  only; the full local record, for the person's own backup) and **Start over** (a strong
  confirmation; clears the profile and changes nothing on the computer). **Add to my
  school profile** appears only in standard mode, and only once the owner turns section
  3 on.

### Plain view: **Your progress**

A plain-view panel reached from the results header shows the same content with no game
words. The rank appears as "Points: 340 (level 3 of 5)", or not at all if the owner
prefers (open question 6). Lessons open in the plain-view lesson host the teach-once
proposal describes, and both views write through `PlayerProfile`.

### Copy rules

The screen uses the project's existing rules: no time words (so "2 questions", never
"1 min"), no fear, nothing implying the person was hacked, and every lesson title word
for word from its file.

---

## 6. Open questions for the owner

1. **New key or same key?** Proposed: write `device-rescue.player.v1` and keep the old
   key frozen, so a downgrade never wipes progress. The alternative is to keep
   `device-rescue.game.v1` with `version: 4`, which is simpler but loses progress if an
   older build is reopened.
2. **Encode in both modes?** You asked for disguise in city mode. Encoding in standard
   mode too would make the store look the same whichever mode is used (this was the
   teach-once proposal's question 10), and there'd be one code path. Debugging gets
   harder.
3. **Publish at all?** If yes: are these three fields, under these names, the right
   ones? Should the school repo get the `SHAPE` additions and a merge import, or should
   the profile stay entirely inside Reclaim City?
4. **Does "learned" need any right answers?** Proposed: answering every question is
   enough, and the right-first-time count is shown as evidence only.
5. **Gap signals.** Should a re-opened "?" count at all? Is one wrong drill enough to
   offer a skipped lesson again, or should it take two?
6. **Rank in plain view?** Show "level 3 of 5", show nothing, or keep rank game-only?
7. **Mission titles in city mode.** Proposed: don't store them, so reclaimed missions
   read "Something that's gone now". Is that acceptable, or should titles be encoded
   too?
8. **Save a copy** in city mode: never (proposed), or as a disguised recipe file?
9. **Help-district progress** saved disguised (decision 8, which reverses the teach-once
   proposal's memory-only rule for safety concepts). Is that the intent for C4 too, or
   only for the help district's own steps?
