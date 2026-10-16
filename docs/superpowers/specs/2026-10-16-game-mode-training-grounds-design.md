# Game mode C: training grounds

**Status:** draft, written 2026-10-16. Its direction ("learn first, then fix") was
chosen in brainstorming, but the details below weren't discussed section by
section. Review section 9 first.
**Part of:** [Consumer security game: overview](2026-10-16-consumer-security-game-overview.md)
**Depends on:** [Spec A: device missions](2026-10-16-game-mode-device-missions-design.md).
It uses [Spec B](2026-10-16-game-mode-one-city-design.md) if that is present.
**Goal:** before the scan, the person can play short teaching missions about how
computers get compromised and what Device Rescue will and won't do. Then the real
scan runs as the final boss, and the city comes out of it.

## 1. Overview

Frightened people trust what they understand. A district of short lessons, **The
Training Grounds** (the name is to be confirmed), explains what the scan is about
to look for. Each lesson uses the game's existing patterns: a briefing, then a few
questions with Scout's feedback, like the phishing quiz. When the person is ready,
the scan runs as the final boss, and Spec A's city appears from its results.

### Rules

1. **The scan is never locked behind lessons.** Every Training Grounds screen has
   "Skip to the checkup". A frightened person must be able to reach the scan
   straight away.
2. **Lessons teach. They don't diagnose.** No lesson says or hints that the
   person's computer has a problem. The scan says that.
3. **Every factual claim has a source.** Each claim traces to a remediation guide
   or a module in this repo (section 5). Lessons never invent menu paths, commands
   or settings.
4. **No score that pressures.** Lessons record completion, not marks. A wrong
   answer gets an explanation, not a penalty.

### Non-goals

- Lessons don't scan, read anything on the computer, or offer fixes.
- No upstreaming to the hosted game in this spec (section 9).
- No lessons about accounts. Reclaim City already teaches those, and Spec B puts
  them on the map.

## 2. The flow

```
Welcome → "Play it as a game" → worry → Training Grounds ─┬─ lessons (any order, any number)
                                                          └─ "Start the checkup" / "Skip to the checkup"
                                         → Final boss (the scan) → the city (Spec A / B)
```

- The Training Grounds come after the worry screen, so the safety gate (Spec A's
  `gate.js`) has already applied. For worries the gate excludes, game mode was
  never offered.
- The worry picks which lessons are **recommended** (shown first). It never hides
  the rest. For example, `wifi` recommends the Wi-Fi lesson, and `sketchy` (which
  scans with the `ai_worm_response` profile) recommends the package-worm lesson.
- People can come back to the Training Grounds from the city at any time.

## 3. The lessons (first set)

Each lesson is one file in `desktop/renderer/game/lessons/`, as data:

```js
{ id, title, district: 'training', recommendedFor: ['unsure', 'wifi', …],
  briefing, questions: [{ prompt, options: [{ text, correct, feedback }] }],
  whatTheScanLooksFor,          // one sentence, shown before the final boss
  sources: ['guides/remediation/<file>.md', 'modules/security/<module>'] }
```

| Lesson | Teaches | Sources (to be confirmed in the plan) |
| --- | --- | --- |
| **The tool that asks for your password** | Device Rescue never asks for a password, a code or a recovery code, and anything that does is a red flag. Fake "your computer is infected" pop-ups and tech-support scams. | `README.md`, `docs/trust-and-safety.md` |
| **Things that start on their own** | Launch agents and startup items: what they are, why malware likes them, and what "unsigned" and "made by" mean. | `review_launch_persistence.md`, `review_windows_autoruns.md` |
| **Updates and the locked door** | System updates, disk encryption and the lock screen, and why a stolen laptop matters. | `enable_automatic_updates.md`, `enable_disk_encryption.md`, `enforce_lock_screen.md` |
| **Who's on your Wi-Fi** | The router, the Wi-Fi password, unknown devices, and why "computer is hot and slow" isn't proof of an intruder. | `review_network_connections.md`; the `router_security_audit` and `wifi_security_audit` modules. There's no remediation guide for the router yet: write one first, or narrow the lesson. |
| **Browser add-ons** | What extensions can see, and what to do with ones you don't recognize. | `review_browser_extensions.md`, `review_chrome_extensions.md`, `review_safari_extensions.md` |
| **What "couldn't check" means** | Some checks need permissions or a specific OS, and a gap is not a clean result. | `docs/trust-and-safety.md` |
| **Poisoned packages** (recommended for `sketchy`, open to everyone) | How npm/PyPI worms spread through developer tools. | `clean_ai_worm_filesystem.md`, `cut_ai_worm_c2.md`, `secure_git_ssh_after_worm.md` |

## 4. The final boss

- The checkup screen is the scan screen, re-skinned. The progress events Spec A
  already gets (`{phase, index, total, module, category}`) drive it. Each finished
  check sweeps its category's district on a dimmed city map, and Scout narrates the
  category, not the module.
- The count of findings so far is shown as it is today. Nothing is revealed early:
  districts show as **swept**, not as safe or unsafe, until the scan finishes.
- The scan can take a while, and AGENTS.md notes it runs for several minutes. The
  boss screen offers the Training Grounds again while it runs ("Play a lesson while
  you wait"). The scan keeps running in the main process either way.
- When it finishes, the city appears in Spec A's state.

## 5. Keeping the content accurate

Earlier drafts written with help invented menu paths and commands (see project
memory). Lesson content needs a mechanical check:

- `game-lessons.test.js`:
  - Every lesson has at least one `sources` entry, and every source path exists.
  - **Menu paths and commands.** Any text in a lesson that looks like a UI path
    (`A → B`, "System Settings", "Settings >") or a command in backticks must
    appear word for word in one of the lesson's sources.
  - No lesson text uses words that diagnose the person's own computer, such as
    "your computer has" or "you are infected". The test uses a phrase list.
  - Every question has exactly one correct option, and every option has
    `feedback`.
  - `recommendedFor` uses only worry ids that exist in SITUATIONS.
- Each lesson's wording is reviewed against its sources before merging, the same
  way finding text is reviewed today.

## 6. Progress

- Lessons are stored under `lessons: {[id]: {completedAt}}` in
  `device-rescue.game.v1` (Spec A's store, bumped to v2 with a migration that
  keeps `missions`).
- A device mission whose category had a completed lesson shows "You learned about
  this in the Training Grounds →" in its briefing. That's a link, not a gate.
- Lessons never count toward fixes, confirmed or reported.

## 7. Error handling

| Failure | Behaviour |
| --- | --- |
| A lesson file fails to load | That lesson is left out. The Training Grounds and the scan still work. |
| The scan fails during the boss screen | The same error the list view shows today, then back to the Training Grounds with "Start the checkup" again. |
| The person leaves partway through a lesson | Nothing is recorded. The lesson starts fresh next time. |

## 8. Testing

- `game-lessons.test.js` (section 5).
- `game-training-flow.test.js`:
  - "Skip to the checkup" is present on every Training Grounds screen state.
  - The recommended order follows the worry.
  - A gated worry never reaches the Training Grounds.
- `game-boss.test.js`: progress events map to category sweeps, no district shows
  safe or unsafe before the scan finishes, and a scan error goes back to the
  Training Grounds.
- `game-progress.test.js`, extended: the v1 → v2 migration keeps missions, and
  lessons never count as fixes.

## 9. Decisions to confirm

1. **The name "The Training Grounds", and its place on the map.** It could be its
   own district at the gate, or a building inside "Your computer".
2. **The first lesson set (section 3).** Add or cut lessons. The password/scam
   lesson goes first whatever the worry, because it protects the person from the
   scams that copy this kind of tool.
3. **Whether lessons stay in Device Rescue or go upstream** to Reclaim City as a
   district the hosted game also shows. This draft keeps them local, so they can
   cite this repo's guides and stay tested against them.
4. **Whether the phishing quiz from the vendored game joins the Training Grounds.**
   It's already written and local, and it overlaps with the password/scam lesson.
