# Command center and Signal or Noise — design

Status: approved in conversation, 2026-10-18. Builds on game mode A/B/C
(`2026-10-16-game-mode-*.md`) and the scan-first flow (the scan starts as soon
as a worry is picked; districts open their lessons while it runs).

## Why

Every scan should be a learning moment. Today the city shows what the scan
found, but sorting through findings — deciding what's yours, what's a threat,
what to look at — is where people get lost, and it's also the skill that
makes someone safer next time. The tester's framing: a personal secops
"operational command center" that's fun to use, in the spirit of a strategy
hacking game, where the thrill is that it's your real computer.

## Roadmap (each piece gets its own spec → plan → build)

| # | Piece | Depends on |
|---|---|---|
| **1** | **Command center + Signal or Noise (this spec)** | scan-first flow |
| 2 | Places map, zoomable: districts are real security-relevant places with real paths; findings sit where they live; read-only `ls` on demand, including places outside the map | 1 |
| 3 | Breach Protocol: fixes as a hacking sequence; the real consent screen is EXECUTE; a re-check confirms | 1 |
| 4 | Dossier: "who made this?" from `made_by` evidence | 1 (best with 2) |
| 5 | Reverse Heist: account steps ordered, then done at the provider; YOU REPORTED only | 1 |
| 6 | Full-disk city: an opt-in button builds the whole map from the virus/worm scanners' existing walk; never automatic, cancellable, size-guarded | 2 |
| 7 | Network analysis track (N1–N10): onboarding level, network visibility in three levels, the skill ladder, case files, the review ladder. See `2026-10-18-network-analysis-training-design.md` | 1 |

**Shared with the network analysis track** (`2026-10-18-network-analysis-training-design.md`):
- The **threat board** that THREAT sends signals to is that spec's
  **Evidence Board**. A threat card can be opened as a case.
- The **Dossier** (piece 4) covers addresses and domains as well as programs.
  Its "who owns this address" half is network piece N4.
- **Drills**, **ranks** and the **ops log** are shared. Network drills join the
  drill bank. Case-file grades feed the same rank. The ops log is the raw
  timeline that a case file's "What happened" is built from.

## Decisions

- Fun comes from a mix: an ops-room home (the deck) plus arcade-style
  mini-games that open from it.
- Layout: **Netrunner Deck** (mockup A, `.superpowers/brainstorm/…/command-center-directions.html`):
  the city in the middle, a cockpit of instruments around it.
- Scoring: real findings score the investigation, never the verdict;
  clearly marked DRILLs are scored right/wrong.
- Real changes always keep their own explicit OK for that specific change.
  The game makes that moment dramatic; it never skips it.

## 1. The deck

Replaces the current city home screen (one-city map + HUD) in game mode.

- **Top bar:** rank, last sweep time and check count, **RE-SWEEP ⟳** (the same
  read-only scan as the plain route, same profile for the worry).
- **Left — INCOMING SIGNALS:** unsorted findings. Critical and warning first;
  info folded into one "low-priority signals (N)" row. DRILLs mixed in.
  **INVESTIGATE NEXT ▶** opens the most important unsorted signal.
- **Centre — the city:** today's map (piece 2 makes it real places). Districts
  glow by open-signal heat; districts the scan couldn't check are fogged, never
  clear. Clicking a district filters the queue to it. Account districts stay.
- **Right — instruments:**
  - **City integrity** = share of *checked* districts with no open critical or
    warning signal. Unchecked districts are excluded, so fog never inflates it.
  - **Sparkline** of integrity across recent sweeps.
  - **Bars:** sorted · confirmed fixed (proven by re-check) · you reported.
    Confirmed and reported are never summed.
  - **Rank progress.**
- **Bottom — ops log:** every tag, confirmation, report and sweep, timestamped
  and labelled by kind.

## 2. Signal or Noise

A panel over the deck for one finding.

1. **The signal:** plain title, district, severity.
2. **Clues** (locked until SCAN CLUE). Only clues the finding's evidence
   supports are shown:
   - **Who made it** — `made_by`: name, verified or not, how.
   - **Where it lives** — the real path from `data`, plus a one-line "what this
     place is" (e.g. `~/Library/LaunchAgents` — things that start when you log in).
   - **What it does** — the finding's plain description.
   - **When it showed up** — only when the scan recorded a date.
   - Network signals add, when the evidence supports them: **Where it's
     going** (remote address and port), **How often / how much** (from a
     connection watch), and **Who owns that address** (the Dossier). These
     come from network pieces N3 and N4.
   Each clue carries a "how to read this" line, e.g. "Verified signature: Apple
   checked who signed this. It tells you who made it, not that it's safe."
3. **Your call:** **MINE** · **LOOK CLOSER** · **THREAT**.
4. **Scout's read:** after tagging, the scan's own view in plain words, saying
   whether it agrees and why. Never "wrong". The person's call stands.

What tags do (tags are game sorting only; they change nothing on the computer):

- **MINE** → the "known" pile. Offers the real "It's mine" step (MarkFlow, with
  its own confirmation question); optional.
- **THREAT** → the threat board with its next move: Breach Protocol if fixable
  (piece 3), guide steps, or account steps (piece 5).
- **LOOK CLOSER** → stays in the queue with a zoom hint (piece 2).

Info signals can be batch-tagged ("these are all fine"); only opened ones earn points.

## 3. Drills

- A drill bank of invented findings, as data files beside the lessons. Each has
  title, district, clues (maker, path, what, when), the right tag, and why.
  Realistic but invented (e.g. an unsigned `upd8r` in a hidden `~/.cache`
  folder set to start at login; a signed Zoom helper in its normal place).
- Same accuracy gate as lessons: paths and "how to read this" lines must be
  traceable to cited guides; a test enforces it.
- Always visibly different: **DRILL** stamp, hatched lime border, "Practice.
  This isn't on your computer."
- Never counted in integrity, the sparkline, or sorted/confirmed/reported.
  They earn drill score, which feeds rank.
- About one per four real signals, at most three per scan, drawn from the same
  districts as the real queue. **DRILL RANGE** on the deck runs more, any time,
  with or without a scan.
- Right tag scores (+ clue bonus); wrong scores nothing, costs nothing, and
  Scout explains the tell.
- No drills about stalkerware, monitoring apps, or being watched.

## 4. Progression

| Earned by | Points |
|---|---|
| Opening a clue (once per finding per scan) | small |
| Tagging after 2+ clues | bonus |
| Correct drill | drill points |
| **Confirmed fix** (re-check proves it) | largest |
| **Reported step** | smaller, labelled YOU REPORTED |
| **Clean sweep**: a re-sweep with no open critical/warning in any checked district | bonus |

Never earns points: removing or deleting anything for its own sake; anything
touching monitoring software (the game isn't offered then); speed.

Ranks: ROOKIE → SIGNAL ANALYST → NETRUNNER → SYSOP → CITY WARDEN. Rank never
drops. Moments (district secured, clean sweep, rank up) get short animations and
a log entry; with reduced motion, a still banner.

Storage: the existing progress store (`device-rescue.game.v1`), migrated to
version 3: points, rank, drill stats, tags keyed by `findingIdentity` (stable
keys, not titles), and sweep history as dates + severity counts only — no
names, no paths. `monitoringSeen` stays in memory only, never persisted.

## 5. Edge cases

- **Couldn't-check modules:** district fogged; a COULDN'T CHECK signal in the
  queue that can't be tagged MINE/THREAT — it's **NOTED**, with a link to the
  couldn't-check lesson.
- **`data.marked_by_user`:** arrives pre-tagged MINE with a MARKED badge, still
  visible. `data.mark_stale: true` returns it to the queue as "changed since you
  marked it".
- **Re-sweep:** tags carry over by identity. A finding that's gone is logged
  "no longer seen", no points; only a re-checked fix is CONFIRMED.
- **Monitoring appears in a re-sweep:** the game is withdrawn immediately and the
  person lands on plain results (existing gate: `gameStillOffered`,
  `postScanView`, `noteMonitoring`).
- **Zero findings:** a clear board and an offer of DRILL RANGE.
- **Hundreds of info findings:** stay folded.
- **Narrow window:** panels stack (queue, city, instruments, log).
- **Windows/Linux:** the same deck; System Settings buttons are Mac-only.

## Accessibility

Keyboard-navigable deck; the queue is a list of real buttons; every graph has a
text equivalent ("City integrity 72%, up from 61% last sweep"); redraws keep
focus (existing controller behaviour); reduced motion respected.

## Testing

- Pure functions: queue ordering, integrity (fog excluded), point ledger
  idempotency (no farming by re-tagging), drill mixing caps, progress v2→v3
  migration.
- Drill accuracy against cited sources, like `game-lessons.test.js`.
- View tests for the deck and the Signal or Noise panel.
- Every existing safety-gate test carries over.
- `desktop/MANUAL-QA.md` gains deck steps.

## Out of scope here

Pieces 2–7 above. Windows/Linux settings deep links. Any change to what the
engine scans.
