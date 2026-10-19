# Retiring Plain view Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Everyone plays the city. The welcome flow goes worry → safety question → checkup → the city, with no Plain view route or toggle. The results screen survives only as the city's LIST tab: a read-only, literal list of everything the checkup found.

**Architecture:**
- `app.js` keeps the worry screen, the safety question, the scan screen (the fallback when the game can't draw, and where a running scan's progress lives) and the results screen, which becomes the **LIST view**. Every worry, the iPhone one included, starts its scan in the game when the game is ready (`gameOfferedFor` is true for any worry). `postScanView` never lands on the list unless the city can't be drawn or the person left it.
- The LIST view is built from `NotChecked.displayItems` (via `plainCards`) with `Evidence` blocks, the honest not-checked box, the removal-warning banner (standard) or full notes (city), and per-card "Get help" (Ask / Copy for any AI) under the existing held and monitoring exclusions. No fix, mark, "I did this", checkboxes, bulk bar, "Cleared" list or paging. In city mode a held item is drawn as the help district draws it (`Evidence.renderEvidence(rows, { held: true, title })`), with the hold line and its help.
- "Back to the city" on the LIST and Esc (both modes) return to the city. When the city is already drawn and the scan hasn't changed since, the host just shows the city again (the controller keeps its own screen); when a re-run on the LIST changed the scan, `RescueGame.show(doc)` redraws it.
- `RescueHost.leaveGame()` (the city failed to draw, or the game's old PLAIN VIEW buttons until the foundation removes them) goes to the LIST when there is a finished scan, the scan screen while one runs, otherwise the scan screen.
- Removed: the route choice on the welcome screen, `clear-list.js`, the Plain fix and mark panels' UI on cards (the flows `FixFlow` / `MarkFlow` and main's gates stay; the foundation's runner uses them), `game/profile/plain-panel.js` and the Your-progress dialog (YOUR FILE replaces it), `RescueHost.listCounts`, the iPhone "Start" button on the list (the city's waiting signal starts that sweep), `Checklist.preserveFocus` (only the Plain cards' re-renders used it), and their CSS.

**Tech Stack:** Electron 41, plain JavaScript classic scripts + ES modules, `node --test`.

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md`, "Retiring Plain view" and owner's pick 4. Common brief: `.superpowers/sdd/missions-common.md`.

## Global Constraints

- "The welcome flow goes worry → safety question → checkup → the city. No "Plain view" route or toggle."
- "`standard` mode is the city with plain words allowed and safety notes as today; `city` mode is stealth."
- "The LIST tab stays: a read-only literal list (from `displayItems`, with evidence blocks, no fix/mark controls; in stealth, held items as the help district shows them) so a person can always see everything."
- "the fix and mark FLOWS (FixFlow, MarkFlow, main-process gates) stay — the runner uses them. The Your-progress dialog is replaced by YOUR FILE."
- "Tests for removed screens are deleted with them; tests for kept behaviour (safety warning, honesty, stealth, gating, step-fill, evidence) are moved to the city equivalents, never dropped."
- Files owned: `desktop/renderer/{app.js,index.html,styles.css,clear-list.js,checklist.js,ask.js,copy-ai.js,quiet-notes.js}`, `desktop/renderer/game/profile/plain-panel.js`, and their tests. Never edit `game/**` (but plain-panel.js), `missions/**`, `evidence.js`, `not-checked.js`, `step-fill.js`, `fix-flow.js`, `mark-flow.js`, `main.js`, `preload.js`, `engine-runner.js`.
- Never an all-clear while a check didn't run, finish or start. No clipboard for monitoring evidence in city mode. No time words in copy.

## Review Focus

1. **The game can't draw.** The person must still see everything: `leaveGame` and a `false` from `scanDone`/`show` land on the LIST (or the scan screen with progress while a scan runs). Pinned in Task 1.
2. **Held items in stealth on the LIST.** No copy button, no Get help, no steps, no fix; the evidence block is the help district's "write this down" block. Pinned in Task 2.
3. **Back to the city mid-scan.** Esc / "Back to the city" while the game's sweep runs must not call `RescueGame.show` (that ends the game's scan state); it shows the city host again. Pinned in Task 1.
4. **Kept behaviour tests moved, not dropped:** safety banner and lines, honesty lines, stealth exclusions, partial-results gating, step-fill, evidence, product name, disk words.

## Decisions

- Steps ("Show me how, step by step") stay on LIST cards as text: they're instructions, not controls, and keep step-fill covered on the list. No "Or fix it yourself" wording (there's no fix button).
- "Run them again" for checks that took too long stays: it is read-only, and the city has no equivalent. A changed scan marks the city stale, so the way back redraws it.
- The iPhone backup's "Start" moves to the city only (its waiting signal already offers it); the LIST keeps the "not started" line, never "couldn't run".
- The step dots' last label becomes "The city".

## Needs from the foundation (game/controller.js, game/views/**)

- Remove the PLAIN VIEW buttons (`data-act="leave"` in `views/boss.js` and `views/training.js`). Until then `leaveGame` sends them to the LIST.
- Optional: a `RescueGame.resume()` entry that re-renders the current screen without resetting it, so "Back to the city" can redraw after the window was hidden. The host uses `showScreen('city')` without it.

---

### Task 1: One route into the city

**Files:** `desktop/renderer/index.html`, `desktop/renderer/app.js`, `desktop/test/list-view.test.js` (new), `desktop/test/first-question-flow.test.js`, `desktop/test/game-worry-scan.test.js`, `desktop/test/situations.test.js`.

- [ ] Failing tests (`list-view.test.js`): the welcome screen has one start button (`btn-get-started`) and no "Plain view" text; `gameOfferedFor` is true for the iPhone worry; `postScanView` lands on `city` for every worry when ready; `leaveGame` with a finished scan shows `results`; with a scan running shows `scan`; Esc on the LIST in standard mode returns to the city; Esc mid-game-scan shows the city without `RescueGame.show`.
- [ ] Implement: welcome markup (one button), `gameOfferedFor`, `postScanView`, `worryStartsGameScan` (no `wantsCity` needed), `leaveGame`, `backToCity()`, Esc handler for both modes, "Back to the city" button replacing "See it as a city".
- [ ] Run `node --test test/list-view.test.js test/first-question-flow.test.js test/game-worry-scan.test.js`; commit.

### Task 2: The LIST is read-only and literal

**Files:** `desktop/renderer/app.js`, `desktop/renderer/index.html`, `desktop/renderer/quiet-notes.js`, `desktop/test/list-view.test.js`, `desktop/test/plain-ux-round*.test.js`, `desktop/test/partial-results.test.js`, `desktop/test/stealth-mode.test.js`, `desktop/test/removal-warning.test.js`, `desktop/test/quiet-notes.test.js`, `desktop/test/ux-sec.test.js`.

- [ ] Failing tests: a card never carries fix / mark / "I did this" / a checkbox / a bulk bar, in either mode; every item of `displayItems` is drawn (no "Show more"); a held card in city mode carries the held evidence block (`data-held` / "Write this down"), the hold line and help, and no copy, Get help or steps; the not-checked box and the not-started line are unchanged.
- [ ] Implement: strip `renderSeverityGroup` of controls, paging, `ClearList`, `FixFlow.attach`, `MarkFlow.attach`, the bulk bar; held cards render `Evidence.renderEvidence(rows, { held: true, title })`; drop `QuietNotes.lineHtml`'s `first` branch.
- [ ] Move kept-behaviour tests from removed screens to the LIST; delete the ones for removed controls. Commit.

### Task 3: Remove Plain-only code

**Files:** delete `desktop/renderer/clear-list.js`, `desktop/renderer/game/profile/plain-panel.js`, `desktop/test/clear-list.test.js`, `desktop/test/profile-plain-panel.test.js`; edit `index.html` (scripts, dialog, progress link), `checklist.js` (`preserveFocus`, `focusKey`), `copy-ai.js` (person_said), `ask.js` (no time words), `styles.css`, `desktop/test/checklist.test.js`, `desktop/test/page-harness.js`.

- [ ] Move the publishing-seam guard from `profile-plain-panel.test.js` to `list-view.test.js`.
- [ ] Remove the files and their references; CSS for removed classes; run the full suite and `npm run check-game-files`; commit.

### Task 4: Verify

- [ ] Self-review against the spec; full suite green.
- [ ] Render the LIST for synthetic items in standard and city mode (scratch preview), look at it, note what was seen in the report.
