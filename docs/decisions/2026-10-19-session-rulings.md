# Calls made during the working session (2026-10-18/19) — confirm or change

These were decided so work could keep moving. Each one is easy to reverse. The hourly loop copies them into
`docs/decisions/2026-10-19-open-decisions.md` (branch `decisions`) so there is one list to review.

## Product and safety

1. **App signature check: hitting the 60-app limit counts as "didn't finish".** On most Macs the Gatehouse is then
   never fully secured and a CLEAN SWEEP is rare. Honest (the other apps weren't checked), but less rewarding.
   Options: keep; or count the limit as finished and show "checked 16 of 110 apps" as a note.
   **Owner (2026-10-19): keep.**
2. **VS Code, Steam and other apps known only by their self-reported ID stay held in stealth mode** (in the help
   district, with "talk to an advocate"). Letting them out by name was a security hole (a keylogger can call itself
   Chrome). The real fix is confirming identity from macOS's own permission record (csreq) — the hourly loop is
   researching it. Options: keep until csreq lands; or show a gentler line for familiar names meanwhile.
   **Owner (2026-10-19): these are not monitoring software — verify them via csreq now** (merged). VS Code verified; Steam's "Mac App Store or Valve's Developer ID" requirement accepted by the owner (2026-10-20).
3. **Your NextDNS profile shows as a warning** ("Your DNS goes through a filtering profile"), markable as yours.
   A DNS profile's owner sees every website name looked up, so an abuser could use one to watch browsing.
4. **The removal warning stays on tampered-app findings** (a tampered app can be a disguised monitoring tool).
5. **Fixes and "It's mine" are refused while a scan runs** (not queued for later).
6. **No checkboxes on the results-while-scanning preview** (nothing can be acted on until the scan ends).
7. **Points:** monitoring software never pays and its answers aren't remembered across scans; other items with a
   removal warning (remote-access tools, unknown background tasks) pay normally. **City integrity rises only on a
   confirmed re-check**, never on a decision alone — so "decided" and "fixed" are shown separately.
8. **Sleep / Power Nap / screen-off settings go to Odd Jobs**, because Lock Run has no sleep lock yet. Option: add a
   sleep lock to Lock Run (small) and move them. **Owner (2026-10-19): yes** (branch `lockrun-sleep-windows`).
9. **"Mine" on an item with a removal warning asks a one-line confirm** instead of the full "It's mine" panel.
10. **Lock Run practice is Mac-only**; Windows players get the Mac practice wording. Option: add Windows practice. **Owner (2026-10-19): yes** (branch `lockrun-sleep-windows`).

## Known rough edges (no decision needed unless you want to prioritise)

- Notes count can differ by one between the missions and the scan (290 vs 289 on your scan).
- Standard mode: the CRITICAL + WARNING chips can add up to less than TO DO (held items).
- A fixed item can show both the old RECLAIMED row and the new DONE row on the district screen.
- Editing the Mac hosts file still goes through Terminal (`sudo nano /etc/hosts`); a plainer route needs engine work.
- Chrome's newer `host_permissions` aren't read, so some all-websites extensions aren't flagged (engine; hourly loop).

## Releasing

11. **Merging to main and the release are yours to do.** `profile` contains reclaim-city + checklists + player
    profile + little missions + all fixes. Merging `profile` into `main`, tagging a release (`v*` builds the
    installers), and publishing the renamed download page / themultiverse.school `/x/` page are outward-facing.
12. **Publishing your profile to the school (Task 22)** waits on fixes in the school repo (shape fields, object type,
    merge-not-replace import, provenance). Publishing stays switched off until then.
13. **App icon art** (`desktop/build/icon.png`) is still needed from you.

## Housekeeping

14. **Git incident:** an agent ran a repo-wide cleanup (reflog expire + gc) while removing your device data from a
    branch. No branch or commit was lost, but git's undo history and any stashes in this repo (including other
    sessions') are gone. A rule now forbids this.
15. **Disk:** free space is around 44–50 GB, at or under your 50 GB floor. Old worktrees outside this work
    (`rescue-stick`, `clear-the-list`, `n3-level-1`, `reclaim-city`, `checklists`) could be removed if done.
16. **The hourly routine doesn't stop by itself.** Pause it at https://claude.ai/code/routines/trig_01QNTm3gzjWE89jv3abK7DFb
    when you've reviewed this.
