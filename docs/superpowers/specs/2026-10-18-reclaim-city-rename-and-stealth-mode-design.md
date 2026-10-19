# Reclaim City: the rename, the safety question, and stealth mode — design

Status: drafted from conversation 2026-10-18, pending the tester's review.
Builds on game mode (`2026-10-16-game-mode-*.md`) and the command center
(`2026-10-18-command-center-signal-or-noise-design.md`).

## Why

Two problems, one answer.

1. Domestic-violence safety text shows on most routes today ("hacked", "not
   sure", the scan banner, finding descriptions). Most people aren't in that
   situation, and being confronted with it on every screen is noise at best and
   distressing at worst.
2. The people who *are* in that situation need the opposite: help that's easy to
   reach and an app that doesn't look like a security tool to whoever is
   watching. The Six Roses guide (https://themultiverse.school/x/six-roses) already
   works this way: it's a real safety guide that looks like a rose apple tart
   recipe.

So the whole app becomes a game, **Reclaim City**, for everyone. Nobody stands out
for having switched on a special mode. Inside, one gentle question decides how
much safety text a person sees, and people worried about a partner get stealth
mode: the game is the cover, and the help lives inside it under a disguise
generated for that install.

## 1. The rename: Device Rescue → Reclaim City, everywhere

- **Desktop app:** `productName`, window title, menus, About, installer and
  artifact names (`ReclaimCity-mac-arm64.dmg`, `ReclaimCity-mac-x64.dmg`,
  `ReclaimCity-windows-x64.exe`), Dock name, icon (a game icon, not a shield).
- **Kept stable on purpose:** the installer's `appId` (so updates and OS
  permissions carry over) and the user-data location (set explicitly so saved
  progress and the game store `device-rescue.game.v1` survive the rename). The
  storage key keeps its name; it's never shown.
- **Everything people read:** README, download page (GitHub Pages `site/` and the
  themultiverse.school `/x/` page), docs site, CONTRIBUTING, AGENTS.md wording,
  in-app copy ("Device Rescue looks over your Mac…" → Reclaim City), release
  notes. The plain checkup is presented as **Plain view**, one way to play.
- **Not renamed:** the engine CLI `rescue` and the Python package (existing
  installs and AI-assistant instructions depend on it), and the GitHub repository
  (renaming it changes every link; a separate decision for the owner).
- **Release links:** the stable `releases/latest/download/…` names change with the
  artifacts; the download page and README move to the new names in the same
  release. Old links stop working at that release, so the page must ship with it.
- Publishing the site, the `/x/` page and a release are outward-facing and wait
  for the owner's go-ahead.

## 2. The safety question

Asked once, right after the worry screen, and remembered:

> Is there someone in your life you're worried might be watching your devices — a
> partner, an ex, a family member, someone you live with?

| Answer | Mode |
|---|---|
| No | Standard |
| Yes, that's part of it | Stealth |
| I'd rather not say | Standard, with safety notes cut to one line + "more" |

- The worry "I think someone is watching me" goes straight to stealth mode
  without asking.
- **Stored innocuously:** as a display preference, `city` or `standard`. The words
  partner, safety, stalking or watching never appear on disk.
- **Changing it:** a quiet "Something changed?" link on the worry screen opens the
  question again. No nagging.
- **Re-check when there's a reason:** if monitoring software turns up and the mode
  is standard, ask once: "We found something that can be used to watch a
  computer. Is that something you know about?" The answer can switch to stealth.
  This replaces today's rule that withdraws the game when monitoring is seen.

## 3. Standard mode: much less DV text

- Safety paragraphs, the scan-screen banner and hotline lines are hidden
  (`wantsSafetyNote` becomes mode-driven instead of worry-driven).
- **Kept, always:** a finding that *is* monitoring software carries one line:
  "Removing this can alert whoever installed it. Read this first." with the full
  note behind it. This is the moment it matters.

## 4. Stealth mode: the game is the cover

- **Opens into the game.** Straight to the command deck. To anyone glancing, it's
  a city game.
- **A generated help district.** At first entry into stealth mode the install
  picks the district's name, look and voice from a large pool (e.g. The Night
  Market, Pier 9, Clocktower Commons, The Observatory…), seeded locally, so
  there's no fixed name to search for or recognise across installs. The pool
  holds only names that fit the city; none of them hint at safety.
- **What's inside it,** written in that district's game voice, sourced from the
  Six Roses guide:
  - quiet first steps: keep a hidden record; a safety phone; code words with a
    trusted friend; a separate "freedom" email made on a device that isn't
    yours; preserving evidence before changing anything;
  - help: 911, National DV Hotline 1-800-799-7233 (text START to 88788),
    TechSafety.org, NNEDV Safety Net, WomensLaw.org, Clinic to End Tech Abuse,
    and the Six Roses guide itself (opens in the browser; its title reads as a recipe, though the page itself is plainly a safety guide);
  - "Leaving is the most dangerous time. Plan carefully with DV advocates."
- **Monitoring findings never say "remove".** In stealth mode a monitoring
  finding goes to the help district as "Don't remove it yet. Talk to an
  advocate first," with how to capture evidence of it quietly. No fix, no
  "It's mine" prompt, no points for it.
- **Panic key.** On any help-district screen, Esc or a "back to the game" button
  swaps instantly to the ordinary deck, with focus on the map.
- **Quiet traces.** No notifications. Ops log and history entries for the help
  district are generic ("Visited Pier 9"). Nothing written names what was read.
- **Safety gate reversed on purpose.** Today the game is withdrawn when someone
  may be watched; in stealth mode it stays on, by design. The gate tests are
  rewritten to enforce the new rules: stealth never prompts removal, never shows
  a fix for monitoring software, and always offers the help district.

## 5. Copy rules

Plain, calm, no fear. Every hotline, resource and step is traceable to the Six
Roses guide or an existing project guide; a test checks the help-district text
against those sources, like the lesson accuracy test.

## 6. Testing

- Mode selection: every answer, the "watching" worry shortcut, the re-check on
  monitoring, the "Something changed?" link.
- Storage: only `city` / `standard` is written; a test scans everything the app
  writes for forbidden words.
- Standard mode: no DV text except the one-line note on monitoring findings.
- Stealth mode: opens to the deck; the help district name comes from the pool
  and is stable per install; monitoring findings route to it with no
  fix/mark/points; Esc returns to the deck; log entries are generic.
- Rename: no user-visible "Device Rescue" left in the app, site or README
  (a test greps shipped copy); appId and user-data path unchanged.

## Out of scope

Hiding the app from monitoring software that watches running processes; a
per-install app icon or name; renaming the GitHub repo or the CLI.

## Note for the Six Roses guide (not this repo)

The guide recommends resets and new devices but never warns that removing
monitoring software or trackers can alert whoever installed it; it warns about
timing only for the credit freeze. Worth a sentence. It also cites an "85% of
survivors" figure without a source.
