# Consumer security game: overview

**Status:** in review, written 2026-10-16.
**Goal:** Device Rescue becomes a consumer security game. A frightened, non-technical
person fixes their real computer and their real accounts by playing it, and the
progress they see is honest.

Device Rescue already finds problems on the computer and fixes them, one agreed
change at a time. Reclaim City
(<https://play.multiversegames.ai/reclaim-city/>, repo
`lizTheDeveloper/privacy-the-game`) already turns account security and privacy
into a game: a city of districts, with a briefing, a mission and a debrief for each
building. This work puts the two together inside the desktop app.

## The three specs

| Spec | What it adds | Depends on |
| --- | --- | --- |
| [A. Device missions](2026-10-16-game-mode-device-missions-design.md) | Real scan findings become Reclaim City missions. A re-check proves each fix. | none |
| [B. One city](2026-10-16-game-mode-one-city-design.md) | The device districts and Reclaim City's account districts on one map, with device checks proving some of the game's own missions. | A |
| [C. Training grounds](2026-10-16-game-mode-training-grounds-design.md) | Teaching missions come before the scan, and the real scan is the final boss. | A (B helps but isn't needed) |

Each spec gets its own implementation plan and is built in this order: A, B, C.

## Rules that hold across all three

1. **The game never fixes anything on its own.** Every change to the computer goes
   through the existing per-fix confirmation (`desktop/renderer/fix-flow.js`), and
   every "this is mine" through `mark-flow.js`.
2. **A device mission counts as done only when the engine says so.** A mission the
   person reports on themselves (an account mission) is always shown apart from a
   verified one.
3. **"Couldn't check" is never shown as safe.**
4. **Nothing leaves the computer.** The game runs from files bundled in the app.
   Reclaim City's analytics switch-off is set before any game code loads, the
   Sentry/GlitchTip global is never loaded, and the app's CSP stays
   `default-src 'self'`.
5. **The game is never offered to someone who may be watched.** That covers the
   "watching me" worry, the iPhone spyware worry, and scans that find monitoring
   software. The same rule already hides the Reclaim City link (`learnMoreFor` in
   `desktop/renderer/app.js`).
6. **The person can always drop back to the plain list view.**

## How the game code gets in

Reclaim City is added as a git submodule at `desktop/vendor/reclaim-city/`, pinned
to a commit on its `origin/main`. Device Rescue reuses its screens, components,
helpers, CSS and art, and writes its own small controller, so the game's
`src/app.js`, which carries the analytics, error reporting and the backend code for
shared stats, is never loaded. Spec A has the details.
