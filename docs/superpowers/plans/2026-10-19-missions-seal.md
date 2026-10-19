# Seal Check (the `seal` mini-game) — implementation plan

> **For agentic workers:** implement task by task, test first. Each task: write the failing test, run it and see it
> fail, implement, run it and see it pass, commit. Do not edit files outside the "Files" list.

**Goal:** a mini-game for app seals (code signatures, Gatekeeper, added root certificates, Windows Authenticode and
unsigned drivers). Each item shows "what the maker signed" next to "what's on disk", a plain verdict
(tampered / old format / unknown maker / unsigned), and 2–3 decisions: **Reinstall from the maker** (a maker-site
look-up intent plus steps), **Mine, I know why** (mark), **Look closer** (evidence + checklist).

**Spec:** `docs/superpowers/specs/2026-10-19-little-missions-and-minigames-design.md` (table row `seal`, "Each
mini-game" → seal). **Contract:** `desktop/renderer/missions/contract.js`. **Brief:**
`.superpowers/sdd/missions-common.md`.

**Architecture:** one pure ES module, `desktop/renderer/missions/games/seal.js`. A `classify(finding)` step turns a
finding into a *verdict* record (`{ verdict, maker, disk, means }`), driven by the finding `code` (and `data.check`
for code-less Windows driver findings). `decisions`, `research`, `render` and `summary` all read that record, so the
words for one verdict live in one table. No DOM, storage, globals, network or clipboard. Practice items are inline
synthetic items in the module; test fixtures are synthetic scan-shaped findings under
`desktop/test/fixtures/missions/seal-*.json`.

**Tech stack:** plain JS ES modules, `node:test`, the contract helpers (`makeItem`, `testContext`,
`runContractChecks`, `checkCityWords`).

## Files

- Create `desktop/renderer/missions/games/seal.js`
- Create `desktop/renderer/missions/games/seal.css`
- Create `desktop/test/missions-seal.test.js`
- Create `desktop/test/fixtures/missions/seal-mac.json`, `desktop/test/fixtures/missions/seal-win.json` (synthetic)

## Global Constraints

- Games are pure: return Decisions/Effects/link INTENTS only; never URLs (`href`/`url`), never act.
- Every scan value goes through `ctx.esc` (which also makes control/bidi characters visible). Never render
  `finding.description`: the engine's own prose can carry hotline/advocate sentences, which city mode forbids.
- City mode: game words only (`CITY_FORBIDDEN`); look-ups are intents (the runner shows them as text in city).
- Removal warning: an item with `removal_alert` / `safety_note`, **and every tampered critical** (controller
  ruling: a tampered app can be a trojaned monitoring tool), never gets a removing or replacing decision first.
  The reinstall/remove-trust effect carries `removal: true` so the runner shows the warning in its confirm.
- Honesty: `data.apps_checked < data.apps_total` → "This check looked at N of M apps. The rest weren't checked."
  An item from a check that didn't finish (`item.complete === false`, `item.unfinished`, `finding.complete ===
  false`, `data.incomplete`) → "This check didn't finish." A summary never says "all clear".
- 2–3 decisions per item, labels ≤ 4 words, both modes. No time words. Teach once: one short line + lesson link.
- Mac and Windows: `code_signature_audit` on win32 (Authenticode HashMismatch / NotSigned / other status),
  `win_rootkit_check.unsigned_drivers`, code-less `win_driver_check` unsigned drivers (handled, not claimed), with
  `windows-apps` / `windows-update` / `windows-security` panes.

## Review Focus

- The tampered critical never leads with Reinstall, even without `removal_alert` on the item.
- No engine prose (description) in output; hostile strings inert; city words clean (practice included).
- Coverage line uses the engine's real fields (`apps_checked`, `apps_total`).
- `covers` claims only real codes; `suspicious_processes` is narrowed to `unsigned_apps`.

## Covers

```js
covers: [
  { module: 'code_signature_audit' },                // macOS codesign/spctl and Windows Authenticode
  { module: 'gatekeeper_quarantine_check' },
  { module: 'suspicious_processes', codes: ['security.suspicious_processes.unsigned_apps'] },
  { module: 'certificate_audit' },
  { module: 'certificate_trust_audit' },
  { module: 'win_rootkit_check', codes: ['security.win_rootkit_check.unsigned_drivers'] },
]
```

Real codes (from `modules/security/*/__init__.py`): `code_signature_audit.{tampered_binary, unsigned_system_app,
gatekeeper_rejected, old_signature_format, inventory}`; `gatekeeper_quarantine_check.{gatekeeper_disabled,
sip_disabled, quarantine_removed, gatekeeper_assessment_failed, …_enabled/_working}`;
`suspicious_processes.unsigned_apps` (data.apps `[{path, name}]`); `certificate_audit.{expired_certificates,
user_root_cas}` (data.certificates `[{name, expiry?}]`); `certificate_trust_audit.{suspicious_certificates,
self_signed_root_certs, expired_certificates, user_added_certs}` (data.certs `[string]`);
`win_rootkit_check.unsigned_drivers` (data.drivers `[string]`). `win_driver_check` emits no codes, so it can't be
narrowed to its unsigned-driver finding; the game handles `data.check === 'unsigned_drivers'` but does not claim
the module (noted for the foundation).

## Verdicts

| Verdict | From | Maker side | Disk side | Decisions (in order) |
|---|---|---|---|---|
| `tampered` | tampered_binary (mac + win HashMismatch) | maker's seal / "Signed by …" | changed after signing | Look closer · Mine, I know why · Reinstall from the maker (`removal`) |
| `old-format` | old_signature_format | sealed under old rules | today's macOS can't check it | Reinstall · Mine · Look closer |
| `unsigned` | unsigned_system_app, unsigned_apps, unsigned drivers | no seal | installed for everyone | Reinstall (driver: Update the driver) · Mine · Look closer |
| `unknown-maker` | gatekeeper_rejected, added/self-signed/interception roots | a maker the system doesn't trust | blocked / trusted for every site | apps: Reinstall · Mine · Look closer; certs (alerting): Look closer · Mine · Not mine (`removal`) |
| `expired` | expired certificates | seal ran out | trusted for nothing | Leave it · Look closer |
| `checker-off` | gatekeeper_disabled, sip_disabled | the seal checker | switched off | Turn it back on · Mine, I know why · Look closer |
| `checker-unsure` | gatekeeper_assessment_failed, other | the seal checker | gave no clear answer | Check again · Look closer |

"Mine, I know why" is `{ kind: 'mark' }` when the finding carries `markable`, else `{ kind: 'keep' }` (no
signature finding is markable in the engine today — noted for the foundation/engine).

## Task 1: fixtures and the shape/contract test

**Test** (`desktop/test/missions-seal.test.js`):

```js
const load = async () => ({ C: await import(url('contract.js')), G: (await import(url('games/seal.js'))).default });
test('seal passes every contract check over the fixtures and its practice', async () => {
  const { C, G } = await load();
  assert.deepStrictEqual(C.runContractChecks(G, fixtureItems(C)), []);
});
test('covers claims real modules, narrowed where shared', async () => { /* exact covers list above */ });
```

Fixtures: `seal-mac.json` (tampered, old format with `apps_checked: 40, apps_total: 120`, unsigned, gatekeeper
rejected, gatekeeper off, SIP off, unsigned_apps, user_root_cas, interception cert, expired cert) and
`seal-win.json` (Authenticode HashMismatch, NotSigned, NotTrusted, win_rootkit unsigned drivers, code-less
win_driver_check unsigned drivers). Paths `/Applications/Example*.app`, `C:\Program Files\Example\…`.

Implement the module skeleton (`type`, `title`, `concepts: ['who-made-it', 'couldnt-check']`, `covers`, the
verdict table, `classify`, `decisions`, `research`, `render`, `summary`, `practice`). Run → pass. Commit.

## Task 2: verdicts and decisions

**Tests:** each fixture classifies to its verdict; the tampered critical's first decision is not the reinstall,
with or without `removal_alert`; reinstall effect is `{ kind: 'link', link: { kind: 'lookup', source:
'maker-site' | 'web' }, removal }`; maker-site only when `made_by` is verified; certificates with `removal_alert`
put "Not mine" last; old format leads with Reinstall; labels ≤ 4 words in both modes.

Implement, pass, commit.

## Task 3: research and honesty

**Tests:** `rows` come from `ctx.evidenceRows(finding, { mode })`; `what` is the verified `made_by[].what` else
"Unknown maker"; links include the `who-made-it` lesson; Windows items get `windows-apps`/`windows-update` panes;
coverage line "looked at 40 of 120 apps"; unfinished line; no "all clear" in summaries.

Implement, pass, commit.

## Task 4: render, city words, practice and summary

**Tests:** render shows both sides with headings "What the maker signed" / "What's on disk" (city: "The maker's
seal" / "What's here now") and the verdict; description never rendered; city output (every fixture and practice
item, every practice step's `say`) passes `checkCityWords`; practice has 3 synthetic items (old-format game,
tampered app, unsigned developer build) with a script whose `expect` ids exist in that item's decisions; summary
counts decisions and mentions partial coverage.

Implement, add `seal.css` (uses the game variables; side-by-side grid collapsing to one column under 560px),
pass, commit.

## Task 5: self-review, full suite, visual check

`cd desktop && npm test && npm run check-game-files`. Preview HTML in the scratch folder rendering practice and
fixture items in both modes with `seal.css` + game variables; screenshot with Playwright at default and 800px.
Write the report.
