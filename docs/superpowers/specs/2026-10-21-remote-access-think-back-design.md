# Remote-access tools: one check, the Think Back walk-through, and placement fixes

Status: draft for owner review (2026-10-21)

## Why

Remote-access tools (TeamViewer, AnyDesk, ScreenConnect, RustDesk…) are how most tech-support scams get in,
and how some abusers watch a screen. Today:

- Windows (`win_remote_access_audit`) knows TeamViewer, AnyDesk, VNC, LogMeIn and Chrome Remote Desktop only.
- macOS has no remote-tool check of its own. Remote-tool names live in `stalkerware_scan`, so every hit is
  held (help district in stealth, Odd Jobs list in standard) and never becomes a mission.
- Nothing says *when* a tool arrived, whether it lets someone in without a click, or when it was last used.
  That's the evidence a person needs to decide "mine, scam, or someone I know".

The owner asked that finding a remote tool walks the person through a quiz about when it would have been added.

## What changes

### 1. Engine: `remote_access_tools` (macOS + Windows)

One module, both platforms, read-only. `win_remote_access_audit` keeps RDP and its existing codes for
compatibility; its per-tool detections move into the new module (the old module stops emitting
`*_installed` codes, keeps `rdp_enabled`). `stalkerware_scan` drops its remote-tool name patterns (it keeps
true stalkerware, employee monitoring and parental-control products) so one tool is reported once.

**Tool list** (data file `modules/security/remote_access_tools/data/tools.json`, each with name, maker, macOS
bundle ids/paths, Windows service/uninstall names, log locations): TeamViewer (incl. QuickSupport), AnyDesk,
ConnectWise ScreenConnect, RustDesk, UltraViewer, Splashtop, LogMeIn / GoTo (incl. Rescue), Zoho Assist,
Supremo, AeroAdmin, Ammyy Admin, Remote Utilities, SimpleHelp, HopToDesk, BeyondTrust (Bomgar), Atera,
NinjaOne, Action1, Chrome Remote Desktop, RealVNC, TightVNC, UltraVNC, Parsec. Windows Quick Assist is built
in, so it's reported only from use (its recent-session evidence), never from presence.

**Evidence per tool** (all read-only, each step time-budgeted, missing evidence says "couldn't tell", never
"no"):

| Field | macOS | Windows |
|---|---|---|
| `added_on` (date only) | Spotlight `kMDItemDateAdded`, else file birth time; install receipts | Uninstall key `InstallDate`, else folder creation time |
| `lets_in_unattended` | a LaunchDaemon/LaunchAgent for the tool, or its unattended/password setting | an auto-start service for the tool |
| `running_now` | process list | process list |
| `last_incoming` + `incoming_count` | TeamViewer / AnyDesk connection logs (date and count only) | same logs, plus Quick Assist |
| `one_off` | the app sits in Downloads and has no service (a run-once support download) | same |
| `made_by` | existing attribution (verified signature by path) | same |

Remote IDs and peer names in connection logs are **not** copied into findings (they're the other party's
identifiers; the person can open the log themselves; and nothing identifying the other party is written into
exports by accident).

**Severity**: warning per tool; critical when two or more tools are present (the known scam pattern), or a
tool lets in unattended *and* was added in the last 30 days. Info only for a tool that's verified-signed,
one-off, not running and never connected. Every finding carries the removal warning (`removal_alert` via
`safety_scope`): a remote tool can be an abuser's way to watch.

Codes: `security.remote_access_tools.tool_found`, `.several_tools`, `.unattended_recent`, `.running_now`.

### 2. Desktop: the Think Back walk-through

Remote tools become their own mission type, **`guestbook`** — city name **The Guest Book** ("who was let in,
and when"); standard name **Remote access**. It's a new mini-game in the missions framework (contract rules
apply: pure, link intents only, 2–3 decisions per step, labels ≤4 words). It replaces Switchboard as the home
for remote-tool findings; Switchboard keeps sharing, RDP, proxy, DNS and hosts.

**The card** shows the evidence first, in plain words: "Added on 3 March", "Can let someone in without you
clicking yes", "Last let someone in: 12 March (4 times)", "Running now", "Made by AnyDesk Software GmbH
(checked)". Missing evidence reads "Couldn't tell when this was added".

**If it's running now**, the first line says so and offers one step before anything else: disconnect the
internet (link intent to the network pane), so nobody can watch the rest. The quiz waits.

**The questions** (one at a time, each 2–3 answers; the date is filled in from `added_on`):

1. *Think back to around 3 March. How did this get here?*
   - "I installed it" → Q2
   - "Someone helped me" → Q3
   - "I don't remember" → Q4
2. *Do you still use it?* "Yes" → outcome **Mine**. "No" → outcome **Not needed**.
3. *Who was it?*
   - "IT or a store I contacted" → outcome **Mine**.
   - "Someone who contacted me" (a call, pop-up, email or text) → outcome **Scam**.
   - "Someone I know" → outcome **Someone I know**.
4. *Around then, did a call, pop-up, email or text say something was wrong with your computer, an account, a
   refund or a payment?* "Yes" → **Scam**. "No" or "Not sure" → **Not sure**.

Wording stays neutral: it never says partner, ex, abuser or stalker, because a running remote tool may be
showing this screen to someone.

**Outcomes** (each one decision, with steps and links done for the person):

- **Mine**: mark it as yours (MarkFlow; remembered until the evidence changes). If it lets in unattended, a
  step: turn off unattended access or set a new password in the tool's own settings.
- **Not needed**: remove it (FixFlow, removal warning shown first), then recheck.
- **Scam**: in order, from a *different* device where possible: call your bank on the number on your card;
  change your email password, then other accounts; remove the tool (removal warning, then recheck — the
  recheck also looks for a second tool, a common scam trick); report it (look-up intents: FTC
  reportfraud.ftc.gov, Action Fraud, Canadian Anti-Fraud Centre). Links to the `password-asker` lesson.
- **Someone I know**: no removal offered first. "Talk to an advocate before removing it — removing it can
  alert them", the hotline as text, keep evidence (the card's dates), and "Later". This item then follows the
  monitoring rules: no points, not remembered across scans.
- **Not sure**: the safe middle: turn off unattended access (not remove), and recheck next time. Offer
  "Show me how to look at its connection list".

**Stealth (city) mode**: remote tools stay held in the help district (as monitoring items do today) with the
evidence card and "talk to an advocate". The Think Back questions don't run in city mode. A person who chose
stealth has already told us their situation.

**Practice**: first time, a two-item practice round (made-up TeamViewer added after a "refund" call; made-up
RustDesk the person installed), Mac and Windows wording (`practiceByPlatform`).

**Points**: Mine / Not needed / Scam outcomes pay as normal decisions; confirmed removal pays the confirmed
bonus. Someone I know pays nothing (monitoring rule).

**Lesson**: `password-asker` gets `remote_access_tools` in its `modules` (both platforms), and its "what the
scan looks for" line drops "On Windows".

### 3. Placement fixes

| Finding | Today | After |
|---|---|---|
| Adware from bloatware modules (Genieo, Pirrit, MacKeeper…) | Junkyard (clutter) | Evidence Locker (by code) |
| Root certificates (`certificate_audit`, `certificate_trust_audit`) | Seal Check | Switchboard (a new "trust" line kind) |
| Device management (`mdm_enrollment*`) profiles installed | Odd Jobs / notes | Switchboard ("trust" line), warning when a profile isn't from a known employer/school MDM |

## Safety rules this keeps

Removal warning on every remote-tool removal and in fix confirms; never a removing default; no
partner/abuser words on screen; nothing reads "safe" because evidence is missing; stealth holds remote tools;
"Someone I know" never pays or is remembered; log contents beyond dates and counts never leave the machine.

## Out of scope (next)

Browser notification-spam permissions, info-stealer and clipboard-hijacker indicators, more scareware,
Windows browser/certificate/MDM parity, and App Store apps holding sensitive permissions.

## Testing

Engine: synthetic fixtures per tool and platform (paths, services, log lines with made-up IDs), each evidence
field present / missing / unreadable, severity rules, the de-duplication with `stalkerware_scan` and
`win_remote_access_audit`, catalogs and manifest. Desktop: contract checks for `guestbook`; each quiz path
reaches its outcome; dates filled from evidence and "couldn't tell" when missing; running-now step first;
city mode holds and never shows the quiz; CITY_FORBIDDEN and disk-words; no-double-claim covers; screenshots
of each outcome in standard mode and the held card in city mode.
