# Remote-access tools and the Think Back walk-through: implementation plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** One engine check, `remote_access_tools`, reports each remote-access tool on macOS and Windows with the evidence a person needs: when it was added, whether it lets someone in without a click, whether it's running, and when it last let someone in. Then a new Guest Book mini-game walks the person through "think back to around <date>: how did this get here?" to one clear next step. The same branch fixes three placements.

**Architecture:** The engine module reads a data file of tools and, for each tool, collects evidence through small methods that tests can replace. The serializer and `safety_scope` attach the removal warning, as they do for every other check. On the desktop, the runner learns two things: a question effect (`ask`) that keeps the same item on screen, and an `unpaid` flag. `guestbook.js` is an ordinary contract game built on them. In city mode the item is held in the help district, so the quiz never shows there.

**Tech Stack:** Python 3 engine (`rescue`, pytest, ruff, uv). Electron renderer ES modules (`node --test`).

**Spec:** `docs/superpowers/specs/2026-10-21-remote-access-think-back-design.md`

## Global Constraints

- Work in `.worktrees/pf` on branch `profile`. Never push to main and never force-push. Push only when the owner says to.
- Engine checks are read-only. Every system command goes through `rescue.command.run` with a timeout. Every file walk is bounded. All evidence collection fits a total time budget of `EVIDENCE_BUDGET_SECONDS = 20.0`.
- Missing evidence is `None` and reads "Couldn't tell …". It never reads as "no" or as safe.
- The engine never copies anything from a connection log except dates and a count. No remote IDs, peer names, user names or GUIDs go into a finding, a test fixture or an export.
- Fixtures are synthetic only: made-up IDs and paths, never real scan data.
- `emits_codes` must equal the `code="…"` literals in the source (`tests/test_module_code_consistency.py`). Never build a code with an f-string.
- After editing any `rescue/**/*.py` file, run `.venv/bin/python scripts/generate_integrity_manifest.py` and commit `rescue/security/integrity_manifest.json`.
- If a finding description changes for a monitoring module, run `scripts/monitoring_descriptions.py`. If the TeamViewer fixture's source changes, run `scripts/remote_access_fixture.py`. Run the catalog generators with `--check` (`scripts/generate_module_catalog.py`, `scripts/generate_command_catalog.py`).
- Game contract: games are pure, links are intents only, there are 2–3 decisions per screen with the safe one first, and each label is at most 4 words (`MAX_LABEL_WORDS`).
- On-screen wording never says partner, ex, abuser, stalker or spy. City-mode text outside the help district must pass `CITY_FORBIDDEN`.
- Never weaken the removal warning. A removing decision never leads. Identities come from verified paths or engine evidence, never from names.
- Never pass `--auto`, `--yes` or `--i-understand`. Never ask for a password.
- Keep disk free above 50 GB. A new worktree symlinks `desktop/node_modules` from pf instead of reinstalling.
- Subagents never run repo-wide git cleanup (reflog expire, gc, prune, filter-repo) or a bare `git stash`.
- No time estimates in any document.
- Every engine task ends with `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check .` and `.venv/bin/python -m rescue.cli validate` all green. Every desktop task ends with `cd desktop && npm test` green.

## Review Focus

1. **A connection log with hostile or odd content** (a huge file, binary junk, a line with HTML in the peer name, dates in an unexpected format). Expected: the dates and count come out right or as `None`, nothing else from the log appears anywhere, and the read stops at 1 MB. Pinned in Task 2.
2. **A tool the person really uses** (a verified TeamViewer they keep for helping family). Expected: "Mine" marks it, the mark is remembered until the evidence changes, and a new incoming connection or new unattended setting brings it back. Pinned in Task 2 (the `known_items` kind) and Task 8 (fingerprint).
3. **The date is unknown.** Expected: Q1 reads "Think back. How did this get here?" with no made-up date, and the card says "Couldn't tell when this was added". Pinned in Task 7.
4. **Two tools at once** (the scam pattern). Expected: one critical "several tools" finding, plus each tool still on its own card. The game's recheck after removing one names the other. Pinned in Tasks 3 and 7.
5. **City mode with a remote tool running now.** Expected: the item is held in the help district, the help district shows the go-offline line first, and no mission, points or stored answer exists for it. Pinned in Task 6.

---

### Task 1: The tool list

**Files:**
- Create: `modules/security/remote_access_tools/data/tools.json`
- Create: `modules/security/remote_access_tools/tools.py`
- Test: `tests/test_remote_access_tools_data.py`

**Interfaces:**
- Produces: `load_tools() -> list[Tool]`. `Tool` is a frozen dataclass with these fields:
  - `id: str`, `name: str`, `maker: str`;
  - `mac_bundle_ids: tuple[str, ...]`, `mac_app_names: tuple[str, ...]` (e.g. `"AnyDesk.app"`), `mac_launchd: tuple[str, ...]` (label prefixes);
  - `win_display_names: tuple[str, ...]` (regexes over uninstall `DisplayName`, case-insensitive), `win_services: tuple[str, ...]`, `win_processes: tuple[str, ...]`;
  - `mac_processes: tuple[str, ...]`;
  - `logs: tuple[LogSpec, ...]`, where `LogSpec(platform: str, path: str, format: str)`, `format` is `"teamviewer_incoming"` or `"anydesk_trace"`, and the path may start with `~` or contain `%ProgramData%` / `%AppData%`;
  - `presence_only: bool`. This is true for Quick Assist, which is reported only while it's running.
- `TOOLS_FILE = content_file("modules/security/remote_access_tools/data/tools.json")`.

- [ ] **Step 1: Write the failing tests.**
  - `test_every_spec_tool_is_listed`: ids ⊇ {teamviewer, anydesk, screenconnect, rustdesk, ultraviewer, splashtop, logmein, zoho_assist, supremo, aeroadmin, ammyy, remote_utilities, simplehelp, hoptodesk, beyondtrust, atera, ninjaone, action1, chrome_remote_desktop, realvnc, tightvnc, ultravnc, parsec, quick_assist}. The list also takes over the three remote tools `stalkerware_scan` lists that the spec missed: netsupport, dwagent, radmin.
  - `test_ids_unique_and_names_nonempty`.
  - `test_patterns_compile`: every `win_display_names` entry compiles.
  - `test_quick_assist_is_presence_only`.
  - `test_only_teamviewer_and_anydesk_have_logs`.
  - `test_bad_file_raises`: a list missing `name` raises `ValueError`.
- [ ] **Step 2:** Run `.venv/bin/python -m pytest -q tests/test_remote_access_tools_data.py`. Expected: it FAILs on the import.
- [ ] **Step 3:** Write `tools.json`, using the `{version, last_updated, note, tools: [...]}` layout of `known_stalkerware.json`. Then write `load_tools()`, which validates each entry strictly and raises `ValueError` naming the bad entry.
  - Bundle ids and launchd prefixes come from the vendors' own installers, for example `com.teamviewer.TeamViewer`, `com.philandro.anydesk`, `com.rustdesk.RustDesk`, `com.teamviewer.teamviewer_service` and `com.philandro.anydesk.service`.
  - Where one isn't known, leave it empty. Detection then falls back to the app name.
  - Log paths:
    - TeamViewer: `Connections_incoming.txt` in `%ProgramFiles%\TeamViewer\` and `%ProgramFiles(x86)%\TeamViewer\`, and in `/Library/Application Support/TeamViewer/` on macOS.
    - AnyDesk: `connection_trace.txt` in `%ProgramData%\AnyDesk\` and `%AppData%\AnyDesk\`, and in `~/.anydesk/` on macOS.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit: `Remote access tools: the tool list`.

### Task 2: macOS evidence

**Files:**
- Create: `modules/security/remote_access_tools/__init__.py`
- Create: `modules/security/remote_access_tools/evidence.py`
- Test: `tests/test_module_remote_access_tools_mac.py`

**Interfaces:**
- Consumes: `load_tools()` from Task 1.
- Produces: `evidence.py`:
  - `parse_teamviewer_incoming(text: str) -> tuple[list[date], int]`
  - `parse_anydesk_trace(text: str) -> tuple[list[date], int]`
  - `read_tail(path: Path, cap: int = 1_048_576) -> str | None` (`None` when the file is missing or can't be read)
  - `Sighting` dataclass with these fields:
    - `tool: Tool`, `path: str | None`;
    - `added_on: date | None`;
    - `lets_in_unattended: bool | None`, `unattended_via: str | None` (a launchd label or a service name; never a log value);
    - `running_now: bool | None`;
    - `last_incoming: date | None`, `incoming_count: int | None`;
    - `one_off: bool`.
- Produces: `Module(ModuleBase)`, with `name = "remote_access_tools"`, `category = "security"`, `platforms = [Platform.DARWIN, Platform.WIN32]` and `risk_level = RiskLevel.SAFE`.
  - Class attributes tests can override:
    - `MAC_APP_DIRS = [Path("/Applications"), Path.home() / "Applications", Path.home() / "Downloads"]`
    - `MAC_LAUNCHD_DIRS = [Path("/Library/LaunchDaemons"), Path("/Library/LaunchAgents"), Path.home() / "Library/LaunchAgents"]`
    - `HOME = Path.home()`, `now = staticmethod(lambda: datetime.now())`
  - Methods:
    - `_mac_sightings(profile) -> list[Sighting]`
    - `_added_on_mac(app: Path) -> date | None` (`mdls -raw -name kMDItemDateAdded`, else `st_birthtime`)
- Log parsing rules:
  - TeamViewer: the file is tab-separated. Only the 3rd field (start time, `%d-%m-%Y %H:%M:%S`) is read.
  - AnyDesk: only lines starting with `Incoming` count. The date is the first `YYYY-MM-DD` on the line.
  - In both, lines that don't parse are skipped, never guessed. A file that can't be read gives `None, None`, not `[], 0`.

- [ ] **Step 1: Write the failing tests.** Use synthetic files under `tmp_path`, and patch `rescue.command.run` for `mdls`.
  - `test_finds_app_and_date_added`: AnyDesk.app with an mdls date of `2026-03-03 10:00:00 +0000` gives `added_on == date(2026,3,3)`.
  - `test_falls_back_to_birth_time_when_mdls_fails`.
  - `test_launchd_plist_means_unattended`: a plist whose Label is `com.philandro.anydesk.service` gives `lets_in_unattended is True` and `unattended_via` equal to that label.
  - `test_no_launchd_item_is_false_only_when_dirs_were_readable`: if a dir is unreadable, the result is `None`.
  - `test_running_now_from_profile_processes`.
  - `test_teamviewer_incoming_dates_and_count`: 4 lines, the last on 12-03-2026, give `(…, 4)` with max 2026-03-12.
  - `test_anydesk_trace_counts_incoming_only`: an `Outgoing` line is skipped.
  - `test_log_values_never_leave_the_parser`: a line with peer name `<img src=x onerror=1>` and ID `987654321` must not appear in `json.dumps(result.findings[*].data)`.
  - `test_huge_log_reads_only_the_tail`: a 3 MB file is read only up to its last 1 MB.
  - `test_binary_log_gives_none_not_zero`.
  - `test_app_in_downloads_without_service_is_one_off`.
  - `test_budget_exhausted_leaves_rest_none`: with the clock patched past the budget, evidence is `None`.
- [ ] **Step 2:** Run `.venv/bin/python -m pytest -q tests/test_module_remote_access_tools_mac.py`. Expected: FAIL.
- [ ] **Step 3:** Implement `evidence.py` and the macOS half of the module. `check()` may return no findings yet; Task 3 builds them.
- [ ] **Step 4:** Run the test. Expected: PASS.
- [ ] **Step 5:** Commit: `Remote access tools: macOS evidence`.

### Task 3: Windows evidence, findings, severity, codes

**Files:**
- Modify: `modules/security/remote_access_tools/__init__.py`
- Test: `tests/test_module_remote_access_tools_win.py`, `tests/test_module_remote_access_tools_findings.py`

**Interfaces:**
- Consumes: `Sighting`, the parsers and `read_tail` from Task 2.
- Produces these methods, each returning `None` when it couldn't read:
  - `_win_uninstall_entries() -> list[dict] | None`, with `{display_name, install_location, install_date}` from HKLM, HKLM WOW6432Node and HKCU Uninstall;
  - `_win_services() -> dict[str, str] | None` (service name → start type);
  - `_win_sightings(profile) -> list[Sighting]`.
- Windows `added_on` comes from `InstallDate` (`YYYYMMDD`). If that's missing, it's the install folder's creation time. `lets_in_unattended` is true when a tool's service has an Automatic start type. Quick Assist gives a sighting only when `QuickAssist.exe` is running. The spec's "recent-session evidence" for it is narrowed to running-now, because Windows keeps no readable session log for it.
- Produces findings. Each one's `data` has these fields:
  - `check`, `tool` (the name), `tool_id`, `path`;
  - `added_on` (ISO date or `None`);
  - `lets_in_unattended`, `unattended_via`, `running_now`;
  - `last_incoming` (ISO date or `None`), `incoming_count`;
  - `one_off`, `known_item_kind: "remote_tool"`.
- Codes and severity, each with its own `code="…"` literal:
  - `security.remote_access_tools.unattended_recent`: CRITICAL, when `lets_in_unattended` and `added_on` is within 30 days of `now()`.
  - `security.remote_access_tools.running_now`: WARNING, when `running_now` and not the case above.
  - `security.remote_access_tools.tool_found`: WARNING otherwise. It is INFO only when `identify(path, platform)` reports a verified maker, `one_off` is true, `running_now is False`, `incoming_count == 0` and `lets_in_unattended is False`. `None` anywhere keeps it a WARNING.
  - `security.remote_access_tools.several_tools`: one extra CRITICAL finding when two or more distinct tools are seen. `data = {"check": "several_tools", "tools": [names]}`.
- Copy:
  - Title: `"<Tool> can let someone control this computer"`.
  - The description's first paragraph is the evidence in plain words, with "Couldn't tell …" for each `None`. The second paragraph names the common scam ("Scammers who call or show a pop-up often ask people to install tools like this").
  - The description never names a relationship. `fix()` returns GUIDANCE actions only.
- The `known_items` mark kind is `remote_tool`. Add it to `rescue/known_items.py` `ITEM_KINDS` and to `desktop/renderer/mark-policy.js`. Its mark identity is tool id plus path. The evidence fingerprint covers `lets_in_unattended`, `last_incoming` and `incoming_count`, so a newer connection un-marks it.

- [ ] **Step 1: Write the failing tests.**
  - `test_uninstall_entry_and_date` (a mocked `reg query` returns synthetic output).
  - `test_auto_start_service_is_unattended`.
  - `test_registry_unreadable_is_none_not_false`.
  - `test_quick_assist_only_when_running`.
  - `test_unattended_added_9_days_ago_is_critical`: `now = 2026-03-12` and `added_on = 2026-03-03` give critical `unattended_recent`.
  - `test_unattended_added_40_days_ago_is_warning_tool_found`.
  - `test_running_now_code`.
  - `test_two_tools_add_several_tools_critical`.
  - `test_info_only_when_every_fact_is_known_and_quiet`, plus the same case with `incoming_count=None`, which stays a warning.
  - `test_description_says_couldnt_tell_for_missing_evidence`.
  - `test_no_relationship_words_in_any_text`: none of `partner|ex\b|abuser|stalk|spy` appears in any title, description or action.
  - `test_emitted_codes_are_declared`.
  - `test_mark_kind_known`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Regenerate the manifest, because `rescue/known_items.py` changed.
- [ ] **Step 4:** Run the tests plus `tests/test_module_code_consistency.py`. Expected: PASS.
- [ ] **Step 5:** Commit: `Remote access tools: Windows evidence and the findings`.

### Task 4: Wiring the check in, and one report per tool

**Files:**
- Modify: `rescue/safety_scope.py` (`ALERT_CODES`: add the four new codes; remove `win_remote_access_audit`'s per-tool codes and `multiple_tools`), `rescue/check_names.py` (`"remote_access_tools": "Remote access tools"`).
- Create: `guides/remediation/review_remote_access_tools.md`. It covers both platforms, sets `monitoring_risk: true` and `remediates` the four codes. Its steps: go offline if it's running, decide whether it's yours, turn off unattended access, uninstall, check for a second tool, and the scam steps (bank, passwords from another device, report).
- Modify: `modules/security/win_remote_access_audit/__init__.py`. It keeps only `rdp_enabled`, plus `no_tools_found`, which is renamed in its wording to "RDP is off". Drop the other codes from `emits_codes`, the code, `guides/remediation/review_windows_remote_access.md` and its tests.
- Modify: `modules/security/stalkerware_scan/data/known_stalkerware.json` drops every `category: "remote_access"` entry. `stalkerware_scan/__init__.py` drops the remote-access branch of `fix()`, and its docstring's third bullet says remote tools are `remote_access_tools`' job.
- Modify: `scripts/remote_access_fixture.py`. Build the fixture from `remote_access_tools` instead (a synthetic AnyDesk sighting with mocked evidence, `CODE = "security.remote_access_tools.tool_found"`). Regenerate `desktop/test/fixtures/remote-access-finding.json`, then update `desktop/test/removal-warning.test.js` for the new code and module name.
- Modify: `profiles/home_network_intrusion.yaml`, `profiles/identity_theft_recovery.yaml` and `profiles/digital_security_reset.yaml` to add `remote_access_tools`.
- Regenerate: `docs/modules.md`, `docs/commands.md` and `docs/REMEDIATION_CATALOG.md` with their generators. Regenerate the monitoring descriptions fixture and the integrity manifest.
- Test: `tests/test_module_remote_access_tools_findings.py` (extend it), `tests/test_module_stalkerware_scan.py`, `tests/test_module_win_remote_access_audit.py` and `tests/test_safety_scope.py`.

- [ ] **Step 1: Write the failing tests.**
  - `test_new_codes_carry_removal_alert`: serialize a critical `unattended_recent` finding and check `removal_alert is True` and that the safety note is present.
  - `test_info_tool_found_has_no_alert`.
  - `test_stalkerware_scan_no_longer_reports_teamviewer`: a TeamViewer process gives no stalkerware finding.
  - `test_win_remote_access_audit_reports_rdp_only`.
  - `test_walkthrough_covers_every_code`.
  - `test_profiles_include_remote_access_tools`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement the list above. Then run every generator in `--check` mode and fix what they report.
- [ ] **Step 4:** Run the full engine suite, ruff and `rescue.cli validate`. Expected: all green, and `rescue run remote_access_tools < /dev/null` exits 0 on this Mac. Read its output yourself and don't commit it.
- [ ] **Step 5:** Commit: `Remote access tools: one report per tool (RDP stays in the Windows check; monitoring check drops remote tools)`.

### Task 5: The runner's question step and the unpaid flag

**Files:**
- Modify: `desktop/renderer/missions/contract.js` (`EFFECT_KINDS` gets `'ask'`; the header gets rulings R12 and R13; `checkDecisions` accepts `ask`).
- Modify: `desktop/renderer/missions/runner.js`, `desktop/renderer/game/missions-city.js`.
- Test: `desktop/test/missions-foundation-runner.test.js`, `desktop/test/missions-contract.test.js`.

**Interfaces:**
- R12: an `ask` effect is `{ kind: 'ask' }`. Choosing it adds the decision id to `run.answers[item.key]` (an array) and leaves the item on screen in phase `'item'`. Nothing is recorded, paid or remembered.
  - `decisionsFor` and `viewFor` pass `ctx.answers` (that item's array, `[]` by default) to `game.decisions` and `game.research`.
  - `view.answers` carries the same array to `render`.
  - `run.answers` lives only in memory and is never written to the profile.
  - A new runner function `unask(run) -> run` drops the item's last answer (the BACK button).
  - A practice step may carry `answers: string[]`, which `viewFor` passes as `ctx.answers` for that step.
- R13: any effect may carry `unpaid: true`. In `missions-city.js` `afterResults`, such a result pays nothing, is never kept in the profile (`Run.remembers` returns false) and stops the mission's summary bonus, exactly like `isMonitoringItem`.
- The controller's item screen gets a BACK button while `view.answers.length > 0`. It calls `unask`, through the same path as the existing NEXT.

- [ ] **Step 1: Write the failing tests.**
  - `ask keeps the item and grows answers`.
  - `ask answers reach decisions and render via ctx/view`.
  - `unask drops the last answer`.
  - `answers are never in remembers or summaryResults points`.
  - `practice step answers reach decisions`.
  - `unpaid result: no award, no keepAnswer, no bonus`: drive `afterResults` with stub deps.
  - `checkDecisions accepts ask and rejects unknown kinds still`.
- [ ] **Step 2:** Run `cd desktop && node --test test/missions-foundation-runner.test.js test/missions-contract.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test`. Expected: PASS, with every existing game's tests unchanged.
- [ ] **Step 5:** Commit: `Missions: a question step (ask) and unpaid answers`.

### Task 6: Remote tools are held in city mode

**Files:**
- Modify: `desktop/renderer/not-checked.js`.
  - Add a `HELD_IN_CITY` set: `MONITORING_MODULES` plus `remote_access_tools`.
  - `isHeld` uses it.
  - `MONITORING_MODULES` itself is unchanged, so points and standard mode are unaffected.
- Modify: `desktop/renderer/game/held.js`.
  - `HELD_MODULES` matches `HELD_IN_CITY`.
  - `heldEvidence` adds `added` (from `data.added_on`), `last_in` (from `data.last_incoming` and `data.incoming_count`), `unattended` and `running`.
- Modify: `desktop/renderer/app.js` (`ALWAYS_SAFETY_MODULES` gets `remote_access_tools`). Keep the existing equality tests passing by updating every set they compare.
- Modify: the help-district view that draws `heldEvidence`. Find it with `grep -rn heldEvidence desktop/renderer`. When `running` is true, it shows "Running now. To be safe, go offline first" with the network settings intent first.
- Test: `desktop/test/game-held-followups.test.js` and a new `desktop/test/remote-tools-held.test.js`.

- [ ] **Step 1: Write the failing tests.**
  - `city: a remote_access_tools warning is in held, not in any mission`.
  - `standard: the same finding is a to-do, not held-diverted`.
  - `held evidence shows dates and "Couldn't tell" when missing`.
  - `running now: offline line comes first`.
  - `city held text outside the help district passes CITY_FORBIDDEN`.
  - `a remote tool item still pays in standard mode` (`isMonitoringItem` is false).
- [ ] **Step 2:** Run the new test files. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test`. Expected: PASS.
- [ ] **Step 5:** Commit: `City mode holds remote-access tools in the help district`.

### Task 7: The Guest Book game

**Files:**
- Create: `desktop/renderer/missions/games/guestbook.js`, `desktop/renderer/missions/games/guestbook.css` (`.gb-*` classes; link it where the other games' CSS is linked).
- Modify:
  - `desktop/renderer/missions/contract.js`: `TYPE_IDS` gets `'guestbook'` before `'switchboard'`.
  - `desktop/renderer/missions/types.js`: `TYPE_TITLES.guestbook = { standard: 'Remote access', city: 'The Guest Book' }`; `BASE_COVERS.guestbook = whole('remote_access_tools')`; `IMPORTANCE` puts `'guestbook'` right after `'locker'`.
  - `desktop/renderer/game/lessons/password-asker.js`: `modules: ['win_remote_access_audit', 'remote_access_tools']`. Drop "On Windows, " and start the sentence with "The checkup".
- Test: `desktop/test/missions-guestbook.test.js` and fixture `desktop/test/fixtures/missions/guestbook-items.json`. The fixture is synthetic, built from Task 3's data shape: a dated unattended AnyDesk, an undated TeamViewer, a running RustDesk and a verified one-off.

**Interfaces:**
- Consumes: `ctx.answers` and `view.answers` (Task 5); the finding `data` fields (Task 3).
- Produces: the default export `{ type: 'guestbook', title, concepts: ['remote-access-scams'], covers, decisions, research, practice, practiceByPlatform: { win32 }, render, summary }`, plus `export function stageOf(item, answers) -> 'offline'|'q1'|'q2'|'q3'|'q4'|'mine'|'notneeded'|'scam'|'known'|'unsure'`.
- The quiz, in decision ids, with `ask` effects except where an outcome is named:
  - `offline` stage: shown first only when `data.running_now === true` and `answers` is empty. Decisions:
    - `offline` ("Go offline first"): a `settings` effect, pane `network`, with steps to turn off Wi-Fi or unplug.
    - `continue` ("I'm offline now"): `ask`.
  - `q1`: "Think back to around {Month D}. How did this get here?" When `added_on` is null, the question is "Think back. How did this get here?" Decisions: `installed` "I installed it", `helped` "Someone helped me", `dontknow` "I don't remember".
  - `q2`: "Do you still use it?" Decisions: `use` "Yes, I use it" → mine, `nouse` "No" → notneeded.
  - `q3`: "Who was it?" Decisions: `asked` "Help I asked for" → mine, `contacted` "Someone contacted me" → scam, `knows` "Someone I know" → known.
  - `q4`: "Around then, did a call, pop-up, email or text say something was wrong with your computer, an account, a refund or a payment?" Decisions: `yes` "Yes" → scam, `no` "No" → unsure, `notsure` "Not sure" → unsure.
- Outcomes (`stageOf` derives each from the answers):
  - `mine`: `mark` "Mark it mine". If `lets_in_unattended`, add `closer` "Turn off unattended" with steps for the tool's own settings. Then `later`.
  - `notneeded`: `later` first, then `fix` "Remove it" when `finding.fixable`, else `closer` "Remove it" with `warning: true` and uninstall steps for the platform. Last, `recheck` "I removed it", with the module `remote_access_tools`.
  - `scam`: `closer` "Do these now", with steps in order:
    1. From another phone or computer if you can, call your bank on the number on your card.
    2. Change your email password, then your other accounts.
    3. Remove the tool, then run the check again: scammers often leave a second one.
    4. Report it. The report links are look-up intents, never hard-coded URLs: `{kind:'lookup', source:'web', query:'report a tech support scam FTC'}`, and the same for Action Fraud and the Canadian Anti-Fraud Centre.
    
    Then `fix`/`closer` "Remove it" with `warning: true`, and `later`. `research.links` includes `{ kind: 'lesson', concept: 'remote-access-scams' }`.
  - `known`: every effect carries `unpaid: true`, and no removal is offered.
    - `closer` "Talk to someone first", with these steps: "Removing it can tell whoever set it up. Talk to an advocate before you remove it." The hotline as text: `1-800-799-7233`, or text START to 88788. "Write down the dates on this card."
    - `later`.
  - `unsure`: `closer` "Turn off unattended" (steps), `closer` "Check its connections" (steps for opening the tool's connection list), and `later`.
- Dates are shown with `toLocaleDateString(undefined, { month: 'long', day: 'numeric' })`, plus the year when it isn't the current year. They're built from the ISO string without a timezone shift (split the string; don't call `new Date(iso)`).
- `render` draws the card: the tool name escaped, the evidence lines (the spec's sentences, with "Couldn't tell …" for null), then the current question or outcome heading. In city mode, guestbook items never reach the runner because Task 6 holds them, so `render` in city mode only needs to be safe. Its text must still pass `CITY_FORBIDDEN`, so the hotline line only appears in standard mode.
- Practice (standard words; `practiceByPlatform.win32` has the same 3 steps in Windows words):
  - items: a made-up TeamViewer added `2026-03-03` with `lets_in_unattended: true`, and a made-up RustDesk the person installed.
  - script:
    1. `{item:0, answers:[], expect:'dontknow'}`, which asks how it got here.
    2. `{item:0, answers:['dontknow'], expect:'yes'}`, a "refund" call.
    3. `{item:1, answers:['installed'], expect:'use'}`.

- [ ] **Step 1: Write the failing tests.**
  - Every path reaches its outcome: `[installed,use]`→mine, `[installed,nouse]`→notneeded, `[helped,asked]`→mine, `[helped,contacted]`→scam, `[helped,knows]`→known, `[dontknow,yes]`→scam, `[dontknow,no]`→unsure, `[dontknow,notsure]`→unsure.
  - `offline comes first only when running and unanswered`.
  - `q1 names the added date; undated says "Think back." with no date`.
  - `known outcome: every effect unpaid, no fix, no removing decision`.
  - `notneeded and scam: removal is never first and carries warning`.
  - `scam links are lookup/lesson intents only`.
  - `labels ≤ 4 words, 2–3 decisions at every stage` (loop over all stages and fixture items with `C.checkDecisions`).
  - `contract checks pass` (`C.runContractChecks(game)`), with `HOSTILE` values escaped in `render`.
  - `no relationship words on any standard screen except the known outcome's advocate steps`.
  - `CITY_FORBIDDEN passes in city render`.
  - `date of 2026-03-03 renders March 3 in any timezone` (set `TZ` to `America/Los_Angeles` and to `Pacific/Kiritimati`).
  - `practice and win32 practice have the same step count and each expect is offered`.
  - `no double claims` (`noDoubleClaims` across all games).
- [ ] **Step 2:** Run `node --test test/missions-guestbook.test.js`. Expected: FAIL.
- [ ] **Step 3:** Implement.
- [ ] **Step 4:** Run `npm test`. Expected: PASS.
- [ ] **Step 5:** Screenshot each outcome in standard mode, and the held card in city mode, with the project's run skill. Look at them; don't commit them.
- [ ] **Step 6:** Commit: `The Guest Book: think back to when a remote-access tool arrived`.

### Task 8: Placement fixes

**Files:**
- Modify:
  - `modules/bloatware/process_scanner/__init__.py`: `data.check = entry["category"]`.
  - The same file's `_make_finding` description: adware, scareware and cryptominer no longer say "You can usually ignore this". Each gets its own first line ("This program shows unwanted ads or changes your browser", and so on). "pup" keeps today's wording.
  - `desktop/renderer/missions/games/locker.js` covers: `{ module: 'process_scanner', checks: ['adware', 'scareware', 'cryptominer'] }`.
  - `desktop/renderer/missions/games/junkyard.js`: its covers and `isBloat` keep only `pup` (or no `check`) from `process_scanner`.
  - `desktop/renderer/missions/games/switchboard.js`: a new `trust` kind in `KINDS`, `MODULE_KIND` entries for `certificate_audit`, `certificate_trust_audit`, `mdm_enrollment` and `mdm_enrollment_check`, and the new covers.
    - Chip: "Trusted by this Mac" in standard words, "Seal of trust" in city words.
    - Text: "Certificates and device-management profiles decide who this computer trusts. One you didn't add, or one from an employer or school you've left, can read or change what you do."
    - The pane is `profiles` on macOS and `windows-security` on Windows.
  - `desktop/renderer/missions/types.js`: remove `certificate_audit` and `certificate_trust_audit` from `BASE_COVERS.seal`, and `mdm_enrollment` and `mdm_enrollment_check` from `ODD_JOBS`.
- Modify the MDM checks: `mdm_enrollment.profiles_installed` and `mdm_enrollment_check.all_profiles` become WARNING when a profile's organization isn't in a new `KNOWN_MDM` list in `modules/security/mdm_enrollment/data/known_mdm.json` (Jamf, Kandji, Mosyle, Microsoft Intune, Addigy, JumpCloud, Workspace ONE, Hexnode, SimpleMDM, Fleet, Apple Business/School Manager). The INFO stays when every profile is known. Copy the list to the `_check` module.
- Test: `tests/test_module_process_scanner.py`, `tests/test_module_mdm_enrollment*.py`, `desktop/test/missions-switchboard.test.js`, `desktop/test/missions-locker*.test.js`, `desktop/test/missions-foundation-types.test.js`.

- [ ] **Step 1: Write the failing tests.**
  - `adware finding has check "adware" and no "usually ignore"`.
  - `unknown MDM org is a warning; Jamf is info`.
  - `typeOf: process_scanner adware → locker, pup → junkyard`.
  - `typeOf: certificate_trust_audit user_added_certs → switchboard, lineKind 'trust'`.
  - `typeOf: mdm_enrollment profiles_installed (warning) → switchboard`.
  - `no double claims`.
- [ ] **Step 2:** Run the tests. Expected: FAIL.
- [ ] **Step 3:** Implement. Regenerate the catalogs. Run `scripts/uncovered_codes.py` and confirm no new uncovered warning codes.
- [ ] **Step 4:** Run the full engine and desktop suites, ruff and validate. Expected: all green.
- [ ] **Step 5:** Commit: `Placement: adware to the Evidence Locker; certificates and device management to the Switchboard`.

### Task 9: Whole-branch check

- [ ] **Step 1:** Run `.venv/bin/python -m pytest -q`, `.venv/bin/ruff check .`, `.venv/bin/python -m rescue.cli validate`, every generator with `--check`, and `cd desktop && npm test`. Expected: all green. Record the counts.
- [ ] **Step 2:** Run `rescue scan --json --no-downloads` in the background. Confirm that `remote_access_tools` ran (`supported: true`, `status: ok`), and that the counts in the desktop's standard and city modes agree (`scanCounts` vs missions). Read the output yourself and don't commit it.
- [ ] **Step 3:** Get a fresh-context review of the whole branch diff against `6a1cb68`, with these focuses:
  - safety: the removal warning, held in city, and no relationship words;
  - privacy: no log contents beyond dates and counts;
  - the contract rules.
  
  Fix what it confirms.
- [ ] **Step 4:** Update the spec's Status line to "implemented", and commit. Don't push until the owner says so.
