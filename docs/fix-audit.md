# "Fix it for me" audit

The desktop app may show a "Fix it for me" button only for a module that passes
every one of these tests:

1. The change is reversible, by the person, with steps we can write in plain words.
2. It is low impact: nothing else stops working, no data is lost.
3. It does exactly what one sentence says ("Turns on your Mac's firewall").
4. It needs no administrator password.
5. It touches only the setting or file the finding is about.
6. It cannot be wrongly aimed (no ids or paths that go stale between the scan and the fix).

Any doubt is a NO. A wrong automatic fix on a frightened person's computer is
worse than none; the "How to fix this" steps remain for everything declined here.

Only modules listed with verdict `OFFER` may appear in `rescue/app_fixes.json`.
`tests/test_app_fixes.py` fails if a module with a state-changing `fix()` is
missing from this table, if the table lists a module whose `fix()` is guidance
only, or if the allowlist names a module that is not marked `OFFER` here.

Method: every `modules/*/*/__init__.py` was parsed, and `fix()` plus every helper
reachable from it was searched for state-changing calls (subprocess, kill,
unlink, rmtree, write, move, mkdir, chmod, `ActionKind.MUTATION`). The other
modules' `fix()` only return guidance text (some contain `sudo ...` commands in
strings for the person to read; none run them).

Result: 11 modules have a state-changing `fix()`. **0 are offerable today.**
The feature, the allowlist and the gate are in place and tested, so a module can
be added later once its `fix()` is narrowed and re-audited.

| Module | What fix() really does | Verdict | Reason |
| --- | --- | --- | --- |
| `startup_auditor` | Runs `launchctl unload -w ~/Library/LaunchAgents/<label>.plist` for EVERY matched finding in one go. The list it matches mixes real scareware (MacKeeper, Genieo, Pirrit) with updaters (Google Keystone, Microsoft AutoUpdate, Java) and a working antivirus (Avast). | NO | Fixes all findings at once, so one card's button would change other items. Several matches are security updaters or an antivirus whose removal leaves the person less safe. Unloading adware does not remove it, so "fixed" would overpromise. Candidate for a future per-item version limited to the scareware/adware entries. |
| `firewall_audit` | Runs `socketfilterfw --setglobalstate on` and `--setstealthmode on`. | NO | Needs administrator rights (its own error text says so), so it would fail for a normal user. Stealth mode can also break device discovery. |
| `win_firewall` | Runs `netsh advfirewall set <profile> state on`. | NO | Needs Administrator. Turning a profile on can cut off a network the person relies on (remote desktop, shared printers). |
| `win_defender` | Runs `Set-MpPreference -DisableRealtimeMonitoring $false` or `Update-MpSignature`. | NO | Needs Administrator. Real-time protection is often off on purpose when another antivirus is installed; forcing it on creates conflicts. Tamper Protection can silently refuse. |
| `win_antivirus_status` | Same two PowerShell commands as `win_defender`. | NO | Same reasons as `win_defender`. |
| `win_updates` | Runs `Start-Service -Name wuauserv`. | NO | Needs Administrator. The service is often stopped deliberately by policy or a management tool. |
| `ai_worm_filesystem` | Moves files flagged "high confidence" into `~/.rescue_quarantine`. | NO | Moves files, and the person may be dealing with an active compromise or want to keep evidence. Detection confidence is a heuristic. Needs a human decision per file. |
| `ai_worm_git_ssh` | Unsets global git config keys, edits `.npmrc`, edits MCP server config files, moves repo hook files. | NO | Edits configuration files a developer may rely on, with no undo copy. Wrong edits can break their tools or destroy evidence. |
| `ai_worm_lateral` | Deletes files flagged as malicious artifacts. | NO | Permanent deletion with no undo. Rotating exposed credentials must come first and cannot be automated. |
| `ai_worm_network` | Sends SIGTERM to a process id taken from the scan, and rewrites the hosts file. | NO | The process id can be reused by a different program between the scan and the fix, so it could close the wrong program. Rewriting `/etc/hosts` needs admin. |
| `ai_worm_persistence` | Unloads and deletes launch agents, systemd units and scheduled tasks, and rewrites shell profiles, settings hooks. | NO | Deletes persistence entries and rewrites files with no undo copy, and the order matters for dead-man-switch malware. Needs human guidance. |

## Adding a module later

1. Narrow `fix()` so it acts on exactly one named setting and cannot touch more.
2. Add its row here with verdict `OFFER` and the reason it passes all six tests.
3. Add an entry to `rescue/app_fixes.json` (`will_change`, `how_to_undo`).
4. `pytest tests/test_app_fixes.py` must pass.
